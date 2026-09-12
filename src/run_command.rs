use std::ffi::OsString;
use std::io::{ErrorKind, Read, Write};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use process_wrap::std::{ChildWrapper, CommandWrap};

use crate::parse_arguments::{CredactError, Invocation};
use crate::redact_buffer::redact_buffer;
use crate::resolve_secrets::ResolvedSecret;
use crate::terminate_child::terminate_child;

pub const OUTPUT_LIMIT_BYTES: usize = 64 * 1024 * 1024;

const READ_CHUNK_BYTES: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(windows)]
const NOT_EXECUTABLE_OS_ERROR: i32 = 193;
#[cfg(unix)]
const NOT_EXECUTABLE_OS_ERROR: i32 = 8;

pub struct RunOptions<'a> {
    pub invocation: &'a Invocation,
    pub secrets: &'a [ResolvedSecret],
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stream {
    Stdout,
    Stderr,
}

enum Event {
    Drained(Stream, std::io::Result<Vec<u8>>),
    LimitExceeded,
}

struct Budget {
    used: AtomicUsize,
    exceeded: AtomicBool,
}

fn output_error(message: &str) -> CredactError {
    CredactError::new(1, message)
}

fn read_error_of(stream: Stream) -> CredactError {
    match stream {
        Stream::Stdout => output_error("credact: failed to read command stdout"),
        Stream::Stderr => output_error("credact: failed to read command stderr"),
    }
}

fn failure_after_termination(child: &mut dyn ChildWrapper, failure: CredactError) -> CredactError {
    match terminate_child(child) {
        Ok(_) => failure,
        Err(_) => output_error("credact: command could not be terminated"),
    }
}

pub fn child_environment_of(
    parent: Vec<(OsString, OsString)>,
    secrets: &[ResolvedSecret],
) -> Vec<(OsString, OsString)> {
    let mut environment: Vec<(OsString, OsString)> = parent
        .into_iter()
        .filter(|(name, _)| match name.to_str() {
            Some(name) => !secrets
                .iter()
                .any(|secret| secret.source.name().eq_ignore_ascii_case(name)),
            None => true,
        })
        .collect();

    environment.extend(secrets.iter().map(|secret| {
        (
            OsString::from(secret.source.name()),
            OsString::from(secret.value.as_str()),
        )
    }));

    environment
}

pub fn spawn_error_of(error: &std::io::Error) -> CredactError {
    if error.kind() == ErrorKind::NotFound {
        return CredactError::new(127, "credact: command was not found");
    }

    if error.kind() == ErrorKind::PermissionDenied
        || error.raw_os_error() == Some(NOT_EXECUTABLE_OS_ERROR)
    {
        return CredactError::new(126, "credact: command is not executable");
    }

    CredactError::new(1, "credact: command could not start")
}

pub fn exit_code_of(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }

    1
}

#[cfg(windows)]
fn program_of(invocation: &Invocation) -> Result<OsString, CredactError> {
    which::which(&invocation.command)
        .map(std::path::PathBuf::into_os_string)
        .map_err(|_| spawn_error_of(&std::io::Error::from(ErrorKind::NotFound)))
}

#[cfg(unix)]
fn program_of(invocation: &Invocation) -> Result<OsString, CredactError> {
    Ok(invocation.command.clone())
}

#[cfg(unix)]
struct Interrupts {
    handle: signal_hook::iterator::Handle,
    received: Receiver<i32>,
    forwarder: Option<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl Interrupts {
    fn register() -> std::io::Result<Self> {
        use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};

        let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP])?;
        let handle = signals.handle();
        let (sender, received) = mpsc::channel();
        let forwarder = thread::spawn(move || {
            for signal in signals.forever() {
                if sender.send(signal).is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            handle,
            received,
            forwarder: Some(forwarder),
        })
    }

    fn forward(
        &mut self,
        child: &mut dyn ChildWrapper,
    ) -> Result<Option<ExitStatus>, CredactError> {
        while let Ok(signal) = self.received.try_recv() {
            let _ = child.signal(signal);
        }

        Ok(None)
    }
}

#[cfg(unix)]
impl Drop for Interrupts {
    fn drop(&mut self) {
        self.handle.close();

        if let Some(forwarder) = self.forwarder.take() {
            let _ = forwarder.join();
        }
    }
}

#[cfg(windows)]
struct Interrupts {
    requested: Arc<AtomicBool>,
    registrations: Vec<signal_hook::SigId>,
    requested_at: Option<std::time::Instant>,
}

#[cfg(windows)]
impl Interrupts {
    fn register() -> std::io::Result<Self> {
        use signal_hook::consts::{SIGBREAK, SIGINT};

        let mut interrupts = Self {
            requested: Arc::new(AtomicBool::new(false)),
            registrations: Vec::new(),
            requested_at: None,
        };

        for signal in [SIGINT, SIGBREAK] {
            let registration =
                signal_hook::flag::register(signal, Arc::clone(&interrupts.requested))?;

            interrupts.registrations.push(registration);
        }

        Ok(interrupts)
    }

    fn forward(
        &mut self,
        child: &mut dyn ChildWrapper,
    ) -> Result<Option<ExitStatus>, CredactError> {
        if !self.requested.load(Ordering::SeqCst) {
            return Ok(None);
        }

        let requested_at = *self
            .requested_at
            .get_or_insert_with(std::time::Instant::now);

        if requested_at.elapsed() < crate::terminate_child::GRACEFUL_TERMINATION {
            return Ok(None);
        }

        terminate_child(child)
            .map(Some)
            .map_err(|_| output_error("credact: command could not be terminated"))
    }
}

#[cfg(windows)]
impl Drop for Interrupts {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            signal_hook::low_level::unregister(registration);
        }
    }
}

fn wait_for_status(
    child: &mut dyn ChildWrapper,
    interrupts: &mut Interrupts,
    mut poll: impl FnMut(&mut dyn ChildWrapper) -> Result<(), CredactError>,
) -> Result<ExitStatus, CredactError> {
    loop {
        poll(child)?;

        if let Some(status) = child.try_wait().map_err(|error| spawn_error_of(&error))? {
            return Ok(status);
        }

        if let Some(status) = interrupts.forward(child)? {
            return Ok(status);
        }

        thread::sleep(POLL_INTERVAL);
    }
}

fn drain(
    mut pipe: impl Read,
    budget: &Budget,
    events: &Sender<Event>,
) -> Option<std::io::Result<Vec<u8>>> {
    let mut captured = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK_BYTES];

    loop {
        let count = match pipe.read(&mut chunk) {
            Ok(0) => return Some(Ok(captured)),
            Ok(count) => count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Some(Err(error)),
        };

        let used = budget.used.fetch_add(count, Ordering::SeqCst) + count;

        if used > OUTPUT_LIMIT_BYTES {
            if !budget.exceeded.swap(true, Ordering::SeqCst) {
                let _ = events.send(Event::LimitExceeded);
            }

            return None;
        }

        captured.extend_from_slice(&chunk[..count]);
    }
}

fn spawn_reader(
    stream: Stream,
    pipe: impl Read + Send + 'static,
    budget: Arc<Budget>,
    events: Sender<Event>,
) {
    thread::spawn(move || {
        if let Some(result) = drain(pipe, &budget, &events) {
            let _ = events.send(Event::Drained(stream, result));
        }
    });
}

struct Capture {
    events: Receiver<Event>,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
}

impl Capture {
    fn start(child: &mut dyn ChildWrapper) -> Result<Self, CredactError> {
        let stdout_pipe = child.stdout().take();
        let stderr_pipe = child.stderr().take();

        let (Some(stdout_pipe), Some(stderr_pipe)) = (stdout_pipe, stderr_pipe) else {
            return Err(failure_after_termination(
                child,
                output_error("credact: command output streams were unavailable"),
            ));
        };

        let budget = Arc::new(Budget {
            used: AtomicUsize::new(0),
            exceeded: AtomicBool::new(false),
        });
        let (sender, events) = mpsc::channel();

        spawn_reader(
            Stream::Stdout,
            stdout_pipe,
            Arc::clone(&budget),
            sender.clone(),
        );
        spawn_reader(Stream::Stderr, stderr_pipe, budget, sender);

        Ok(Self {
            events,
            stdout: None,
            stderr: None,
        })
    }

    fn accept(&mut self, event: Event, child: &mut dyn ChildWrapper) -> Result<(), CredactError> {
        match event {
            Event::LimitExceeded => Err(failure_after_termination(
                child,
                CredactError::new(1, "credact: command output exceeded 64 MiB"),
            )),
            Event::Drained(stream, Err(_)) => {
                Err(failure_after_termination(child, read_error_of(stream)))
            }
            Event::Drained(Stream::Stdout, Ok(bytes)) => {
                self.stdout = Some(bytes);

                Ok(())
            }
            Event::Drained(Stream::Stderr, Ok(bytes)) => {
                self.stderr = Some(bytes);

                Ok(())
            }
        }
    }

    fn poll(&mut self, child: &mut dyn ChildWrapper) -> Result<(), CredactError> {
        while let Ok(event) = self.events.try_recv() {
            self.accept(event, child)?;
        }

        Ok(())
    }

    fn finish(mut self, child: &mut dyn ChildWrapper) -> Result<(Vec<u8>, Vec<u8>), CredactError> {
        while self.stdout.is_none() || self.stderr.is_none() {
            let missing = if self.stdout.is_none() {
                Stream::Stdout
            } else {
                Stream::Stderr
            };

            match self.events.recv() {
                Ok(event) => self.accept(event, child)?,
                Err(_) => return Err(read_error_of(missing)),
            }
        }

        Ok((
            self.stdout.take().unwrap_or_default(),
            self.stderr.take().unwrap_or_default(),
        ))
    }
}

fn write_output(writer: &mut dyn Write, bytes: &[u8]) -> Result<(), CredactError> {
    writer
        .write_all(bytes)
        .and_then(|()| writer.flush())
        .map_err(|_| output_error("credact: command output could not be written"))
}

pub fn run_command(options: RunOptions<'_>) -> Result<i32, CredactError> {
    let RunOptions {
        invocation,
        secrets,
        stdout,
        stderr,
    } = options;

    let mut interrupts = Interrupts::register().map_err(|error| spawn_error_of(&error))?;
    let program = program_of(invocation)?;
    let output = if invocation.scan_output {
        Stdio::piped
    } else {
        Stdio::inherit
    };

    let mut command = CommandWrap::with_new(program, |command| {
        command
            .args(&invocation.command_arguments)
            .env_clear()
            .envs(child_environment_of(std::env::vars_os().collect(), secrets))
            .stdin(Stdio::inherit())
            .stdout(output())
            .stderr(output());
    });

    #[cfg(windows)]
    command.wrap(process_wrap::std::JobObject);

    let mut child = command.spawn().map_err(|error| spawn_error_of(&error))?;

    if !invocation.scan_output {
        let status = wait_for_status(child.as_mut(), &mut interrupts, |_| Ok(()))?;

        return Ok(exit_code_of(status));
    }

    let mut capture = Capture::start(child.as_mut())?;
    let status = wait_for_status(
        child.as_mut(),
        &mut interrupts,
        |child: &mut dyn ChildWrapper| capture.poll(child),
    )?;

    drop(interrupts);

    let (stdout_bytes, stderr_bytes) = capture.finish(child.as_mut())?;
    let values: Vec<&str> = secrets.iter().map(|secret| secret.value.as_str()).collect();

    write_output(stdout, &redact_buffer(&stdout_bytes, &values))?;
    write_output(stderr, &redact_buffer(&stderr_bytes, &values))?;

    Ok(exit_code_of(status))
}

#[cfg(test)]
#[path = "run_command.test.rs"]
mod tests;

#[cfg(test)]
#[path = "run_command.integration.test.rs"]
mod integration;
