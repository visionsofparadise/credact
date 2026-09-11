use std::io::{Error, ErrorKind};
use std::process::ExitStatus;
use std::thread;
use std::time::{Duration, Instant};

use process_wrap::std::ChildWrapper;

pub const GRACEFUL_TERMINATION: Duration = Duration::from_millis(250);
pub const FORCED_TERMINATION: Duration = Duration::from_secs(5);

const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[cfg(unix)]
fn request_graceful_exit(child: &mut dyn ChildWrapper) -> std::io::Result<()> {
    child.signal(signal_hook::consts::SIGTERM)
}

#[cfg(windows)]
fn request_graceful_exit(child: &mut dyn ChildWrapper) -> std::io::Result<()> {
    child.start_kill()
}

pub fn terminate_child(child: &mut dyn ChildWrapper) -> std::io::Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }

    let started_at = Instant::now();
    let mut forced = false;

    request_graceful_exit(child)?;

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }

        let elapsed = started_at.elapsed();

        if !forced && elapsed >= GRACEFUL_TERMINATION {
            child.start_kill()?;

            forced = true;
        }

        if elapsed >= FORCED_TERMINATION {
            return Err(Error::new(ErrorKind::TimedOut, "child did not terminate"));
        }

        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
#[path = "terminate_child.integration.test.rs"]
mod integration;
