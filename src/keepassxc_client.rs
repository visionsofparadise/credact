use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use crypto_box::{PublicKey, SalsaBox};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::keepassxc_box::{
    generate_secret_key, increment_nonce, open, random_nonce, seal, session_box_of, KEY_LENGTH,
};

pub const SOCKET_NAME: &str = "org.keepassxc.KeePassXC.BrowserServer";
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(35);
pub const DEFAULT_UNLOCK_INTERVAL: Duration = Duration::from_millis(1500);
pub const MAXIMUM_PENDING_BYTES: usize = 1024 * 1024;

const RECORD_DIRECTORY_NAME: &str = ".credact";
const RECORD_FILE_NAME: &str = "keepassxc-association.json";
const READ_CHUNK_BYTES: usize = 64 * 1024;
const TRUE_STRING: &str = "true";

const DATABASE_LOCKED_CODE: i64 = 1;
const ASSOCIATION_DENIED_CODE: i64 = 6;
const ASSOCIATION_REJECTED_CODE: i64 = 8;
const NO_LOGINS_CODE: i64 = 15;

const MALFORMED_REPLY_CLASS: &str = "keepassxc reply was malformed";
const TIMED_OUT_CLASS: &str = "keepassxc timed out";
const DATABASE_LOCKED_CLASS: &str = "keepassxc database stayed locked";
const NONCE_MISMATCH_CLASS: &str = "keepassxc nonce mismatch";
const DECRYPTION_CLASS: &str = "keepassxc could not decrypt reply";
const ASSOCIATION_DENIED_CLASS: &str = "keepassxc association was denied";
const ACCESS_DENIED_CLASS: &str = "keepassxc access to the matching entries was denied";
const NO_ENTRY_OR_DENIED_CLASS: &str = "keepassxc found no entry, or access to it was denied";
const NO_HOME_DIRECTORY_CLASS: &str = "keepassxc association record needs a home directory";
const LOOKUP_FAILED_CLASS: &str = "keepassxc lookup failed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeePassXcError {
    pub failure_class: String,
    pub error_code: Option<i64>,
}

impl KeePassXcError {
    fn of(failure_class: impl Into<String>) -> Self {
        Self {
            failure_class: failure_class.into(),
            error_code: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    Other,
}

impl Platform {
    fn current() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            Platform::Other
        }
    }
}

pub struct SocketEnvironment<'a> {
    pub variable_of: &'a dyn Fn(&str) -> Option<String>,
    pub temp_directory: PathBuf,
    pub exists: &'a dyn Fn(&Path) -> bool,
}

pub fn resolve_socket_path(environment: &SocketEnvironment<'_>, platform: Platform) -> PathBuf {
    if let Some(overridden) = (environment.variable_of)("KEEPASSXC_BROWSER_SOCKET_PATH") {
        if !overridden.is_empty() {
            return PathBuf::from(overridden);
        }
    }

    match platform {
        Platform::Windows => {
            let username = (environment.variable_of)("USERNAME").unwrap_or_default();

            PathBuf::from(format!(r"\\.\pipe\{SOCKET_NAME}_{username}"))
        }
        Platform::Linux => {
            let runtime_directory = (environment.variable_of)("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    let username = (environment.variable_of)("USER").unwrap_or_default();

                    environment
                        .temp_directory
                        .join(format!("runtime-{username}"))
                });
            let container_path = runtime_directory
                .join("app")
                .join("org.keepassxc.KeePassXC")
                .join(SOCKET_NAME);

            if (environment.exists)(&container_path) {
                container_path
            } else {
                runtime_directory.join(SOCKET_NAME)
            }
        }
        Platform::Other => environment.temp_directory.join(SOCKET_NAME),
    }
}

pub fn split_json_values(buffer: &[u8]) -> Result<(Vec<Value>, usize), serde_json::Error> {
    let mut stream = serde_json::Deserializer::from_slice(buffer).into_iter::<Value>();
    let mut values = Vec::new();
    let mut consumed = 0;

    loop {
        match stream.next() {
            None => {
                consumed = stream.byte_offset();

                break;
            }
            Some(Ok(value)) => {
                values.push(value);

                consumed = stream.byte_offset();
            }
            Some(Err(error)) if error.is_eof() => break,
            Some(Err(error)) => return Err(error),
        }
    }

    Ok((values, consumed))
}

fn action_of(value: &Value) -> Option<&str> {
    value.as_object()?.get("action")?.as_str()
}

fn string_form_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

fn error_code_of(text: &str) -> Option<i64> {
    let trimmed = text.trim_start();
    let (sign, unsigned) = match trimmed.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    let end = unsigned
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(unsigned.len());

    if end == 0 {
        return None;
    }

    unsigned[..end].parse::<i64>().ok().map(|code| sign * code)
}

fn error_of(code: &Value, description: Option<&Value>) -> KeePassXcError {
    let parsed = error_code_of(&string_form_of(code));
    let shown = parsed.map_or_else(|| "unknown".to_string(), |code| code.to_string());
    let description = description.and_then(Value::as_str).unwrap_or_default();

    KeePassXcError {
        failure_class: format!("keepassxc error {shown}: {description}"),
        error_code: parsed,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportError {
    Unavailable,
    TimedOut,
    Malformed,
}

fn unavailable_at(socket_path: &Path) -> KeePassXcError {
    KeePassXcError::of(format!(
        "keepassxc socket unavailable at {}",
        socket_path.display()
    ))
}

fn failure_of(error: TransportError, socket_path: &Path) -> KeePassXcError {
    match error {
        TransportError::Unavailable => unavailable_at(socket_path),
        TransportError::TimedOut => KeePassXcError::of(TIMED_OUT_CLASS),
        TransportError::Malformed => KeePassXcError::of(MALFORMED_REPLY_CLASS),
    }
}

#[cfg(windows)]
fn open_streams(
    path: &Path,
    deadline: Instant,
) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    const PIPE_BUSY_OS_ERROR: i32 = 231;

    const PIPE_BUSY_RETRY_INTERVAL: Duration = Duration::from_millis(50);

    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        {
            Ok(file) => {
                let reader = file.try_clone()?;

                return Ok((Box::new(reader), Box::new(file)));
            }
            Err(error)
                if error.raw_os_error() == Some(PIPE_BUSY_OS_ERROR)
                    && Instant::now() + PIPE_BUSY_RETRY_INTERVAL < deadline =>
            {
                thread::sleep(PIPE_BUSY_RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn open_streams(
    path: &Path,
    _deadline: Instant,
) -> io::Result<(Box<dyn Read + Send>, Box<dyn Write + Send>)> {
    let stream = std::os::unix::net::UnixStream::connect(path)?;
    let reader = stream.try_clone()?;

    Ok((Box::new(reader), Box::new(stream)))
}

pub struct Connection {
    writer: Box<dyn Write + Send>,
    demand: Sender<()>,
    chunks: Receiver<io::Result<Vec<u8>>>,
    read_outstanding: bool,
    pending: Vec<u8>,
    failure: Option<TransportError>,
}

impl Connection {
    pub fn open(path: &Path, deadline: Instant) -> Result<Self, KeePassXcError> {
        let (reader, writer) = open_streams(path, deadline).map_err(|_| unavailable_at(path))?;

        Ok(Self::from_parts(reader, writer))
    }

    pub fn from_parts(mut reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>) -> Self {
        let (demand, demands) = mpsc::channel::<()>();
        let (chunk_sender, chunks) = mpsc::channel::<io::Result<Vec<u8>>>();

        thread::spawn(move || {
            let mut buffer = vec![0u8; READ_CHUNK_BYTES];

            while demands.recv().is_ok() {
                let outcome = reader
                    .read(&mut buffer)
                    .map(|count| buffer[..count].to_vec());

                if chunk_sender.send(outcome).is_err() {
                    break;
                }
            }
        });

        Self {
            writer,
            demand,
            chunks,
            read_outstanding: false,
            pending: Vec::new(),
            failure: None,
        }
    }

    fn fail(&mut self, error: TransportError) -> TransportError {
        *self.failure.get_or_insert(error)
    }

    fn write_message(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }

        let outcome = self
            .writer
            .write_all(bytes)
            .and_then(|()| self.writer.flush());

        match outcome {
            Ok(()) => Ok(()),
            Err(_) => Err(self.fail(TransportError::Unavailable)),
        }
    }

    fn read_chunk(&mut self, deadline: Instant) -> Result<Vec<u8>, TransportError> {
        if !self.read_outstanding {
            if self.demand.send(()).is_err() {
                return Err(self.fail(TransportError::Unavailable));
            }

            self.read_outstanding = true;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());

        match self.chunks.recv_timeout(remaining) {
            Ok(Ok(chunk)) => {
                self.read_outstanding = false;

                if chunk.is_empty() {
                    Err(self.fail(TransportError::Unavailable))
                } else {
                    Ok(chunk)
                }
            }
            Ok(Err(_)) => {
                self.read_outstanding = false;

                Err(self.fail(TransportError::Unavailable))
            }
            Err(RecvTimeoutError::Timeout) => Err(self.fail(TransportError::TimedOut)),
            Err(RecvTimeoutError::Disconnected) => Err(self.fail(TransportError::Unavailable)),
        }
    }

    fn await_action(&mut self, action: &str, deadline: Instant) -> Result<Value, TransportError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }

        loop {
            let split = match split_json_values(&self.pending) {
                Ok(split) => split,
                Err(_) => return Err(self.fail(TransportError::Malformed)),
            };
            let (values, consumed) = split;

            self.pending.drain(..consumed);

            if let Some(value) = values
                .into_iter()
                .find(|value| action_of(value) == Some(action))
            {
                return Ok(value);
            }

            if self.pending.len() > MAXIMUM_PENDING_BYTES {
                return Err(self.fail(TransportError::Malformed));
            }

            let chunk = self.read_chunk(deadline)?;

            self.pending.extend_from_slice(&chunk);
        }
    }
}

pub type Connector = Box<dyn FnMut(&Path, Instant) -> Result<Connection, KeePassXcError>>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangePublicKeysRequest<'a> {
    action: &'a str,
    public_key: String,
    nonce: String,
    #[serde(rename = "clientID")]
    client_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedRequest<'a> {
    action: &'a str,
    message: String,
    nonce: String,
    #[serde(rename = "clientID")]
    client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger_unlock: Option<&'static str>,
}

#[derive(Serialize)]
struct GetDatabaseHashMessage<'a> {
    action: &'a str,
}

#[derive(Serialize)]
struct TestAssociateMessage<'a> {
    action: &'a str,
    id: &'a str,
    key: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssociateMessage<'a> {
    action: &'a str,
    key: String,
    id_key: String,
}

#[derive(Serialize)]
struct AssociationKey<'a> {
    id: &'a str,
    key: &'a str,
}

#[derive(Serialize)]
struct GetLoginsMessage<'a> {
    action: &'a str,
    url: &'a str,
    keys: Vec<AssociationKey<'a>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssociationRecord {
    id: String,
    id_key: String,
}

struct SessionKeys {
    session: SalsaBox,
    client_id: String,
    public_key: PublicKey,
}

fn read_record(record_path: &Path) -> Result<Option<AssociationRecord>, KeePassXcError> {
    let malformed = || {
        KeePassXcError::of(format!(
            "keepassxc association record at {} is malformed",
            record_path.display()
        ))
    };
    let content = match std::fs::read(record_path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(malformed()),
    };
    let record: AssociationRecord = serde_json::from_slice(&content).map_err(|_| malformed())?;

    if record.id.is_empty() {
        return Err(malformed());
    }

    match BASE64.decode(&record.id_key) {
        Ok(bytes) if bytes.len() == KEY_LENGTH => Ok(Some(record)),
        _ => Err(malformed()),
    }
}

#[cfg(unix)]
fn create_record_directory(directory: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
}

#[cfg(windows)]
fn create_record_directory(directory: &Path) -> io::Result<()> {
    std::fs::create_dir_all(directory)
}

#[cfg(unix)]
fn write_record_file(record_path: &Path, text: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(record_path)?;

    file.write_all(text.as_bytes())
}

#[cfg(windows)]
fn write_record_file(record_path: &Path, text: &str) -> io::Result<()> {
    std::fs::write(record_path, text)
}

fn write_record(record_path: &Path, record: &AssociationRecord) -> Result<(), KeePassXcError> {
    let failed = || KeePassXcError::of(LOOKUP_FAILED_CLASS);
    let directory = record_path.parent().ok_or_else(failed)?;

    create_record_directory(directory).map_err(|_| failed())?;

    let text = serde_json::to_string(record).map_err(|_| failed())?;

    write_record_file(record_path, &format!("{text}\n")).map_err(|_| failed())
}

struct Requester<'a> {
    connection: &'a mut Connection,
    socket_path: &'a Path,
    deadline: Instant,
}

impl Requester<'_> {
    fn request(&mut self, outer: &impl Serialize, action: &str) -> Result<Value, KeePassXcError> {
        let text =
            serde_json::to_vec(outer).map_err(|_| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;
        let written = self.connection.write_message(&text);

        written.map_err(|error| failure_of(error, self.socket_path))?;

        let received = self.connection.await_action(action, self.deadline);

        received.map_err(|error| failure_of(error, self.socket_path))
    }

    fn handshake(&mut self) -> Result<SessionKeys, KeePassXcError> {
        let secret_key = generate_secret_key();
        let public_key = secret_key.public_key();
        let client_id = BASE64.encode(random_nonce());
        let request = ChangePublicKeysRequest {
            action: "change-public-keys",
            public_key: BASE64.encode(public_key.as_bytes()),
            nonce: BASE64.encode(random_nonce()),
            client_id: &client_id,
        };
        let reply = self.request(&request, "change-public-keys")?;
        let host_public_key = reply
            .get("publicKey")
            .and_then(Value::as_str)
            .filter(|_| reply.get("success").and_then(Value::as_str) == Some(TRUE_STRING))
            .and_then(|encoded| BASE64.decode(encoded).ok())
            .filter(|bytes| bytes.len() == KEY_LENGTH)
            .ok_or_else(|| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;
        let session = session_box_of(&host_public_key, &secret_key)
            .ok_or_else(|| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;

        Ok(SessionKeys {
            session,
            client_id,
            public_key,
        })
    }

    fn encrypted_request(
        &mut self,
        keys: &SessionKeys,
        action: &str,
        inner: &impl Serialize,
        trigger_unlock: bool,
    ) -> Result<Value, KeePassXcError> {
        let nonce = random_nonce();
        let plaintext =
            serde_json::to_vec(inner).map_err(|_| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;
        let sealed = seal(&keys.session, &nonce, &plaintext)
            .map_err(|_| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;
        let outer = EncryptedRequest {
            action,
            message: BASE64.encode(&sealed),
            nonce: BASE64.encode(nonce),
            client_id: &keys.client_id,
            trigger_unlock: trigger_unlock.then_some(TRUE_STRING),
        };
        let reply = self.request(&outer, action)?;

        if let Some(code) = reply.get("errorCode") {
            return Err(error_of(code, reply.get("error")));
        }

        let reply_nonce = increment_nonce(&nonce);
        let expected = BASE64.encode(reply_nonce);

        if reply.get("nonce").and_then(Value::as_str) != Some(expected.as_str()) {
            return Err(KeePassXcError::of(NONCE_MISMATCH_CLASS));
        }

        let message = reply
            .get("message")
            .and_then(Value::as_str)
            .ok_or_else(|| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;
        let ciphertext = BASE64
            .decode(message)
            .map_err(|_| KeePassXcError::of(DECRYPTION_CLASS))?;
        let opened = open(&keys.session, &reply_nonce, &ciphertext)
            .ok_or_else(|| KeePassXcError::of(DECRYPTION_CLASS))?;
        let parsed: Value = serde_json::from_slice(&opened)
            .map_err(|_| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;

        if !parsed.is_object()
            || parsed.get("success").and_then(Value::as_str) != Some(TRUE_STRING)
            || parsed.get("nonce").and_then(Value::as_str) != Some(expected.as_str())
        {
            return Err(KeePassXcError::of(MALFORMED_REPLY_CLASS));
        }

        Ok(parsed)
    }

    fn wait_for_open(
        &mut self,
        keys: &SessionKeys,
        unlock_interval: Duration,
    ) -> Result<(), KeePassXcError> {
        let mut trigger_unlock = true;

        loop {
            let outcome = self.encrypted_request(
                keys,
                "get-databasehash",
                &GetDatabaseHashMessage {
                    action: "get-databasehash",
                },
                trigger_unlock,
            );

            match outcome {
                Ok(_) => return Ok(()),
                Err(error) if error.error_code == Some(DATABASE_LOCKED_CODE) => {}
                Err(error) if error.failure_class == TIMED_OUT_CLASS => {
                    return Err(KeePassXcError::of(DATABASE_LOCKED_CLASS))
                }
                Err(error) => return Err(error),
            }

            trigger_unlock = false;

            let remaining = self.deadline.saturating_duration_since(Instant::now());

            thread::sleep(unlock_interval.min(remaining));
        }
    }

    fn associate(
        &mut self,
        keys: &SessionKeys,
        record_path: Option<&Path>,
    ) -> Result<AssociationRecord, KeePassXcError> {
        let record_path = record_path.ok_or_else(|| KeePassXcError::of(NO_HOME_DIRECTORY_CLASS))?;

        if let Some(existing) = read_record(record_path)? {
            let outcome = self.encrypted_request(
                keys,
                "test-associate",
                &TestAssociateMessage {
                    action: "test-associate",
                    id: &existing.id,
                    key: &existing.id_key,
                },
                false,
            );

            return match outcome {
                Ok(_) => Ok(existing),
                Err(error) if error.error_code == Some(ASSOCIATION_REJECTED_CODE) => {
                    Err(KeePassXcError::of(format!(
                        "keepassxc association was rejected; delete {} to re-associate",
                        record_path.display()
                    )))
                }
                Err(error) => Err(error),
            };
        }

        let identity_key = BASE64.encode(generate_secret_key().public_key().as_bytes());
        let outcome = self.encrypted_request(
            keys,
            "associate",
            &AssociateMessage {
                action: "associate",
                key: BASE64.encode(keys.public_key.as_bytes()),
                id_key: identity_key.clone(),
            },
            false,
        );
        let reply = match outcome {
            Ok(reply) => reply,
            Err(error) if error.error_code == Some(ASSOCIATION_DENIED_CODE) => {
                return Err(KeePassXcError::of(ASSOCIATION_DENIED_CLASS))
            }
            Err(error) => return Err(error),
        };
        let id = reply
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;
        let record = AssociationRecord {
            id: id.to_string(),
            id_key: identity_key,
        };

        write_record(record_path, &record)?;

        Ok(record)
    }

    fn get_logins(
        &mut self,
        keys: &SessionKeys,
        record: &AssociationRecord,
        reference: &str,
    ) -> Result<Vec<Value>, KeePassXcError> {
        let outcome = self.encrypted_request(
            keys,
            "get-logins",
            &GetLoginsMessage {
                action: "get-logins",
                url: reference,
                keys: vec![AssociationKey {
                    id: &record.id,
                    key: &record.id_key,
                }],
            },
            false,
        );
        let reply = match outcome {
            Ok(reply) => reply,
            Err(error) if error.error_code == Some(NO_LOGINS_CODE) => {
                return Err(KeePassXcError::of(NO_ENTRY_OR_DENIED_CLASS))
            }
            Err(error) => return Err(error),
        };
        let entries = reply
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| KeePassXcError::of(MALFORMED_REPLY_CLASS))?;

        if entries.is_empty() {
            return Err(KeePassXcError::of(ACCESS_DENIED_CLASS));
        }

        Ok(entries.clone())
    }
}

pub struct ClientOptions {
    pub socket_path: PathBuf,
    pub record_path: Option<PathBuf>,
    pub deadline: Duration,
    pub unlock_interval: Duration,
}

impl ClientOptions {
    pub fn from_environment() -> Self {
        let variable_of = |name: &str| std::env::var(name).ok();
        let exists = |path: &Path| path.exists();
        let socket_path = resolve_socket_path(
            &SocketEnvironment {
                variable_of: &variable_of,
                temp_directory: std::env::temp_dir(),
                exists: &exists,
            },
            Platform::current(),
        );

        Self {
            socket_path,
            record_path: std::env::home_dir()
                .map(|home| home.join(RECORD_DIRECTORY_NAME).join(RECORD_FILE_NAME)),
            deadline: DEFAULT_DEADLINE,
            unlock_interval: DEFAULT_UNLOCK_INTERVAL,
        }
    }
}

struct OpenSession {
    connection: Connection,
    keys: SessionKeys,
    record: AssociationRecord,
}

fn start(
    connector: &mut Connector,
    options: &ClientOptions,
    deadline: Instant,
) -> Result<OpenSession, KeePassXcError> {
    let mut connection = connector(&options.socket_path, deadline)?;
    let mut requester = Requester {
        connection: &mut connection,
        socket_path: &options.socket_path,
        deadline,
    };
    let keys = requester.handshake()?;

    requester.wait_for_open(&keys, options.unlock_interval)?;

    let record = requester.associate(&keys, options.record_path.as_deref())?;

    Ok(OpenSession {
        connection,
        keys,
        record,
    })
}

pub struct LookupSession {
    options: ClientOptions,
    connector: Connector,
    session: Option<Result<OpenSession, KeePassXcError>>,
}

impl LookupSession {
    pub fn new(options: ClientOptions) -> Self {
        Self::with_connector(options, Box::new(Connection::open))
    }

    pub fn with_connector(options: ClientOptions, connector: Connector) -> Self {
        Self {
            options,
            connector,
            session: None,
        }
    }

    pub fn lookup(&mut self, reference: &str) -> Result<Vec<Value>, KeePassXcError> {
        let deadline = Instant::now() + self.options.deadline;
        let connector = &mut self.connector;
        let options = &self.options;
        let session = self
            .session
            .get_or_insert_with(|| start(connector, options, deadline));

        match session {
            Err(error) => Err(error.clone()),
            Ok(session) => {
                let mut requester = Requester {
                    connection: &mut session.connection,
                    socket_path: &options.socket_path,
                    deadline,
                };

                requester.get_logins(&session.keys, &session.record, reference)
            }
        }
    }
}

#[cfg(test)]
#[path = "keepassxc_client.test.rs"]
mod tests;

#[cfg(test)]
#[path = "keepassxc_client.integration.test.rs"]
mod integration;
