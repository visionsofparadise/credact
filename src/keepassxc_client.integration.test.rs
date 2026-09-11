use super::*;
use serde_json::json;
use std::collections::HashMap;
use std::io::{PipeReader, PipeWriter};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::keepassxc_box::NONCE_LENGTH;

const TEST_DEADLINE: Duration = Duration::from_secs(2);

static DIRECTORY_COUNT: AtomicUsize = AtomicUsize::new(0);

#[derive(Default, Clone)]
struct ScriptedReply {
    error: Option<i64>,
    body: Option<Value>,
    broadcast_before: bool,
    split_writes: bool,
    wrong_nonce: bool,
    wrong_key: bool,
    silent: bool,
    raw_text: Option<String>,
    flood_bytes: Option<usize>,
    wrong_inner_nonce: bool,
    delay: Option<Duration>,
}

type Script = Arc<dyn Fn(&str, &Value, usize) -> ScriptedReply + Send + Sync>;

#[derive(Default)]
struct FakeState {
    actions: Vec<String>,
    inners: HashMap<String, Value>,
    envelopes: HashMap<String, Value>,
    sent: Vec<Value>,
    chunks: usize,
    malformed_chunks: usize,
    closed: usize,
}

struct Fake {
    state: Arc<Mutex<FakeState>>,
    connections: Arc<AtomicUsize>,
}

impl Fake {
    fn state(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().expect("the fake state is readable")
    }

    fn actions(&self) -> Vec<String> {
        self.state().actions.clone()
    }

    fn envelope(&self, action: &str) -> Value {
        self.state()
            .envelopes
            .get(action)
            .cloned()
            .unwrap_or(Value::Null)
    }

    fn inner(&self, action: &str) -> Value {
        self.state()
            .inners
            .get(action)
            .cloned()
            .unwrap_or(Value::Null)
    }

    fn sent_for(&self, action: &str) -> Vec<Value> {
        self.state()
            .sent
            .iter()
            .filter(|envelope| envelope.get("action").and_then(Value::as_str) == Some(action))
            .cloned()
            .collect()
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    fn connections_closed(&self) -> usize {
        self.state().closed
    }
}

fn send_reply(
    writer: &mut PipeWriter,
    session: &SalsaBox,
    action: &str,
    request_nonce: &[u8; NONCE_LENGTH],
    scripted: &ScriptedReply,
) {
    if scripted.silent {
        return;
    }

    if let Some(count) = scripted.flood_bytes {
        let _ = writer.write_all(&vec![b'{'; count]);

        return;
    }

    if let Some(text) = &scripted.raw_text {
        let _ = writer.write_all(text.as_bytes());

        return;
    }

    if let Some(code) = scripted.error {
        let payload = json!({
            "action": action,
            "errorCode": code.to_string(),
            "error": format!("scripted {code}"),
        });
        let _ = writer.write_all(payload.to_string().as_bytes());

        return;
    }

    if let Some(delay) = scripted.delay {
        thread::sleep(delay);
    }

    let reply_nonce = increment_nonce(request_nonce);
    let impostor = scripted.wrong_key.then(|| {
        session_box_of(
            generate_secret_key().public_key().as_bytes(),
            &generate_secret_key(),
        )
        .expect("the impostor key is accepted")
    });
    let seal_session = impostor.as_ref().unwrap_or(session);
    let mut inner_reply = json!({
        "action": action,
        "nonce": BASE64.encode(if scripted.wrong_inner_nonce { *request_nonce } else { reply_nonce }),
        "success": "true",
    });

    if let Some(Value::Object(body)) = &scripted.body {
        for (name, value) in body {
            inner_reply[name] = value.clone();
        }
    }

    let sealed = seal(
        seal_session,
        &reply_nonce,
        inner_reply.to_string().as_bytes(),
    )
    .expect("the reply seals");
    let payload = json!({
        "action": action,
        "message": BASE64.encode(&sealed),
        "nonce": BASE64.encode(if scripted.wrong_nonce { *request_nonce } else { reply_nonce }),
    });
    let text = if scripted.broadcast_before {
        format!("{}{payload}", json!({ "action": "database-unlocked" }))
    } else {
        payload.to_string()
    };

    if scripted.split_writes {
        let half = text.len() / 2;

        let _ = writer.write_all(&text.as_bytes()[..half]);

        thread::sleep(Duration::from_millis(20));

        let _ = writer.write_all(&text.as_bytes()[half..]);

        return;
    }

    let _ = writer.write_all(text.as_bytes());
}

fn serve(
    mut reader: PipeReader,
    mut writer: PipeWriter,
    state: &Mutex<FakeState>,
    script: &Script,
    host_public_key_bytes: Option<usize>,
) {
    let secret_key = generate_secret_key();
    let mut session: Option<SalsaBox> = None;
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut buffer = vec![0u8; READ_CHUNK_BYTES];

    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) | Err(_) => {
                state.lock().expect("the fake state is writable").closed += 1;

                return;
            }
            Ok(count) => count,
        };

        state.lock().expect("the fake state is writable").chunks += 1;

        let outer = match serde_json::from_slice::<Value>(&buffer[..count]) {
            Ok(outer) if outer.is_object() => outer,
            _ => {
                state
                    .lock()
                    .expect("the fake state is writable")
                    .malformed_chunks += 1;

                continue;
            }
        };
        let action = outer
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let seen = *counts.get(&action).unwrap_or(&0);

        counts.insert(action.clone(), seen + 1);

        {
            let mut state = state.lock().expect("the fake state is writable");

            state.actions.push(action.clone());
            state.envelopes.insert(action.clone(), outer.clone());
            state.sent.push(outer.clone());
        }

        if action == "change-public-keys" {
            let client_public_key = BASE64
                .decode(outer.get("publicKey").and_then(Value::as_str).unwrap_or(""))
                .expect("the client public key is base64");

            session = session_box_of(&client_public_key, &secret_key);

            let public_key = secret_key.public_key();
            let shown = &public_key.as_bytes()[..host_public_key_bytes.unwrap_or(KEY_LENGTH)];
            let reply = json!({
                "action": action,
                "version": "2.7.4",
                "publicKey": BASE64.encode(shown),
                "success": "true",
                "nonce": outer.get("nonce").cloned().unwrap_or(Value::Null),
            });
            let _ = writer.write_all(reply.to_string().as_bytes());

            continue;
        }

        let session = session.as_ref().expect("the handshake ran first");
        let request_nonce: [u8; NONCE_LENGTH] = BASE64
            .decode(outer.get("nonce").and_then(Value::as_str).unwrap_or(""))
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .expect("the request nonce is twenty-four bytes");
        let ciphertext = BASE64
            .decode(outer.get("message").and_then(Value::as_str).unwrap_or(""))
            .unwrap_or_default();
        let inner = open(session, &request_nonce, &ciphertext)
            .and_then(|opened| serde_json::from_slice::<Value>(&opened).ok())
            .unwrap_or_else(|| json!({}));

        state
            .lock()
            .expect("the fake state is writable")
            .inners
            .insert(action.clone(), inner.clone());

        send_reply(
            &mut writer,
            session,
            &action,
            &request_nonce,
            &script(&action, &inner, seen),
        );
    }
}

fn start_fake(script: Script, host_public_key_bytes: Option<usize>) -> (Fake, Connector) {
    let fake = Fake {
        state: Arc::new(Mutex::new(FakeState::default())),
        connections: Arc::new(AtomicUsize::new(0)),
    };
    let state = Arc::clone(&fake.state);
    let connections = Arc::clone(&fake.connections);
    let connector: Connector = Box::new(move |_path, _deadline| {
        connections.fetch_add(1, Ordering::SeqCst);

        let (server_reader, client_writer) = std::io::pipe().expect("the request pipe opens");
        let (client_reader, server_writer) = std::io::pipe().expect("the reply pipe opens");
        let state = Arc::clone(&state);
        let script = Arc::clone(&script);

        thread::spawn(move || {
            serve(
                server_reader,
                server_writer,
                &state,
                &script,
                host_public_key_bytes,
            );
        });

        Ok(Connection::from_parts(
            Box::new(client_reader),
            Box::new(client_writer),
        ))
    });

    (fake, connector)
}

fn create_directory() -> PathBuf {
    let unique = DIRECTORY_COUNT.fetch_add(1, Ordering::SeqCst);
    let directory =
        std::env::temp_dir().join(format!("credact-client-{}-{unique}", std::process::id()));

    std::fs::create_dir_all(&directory).expect("the directory is created");

    directory
}

fn stored_id_key() -> String {
    BASE64.encode(generate_secret_key().public_key().as_bytes())
}

fn record_path_of(directory: &Path) -> PathBuf {
    directory.join(RECORD_DIRECTORY_NAME).join(RECORD_FILE_NAME)
}

fn write_stored_record(directory: &Path, id: &str, id_key: &str) -> PathBuf {
    let record_path = record_path_of(directory);

    std::fs::create_dir_all(
        record_path
            .parent()
            .expect("the record path has a directory"),
    )
    .expect("the record directory is created");
    std::fs::write(
        &record_path,
        format!("{}\n", json!({ "id": id, "idKey": id_key })),
    )
    .expect("the record is written");

    record_path
}

fn options_of(record_path: &Path, deadline: Duration, unlock_interval: Duration) -> ClientOptions {
    ClientOptions {
        socket_path: PathBuf::from("credact-fake-socket"),
        record_path: Some(record_path.to_path_buf()),
        deadline,
        unlock_interval,
    }
}

fn lookup_once(
    connector: Connector,
    options: ClientOptions,
    reference: &str,
) -> Result<Vec<Value>, KeePassXcError> {
    let mut session = LookupSession::with_connector(options, connector);

    session.lookup(reference)
}

fn wait_for_close(fake: &Fake) -> usize {
    for _ in 0..200 {
        if fake.connections_closed() > 0 {
            return fake.connections_closed();
        }

        thread::sleep(Duration::from_millis(10));
    }

    fake.connections_closed()
}

fn scripted_entries() -> Value {
    json!([{ "login": "synthetic-login", "password": "synthetic-password", "stringFields": [] }])
}

fn associated() -> Script {
    Arc::new(|action, _inner, _seen| {
        if action == "get-logins" {
            return ScriptedReply {
                body: Some(json!({ "count": 1, "entries": scripted_entries() })),
                ..ScriptedReply::default()
            };
        }

        ScriptedReply::default()
    })
}

fn scripted_for(action_name: &'static str, reply: ScriptedReply) -> Script {
    Arc::new(move |action, inner, seen| {
        if action == action_name {
            return reply.clone();
        }

        associated()(action, inner, seen)
    })
}

fn failure_of_lookup(outcome: Result<Vec<Value>, KeePassXcError>) -> String {
    outcome
        .expect_err("the lookup fails")
        .failure_class
        .to_string()
}

#[test]
fn rejects_an_association_record_whose_id_key_is_the_wrong_length() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &BASE64.encode([3u8; 31]));
    let (_fake, connector) = start_fake(associated(), None);
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(
        failure_of_lookup(outcome),
        format!(
            "keepassxc association record at {} is malformed",
            record_path.display()
        )
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn rejects_a_handshake_whose_host_public_key_is_the_wrong_length() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (_fake, connector) = start_fake(associated(), Some(16));
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), MALFORMED_REPLY_CLASS);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn rejects_a_reply_whose_inner_nonce_differs_from_its_outer_nonce() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (_fake, connector) = start_fake(
        scripted_for(
            "get-databasehash",
            ScriptedReply {
                wrong_inner_nonce: true,
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), MALFORMED_REPLY_CLASS);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn renews_the_deadline_for_each_lookup_rather_than_spending_one_across_the_session() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (_fake, connector) = start_fake(
        Arc::new(|action, _inner, seen| {
            if action == "get-logins" {
                return ScriptedReply {
                    body: Some(json!({ "entries": scripted_entries() })),
                    delay: (seen > 0).then(|| Duration::from_millis(250)),
                    ..ScriptedReply::default()
                };
            }

            ScriptedReply::default()
        }),
        None,
    );
    let mut session = LookupSession::with_connector(
        options_of(
            &record_path,
            Duration::from_millis(400),
            DEFAULT_UNLOCK_INTERVAL,
        ),
        connector,
    );

    session
        .lookup("keepassxc://synthetic/password")
        .expect("the first lookup succeeds");

    thread::sleep(Duration::from_millis(250));

    assert_eq!(
        session
            .lookup("keepassxc://other/password")
            .expect("the second lookup renews the deadline"),
        scripted_entries().as_array().cloned().unwrap_or_default()
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn runs_the_sequence_and_returns_the_entries_untouched() {
    let directory = create_directory();
    let id_key = stored_id_key();
    let record_path = write_stored_record(&directory, "credact", &id_key);
    let (fake, connector) = start_fake(associated(), None);
    let entries = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    )
    .expect("the lookup succeeds");

    assert_eq!(
        fake.actions(),
        [
            "change-public-keys",
            "get-databasehash",
            "test-associate",
            "get-logins"
        ]
    );
    assert_eq!(
        fake.inner("get-logins"),
        json!({
            "action": "get-logins",
            "url": "keepassxc://synthetic/password",
            "keys": [{ "id": "credact", "key": id_key }],
        })
    );
    assert_eq!(
        entries,
        scripted_entries().as_array().cloned().unwrap_or_default()
    );
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn reuses_one_connection_handshake_and_association_across_references() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(associated(), None);

    {
        let mut session = LookupSession::with_connector(
            options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
            connector,
        );

        session
            .lookup("keepassxc://synthetic/password")
            .expect("the first lookup succeeds");
        session
            .lookup("keepassxc://other/password")
            .expect("the second lookup succeeds");
    }

    assert_eq!(
        fake.actions(),
        [
            "change-public-keys",
            "get-databasehash",
            "test-associate",
            "get-logins",
            "get-logins"
        ]
    );
    assert_eq!(fake.connection_count(), 1);
    assert_eq!(
        fake.inner("get-logins")["url"],
        "keepassxc://other/password"
    );
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn writes_each_request_as_one_raw_chunk_that_parses_whole() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(associated(), None);

    lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    )
    .expect("the lookup succeeds");

    assert_eq!(fake.state().chunks, 4);
    assert_eq!(fake.state().malformed_chunks, 0);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn carries_a_constant_client_id_and_triggers_unlock_only_on_the_poll() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(associated(), None);

    lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    )
    .expect("the lookup succeeds");

    let client_ids: Vec<String> = fake
        .state()
        .sent
        .iter()
        .map(|envelope| {
            envelope
                .get("clientID")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let first = client_ids.first().cloned().unwrap_or_default();

    assert_eq!(client_ids.len(), 4);
    assert!(client_ids.iter().all(|client_id| *client_id == first));
    assert_eq!(
        BASE64
            .decode(&first)
            .expect("the client id is base64")
            .len(),
        NONCE_LENGTH
    );
    assert_eq!(fake.envelope("get-databasehash")["triggerUnlock"], "true");
    assert_eq!(fake.envelope("test-associate").get("triggerUnlock"), None);
    assert_eq!(fake.envelope("get-logins").get("triggerUnlock"), None);
    assert_eq!(
        fake.envelope("change-public-keys").get("triggerUnlock"),
        None
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn associates_on_first_use_and_stores_the_id_with_the_id_key() {
    let directory = create_directory();
    let record_path = record_path_of(&directory);
    let (fake, connector) = start_fake(
        Arc::new(|action, _inner, _seen| {
            if action == "associate" {
                return ScriptedReply {
                    body: Some(json!({ "id": "planner" })),
                    ..ScriptedReply::default()
                };
            }

            if action == "get-logins" {
                return ScriptedReply {
                    body: Some(json!({ "entries": scripted_entries() })),
                    ..ScriptedReply::default()
                };
            }

            ScriptedReply::default()
        }),
        None,
    );

    lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    )
    .expect("the lookup succeeds");

    assert_eq!(
        fake.actions(),
        [
            "change-public-keys",
            "get-databasehash",
            "associate",
            "get-logins"
        ]
    );

    let sent_id_key = fake.inner("associate")["idKey"].clone();
    let stored: Value =
        serde_json::from_slice(&std::fs::read(&record_path).expect("the record is written"))
            .expect("the record parses");

    assert_eq!(stored, json!({ "id": "planner", "idKey": sent_id_key }));
    assert_eq!(
        BASE64
            .decode(sent_id_key.as_str().unwrap_or_default())
            .expect("the identity key is base64")
            .len(),
        KEY_LENGTH
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&record_path)
                .expect("the record exists")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(directory.join(RECORD_DIRECTORY_NAME))
                .expect("the record directory exists")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn polls_until_the_database_is_unlocked() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(locked_until_the_third_poll(), None);
    let entries = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, Duration::from_millis(10)),
        "keepassxc://synthetic/password",
    )
    .expect("the lookup succeeds");

    assert_eq!(fake.sent_for("get-databasehash").len(), 3);
    assert_eq!(
        entries,
        scripted_entries().as_array().cloned().unwrap_or_default()
    );

    let _ = std::fs::remove_dir_all(&directory);
}

fn locked_until_the_third_poll() -> Script {
    Arc::new(|action, _inner, seen| {
        if action == "get-databasehash" && seen < 2 {
            return ScriptedReply {
                error: Some(1),
                ..ScriptedReply::default()
            };
        }

        if action == "get-logins" {
            return ScriptedReply {
                body: Some(json!({ "entries": scripted_entries() })),
                ..ScriptedReply::default()
            };
        }

        ScriptedReply::default()
    })
}

#[test]
fn triggers_the_unlock_prompt_once_rather_than_on_every_poll() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(locked_until_the_third_poll(), None);

    lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, Duration::from_millis(10)),
        "keepassxc://synthetic/password",
    )
    .expect("the lookup succeeds");

    let polls = fake.sent_for("get-databasehash");

    assert_eq!(polls.len(), 3);
    assert_eq!(polls[0]["triggerUnlock"], "true");
    assert!(polls[1..]
        .iter()
        .all(|poll| poll.get("triggerUnlock").is_none()));

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn fails_closed_when_the_database_never_unlocks() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "get-databasehash",
            ScriptedReply {
                error: Some(1),
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(
            &record_path,
            Duration::from_millis(100),
            Duration::from_millis(10),
        ),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), DATABASE_LOCKED_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn reads_a_reply_that_shares_a_chunk_with_a_broadcast() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (_fake, connector) = start_fake(
        Arc::new(|action, _inner, _seen| {
            if action == "get-databasehash" {
                return ScriptedReply {
                    broadcast_before: true,
                    ..ScriptedReply::default()
                };
            }

            if action == "get-logins" {
                return ScriptedReply {
                    body: Some(json!({ "entries": scripted_entries() })),
                    split_writes: true,
                    ..ScriptedReply::default()
                };
            }

            ScriptedReply::default()
        }),
        None,
    );
    let entries = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    )
    .expect("the lookup succeeds");

    assert_eq!(
        entries,
        scripted_entries().as_array().cloned().unwrap_or_default()
    );

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn names_the_record_path_when_the_association_is_rejected() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "test-associate",
            ScriptedReply {
                error: Some(8),
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(
        failure_of_lookup(outcome),
        format!(
            "keepassxc association was rejected; delete {} to re-associate",
            record_path.display()
        )
    );
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn reports_a_denied_association() {
    let directory = create_directory();
    let record_path = record_path_of(&directory);
    let (fake, connector) = start_fake(
        scripted_for(
            "associate",
            ScriptedReply {
                error: Some(6),
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), ASSOCIATION_DENIED_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn reports_no_entry_when_the_lookup_matches_nothing() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "get-logins",
            ScriptedReply {
                error: Some(15),
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), NO_ENTRY_OR_DENIED_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn reports_denied_access_when_the_entry_list_comes_back_empty() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "get-logins",
            ScriptedReply {
                body: Some(json!({ "entries": [] })),
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), ACCESS_DENIED_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn rejects_a_malformed_association_record() {
    let directory = create_directory();
    let record_path = record_path_of(&directory);

    std::fs::create_dir_all(
        record_path
            .parent()
            .expect("the record path has a directory"),
    )
    .expect("the record directory is created");
    std::fs::write(&record_path, json!({ "id": 1 }).to_string()).expect("the record is written");

    let (fake, connector) = start_fake(associated(), None);
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(
        failure_of_lookup(outcome),
        format!(
            "keepassxc association record at {} is malformed",
            record_path.display()
        )
    );
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn rejects_a_reply_whose_outer_nonce_was_not_incremented() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "get-databasehash",
            ScriptedReply {
                wrong_nonce: true,
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), NONCE_MISMATCH_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn rejects_a_reply_sealed_under_a_different_key() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "get-databasehash",
            ScriptedReply {
                wrong_key: true,
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), DECRYPTION_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn fails_closed_when_an_incomplete_reply_exceeds_the_buffer_cap() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "test-associate",
            ScriptedReply {
                flood_bytes: Some(MAXIMUM_PENDING_BYTES + 1),
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(
            &record_path,
            Duration::from_secs(5),
            DEFAULT_UNLOCK_INTERVAL,
        ),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), MALFORMED_REPLY_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn rejects_a_reply_that_never_parses_as_malformed() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "test-associate",
            ScriptedReply {
                raw_text: Some("not-json".to_string()),
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(&record_path, TEST_DEADLINE, DEFAULT_UNLOCK_INTERVAL),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), MALFORMED_REPLY_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn times_out_when_the_server_never_replies() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let (fake, connector) = start_fake(
        scripted_for(
            "test-associate",
            ScriptedReply {
                silent: true,
                ..ScriptedReply::default()
            },
        ),
        None,
    );
    let outcome = lookup_once(
        connector,
        options_of(
            &record_path,
            Duration::from_millis(100),
            DEFAULT_UNLOCK_INTERVAL,
        ),
        "keepassxc://synthetic/password",
    );

    assert_eq!(failure_of_lookup(outcome), TIMED_OUT_CLASS);
    assert_eq!(wait_for_close(&fake), 1);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn reports_an_unavailable_socket_when_nothing_is_listening() {
    let directory = create_directory();
    let record_path = write_stored_record(&directory, "credact", &stored_id_key());
    let socket_path = if cfg!(windows) {
        PathBuf::from(format!(r"\\.\pipe\credact-absent-{}", std::process::id()))
    } else {
        directory.join(format!("absent-{}.sock", std::process::id()))
    };
    let mut session = LookupSession::new(ClientOptions {
        socket_path: socket_path.clone(),
        record_path: Some(record_path),
        deadline: TEST_DEADLINE,
        unlock_interval: DEFAULT_UNLOCK_INTERVAL,
    });

    assert_eq!(
        session.lookup("keepassxc://synthetic/password"),
        Err(KeePassXcError {
            failure_class: format!("keepassxc socket unavailable at {}", socket_path.display()),
            error_code: None,
        })
    );

    let _ = std::fs::remove_dir_all(&directory);
}
