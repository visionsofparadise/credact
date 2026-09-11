use super::*;
use serde_json::json;

use crate::parse_arguments::{EnvironmentSource, KeePassSource};

type Script = Box<dyn FnMut(&str) -> Result<Vec<Value>, KeePassXcError>>;

struct FakeLookup {
    script: Script,
    references: Vec<String>,
}

impl FakeLookup {
    fn new(script: impl FnMut(&str) -> Result<Vec<Value>, KeePassXcError> + 'static) -> Self {
        Self {
            script: Box::new(script),
            references: Vec::new(),
        }
    }

    fn of(entries: Value) -> Self {
        Self::new(move |_| Ok(entries.as_array().cloned().unwrap_or_default()))
    }
}

impl EntryLookup for FakeLookup {
    fn lookup(&mut self, reference: &str) -> Result<Vec<Value>, KeePassXcError> {
        self.references.push(reference.to_string());

        (self.script)(reference)
    }
}

fn unreachable_lookup() -> FakeLookup {
    FakeLookup::new(|_| panic!("the lookup must not be called"))
}

fn environment_source(name: &str) -> SecretSource {
    SecretSource::Environment(EnvironmentSource {
        name: name.to_string(),
    })
}

fn keepass_source(name: &str, reference: &str) -> SecretSource {
    SecretSource::KeePass(KeePassSource {
        name: name.to_string(),
        reference: reference.to_string(),
    })
}

fn response(entry: Value) -> Value {
    let mut reply = json!({
        "login": "synthetic-login",
        "password": "synthetic-password",
        "stringFields": [],
    });

    if let Some(entry) = entry.as_object() {
        for (name, value) in entry {
            reply[name] = value.clone();
        }
    }

    json!([reply])
}

fn environment_of(variables: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    variables
        .iter()
        .map(|(name, value)| (OsString::from(*name), OsString::from(*value)))
        .collect()
}

fn described(secrets: &[ResolvedSecret]) -> Vec<(String, Option<String>, String)> {
    secrets
        .iter()
        .map(|secret| match &secret.source {
            SecretSource::Environment(source) => {
                (source.name.clone(), None, secret.value.to_string())
            }
            SecretSource::KeePass(source) => (
                source.name.clone(),
                Some(source.reference.clone()),
                secret.value.to_string(),
            ),
        })
        .collect()
}

fn secrets_of(outcome: &ResolutionOutcome) -> &[ResolvedSecret] {
    match outcome {
        ResolutionOutcome::Success(secrets) => secrets,
        ResolutionOutcome::Failure { secrets, .. } => secrets,
    }
}

fn error_of(outcome: &ResolutionOutcome) -> &CredactError {
    match outcome {
        ResolutionOutcome::Failure { error, .. } => error,
        ResolutionOutcome::Success(_) => panic!("the outcome reports a failure"),
    }
}

fn assert_resolution_failure(outcome: &ResolutionOutcome, failure_class: &str) {
    let error = error_of(outcome);

    assert_eq!(error.kind, CredactErrorKind::Resolution);
    assert_eq!(error.exit_code, 1);
    assert!(
        error.message.contains(failure_class),
        "{} names {failure_class}",
        error.message
    );
}

#[test]
fn selects_username_password_and_a_unique_protected_custom_field() {
    let mut lookup = FakeLookup::of(response(
        json!({ "stringFields": [{ "KPH: api key": "synthetic-api-value" }] }),
    ));
    let outcome = resolve_secrets(
        &[
            keepass_source("LOGIN", "keepassxc://service/username"),
            keepass_source("PASSWORD", "keepassxc://service/password"),
            keepass_source("API_KEY", "keepassxc://service/api%20key"),
        ],
        &mut lookup,
        &[],
    );

    assert!(matches!(outcome, ResolutionOutcome::Success(_)));
    assert_eq!(
        described(secrets_of(&outcome)),
        [
            (
                "LOGIN".to_string(),
                Some("keepassxc://service/username".to_string()),
                "synthetic-login".to_string()
            ),
            (
                "PASSWORD".to_string(),
                Some("keepassxc://service/password".to_string()),
                "synthetic-password".to_string()
            ),
            (
                "API_KEY".to_string(),
                Some("keepassxc://service/api%20key".to_string()),
                "synthetic-api-value".to_string()
            ),
        ]
    );
}

#[test]
fn deduplicates_identical_references_while_preserving_sources() {
    let reference = "keepassxc://service/password";
    let mut lookup = FakeLookup::of(response(json!({})));
    let outcome = resolve_secrets(
        &[
            keepass_source("FIRST", reference),
            keepass_source("SECOND", reference),
        ],
        &mut lookup,
        &[],
    );

    assert_eq!(lookup.references, [reference]);
    assert!(matches!(outcome, ResolutionOutcome::Success(_)));
    assert_eq!(
        described(secrets_of(&outcome)),
        [
            (
                "FIRST".to_string(),
                Some(reference.to_string()),
                "synthetic-password".to_string()
            ),
            (
                "SECOND".to_string(),
                Some(reference.to_string()),
                "synthetic-password".to_string()
            ),
        ]
    );
}

#[test]
fn attempts_every_distinct_reference_and_retains_successes_in_a_failure_outcome() {
    let mut lookup = FakeLookup::new(|reference| {
        if reference.contains("failure") {
            return Err(KeePassXcError {
                failure_class: "keepassxc lookup failed".to_string(),
                error_code: None,
            });
        }

        Ok(response(json!({ "password": "synthetic-success-value" }))
            .as_array()
            .cloned()
            .unwrap_or_default())
    });
    let outcome = resolve_secrets(
        &[
            keepass_source("BROKEN", "keepassxc://failure/password"),
            keepass_source("WORKING", "keepassxc://success/password"),
        ],
        &mut lookup,
        &[],
    );

    assert_eq!(
        lookup.references,
        [
            "keepassxc://failure/password",
            "keepassxc://success/password"
        ]
    );
    assert_eq!(
        described(secrets_of(&outcome)),
        [(
            "WORKING".to_string(),
            Some("keepassxc://success/password".to_string()),
            "synthetic-success-value".to_string()
        )]
    );
    assert_resolution_failure(&outcome, "keepassxc lookup failed");

    let message = &error_of(&outcome).message;

    assert!(message.contains("BROKEN"), "{message} names the source");
    assert!(!message.contains("synthetic-success-value"));
}

#[test]
fn resolves_environment_sources_without_calling_the_lookup() {
    let mut lookup = unreachable_lookup();
    let outcome = resolve_secrets(
        &[environment_source("API_TOKEN")],
        &mut lookup,
        &environment_of(&[("api_token", "synthetic-environment-value")]),
    );

    assert!(matches!(outcome, ResolutionOutcome::Success(_)));
    assert_eq!(
        described(secrets_of(&outcome)),
        [(
            "API_TOKEN".to_string(),
            None,
            "synthetic-environment-value".to_string()
        )]
    );
    assert!(lookup.references.is_empty());
}

#[test]
fn resolves_mixed_sources_and_retains_both_source_kinds() {
    let mut lookup = FakeLookup::of(response(json!({})));
    let outcome = resolve_secrets(
        &[
            environment_source("REMOTE_TOKEN"),
            keepass_source("LOCAL_TOKEN", "keepassxc://service/password"),
        ],
        &mut lookup,
        &environment_of(&[("REMOTE_TOKEN", "synthetic-remote-value")]),
    );

    assert!(matches!(outcome, ResolutionOutcome::Success(_)));
    assert_eq!(
        described(secrets_of(&outcome)),
        [
            (
                "REMOTE_TOKEN".to_string(),
                None,
                "synthetic-remote-value".to_string()
            ),
            (
                "LOCAL_TOKEN".to_string(),
                Some("keepassxc://service/password".to_string()),
                "synthetic-password".to_string()
            ),
        ]
    );
    assert_eq!(lookup.references, ["keepassxc://service/password"]);
}

#[test]
fn reports_the_clients_failure_class_at_the_provider_error_boundary() {
    let mut lookup = FakeLookup::new(|_| {
        Err(KeePassXcError {
            failure_class: "keepassxc socket unavailable at test".to_string(),
            error_code: None,
        })
    });
    let outcome = resolve_secrets(
        &[keepass_source("TOKEN", "keepassxc://absent-entry/password")],
        &mut lookup,
        &[],
    );

    assert!(secrets_of(&outcome).is_empty());
    assert_resolution_failure(&outcome, "keepassxc socket unavailable at test");
}

#[test]
fn fails_closed_when_an_environment_value_is_absent_empty_or_ambiguous() {
    let cases = [
        (Vec::new(), ABSENT_ENVIRONMENT_CLASS),
        (
            environment_of(&[("API_TOKEN", "")]),
            EMPTY_ENVIRONMENT_CLASS,
        ),
        (
            environment_of(&[("API_TOKEN", "one"), ("api_token", "two")]),
            AMBIGUOUS_ENVIRONMENT_CLASS,
        ),
    ];

    for (environment, failure_class) in cases {
        let mut lookup = unreachable_lookup();
        let outcome = resolve_secrets(
            &[environment_source("API_TOKEN")],
            &mut lookup,
            &environment,
        );

        assert!(secrets_of(&outcome).is_empty());
        assert_resolution_failure(&outcome, failure_class);
    }
}

#[test]
fn fails_closed_on_a_non_utf8_environment_value() {
    #[cfg(unix)]
    let value = {
        use std::os::unix::ffi::OsStringExt;

        OsString::from_vec(vec![0x73, 0xff, 0x74])
    };
    #[cfg(windows)]
    let value = {
        use std::os::windows::ffi::OsStringExt;

        OsString::from_wide(&[0x0073, 0xd800, 0x0074])
    };
    let mut lookup = unreachable_lookup();
    let outcome = resolve_secrets(
        &[environment_source("API_TOKEN")],
        &mut lookup,
        &[(OsString::from("API_TOKEN"), value)],
    );

    assert!(secrets_of(&outcome).is_empty());
    assert_resolution_failure(&outcome, NON_UTF8_ENVIRONMENT_CLASS);
}

#[test]
fn fails_closed_for_a_reply_with_no_single_usable_entry() {
    let replies = [
        json!([]),
        json!([{ "stringFields": [] }, { "stringFields": [] }]),
        json!([{ "login": "synthetic-login", "password": "synthetic-password" }]),
    ];

    for reply in replies {
        let mut lookup = FakeLookup::of(reply);
        let outcome = resolve_secrets(
            &[keepass_source("TOKEN", "keepassxc://service/password")],
            &mut lookup,
            &[],
        );

        assert!(secrets_of(&outcome).is_empty());
        assert_resolution_failure(&outcome, NO_SINGLE_ENTRY_CLASS);
    }
}

#[test]
fn fails_closed_for_an_unusable_field() {
    let cases = [
        (
            "keepassxc://service/missing",
            response(json!({})),
            ABSENT_OR_AMBIGUOUS_FIELD_CLASS,
        ),
        (
            "keepassxc://service/duplicate",
            response(
                json!({ "stringFields": [{ "KPH: duplicate": "one" }, { "KPH: duplicate": "two" }] }),
            ),
            ABSENT_OR_AMBIGUOUS_FIELD_CLASS,
        ),
        (
            "keepassxc://service/duplicate",
            response(
                json!({ "stringFields": [{ "KPH: duplicate": "one" }, { "KPH: duplicate": 2 }] }),
            ),
            ABSENT_OR_AMBIGUOUS_FIELD_CLASS,
        ),
        (
            "keepassxc://service/custom",
            response(json!({ "stringFields": [{ "KPH: custom": false }] })),
            ABSENT_OR_AMBIGUOUS_FIELD_CLASS,
        ),
        (
            "keepassxc://service/password",
            response(json!({ "password": "" })),
            EMPTY_VALUE_CLASS,
        ),
        (
            "keepassxc://service/password",
            response(json!({ "password": "keepassxc://service/password" })),
            UNRESOLVED_REFERENCE_CLASS,
        ),
        (
            "keepassxc://service/bad%zzescape",
            response(json!({})),
            INVALID_FIELD_CLASS,
        ),
    ];

    for (reference, entries, failure_class) in cases {
        let mut lookup = FakeLookup::of(entries);
        let outcome = resolve_secrets(&[keepass_source("TOKEN", reference)], &mut lookup, &[]);

        assert!(secrets_of(&outcome).is_empty());
        assert_resolution_failure(&outcome, failure_class);
    }
}
