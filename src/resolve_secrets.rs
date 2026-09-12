use std::collections::HashMap;
use std::ffi::OsString;

use serde_json::Value;
use zeroize::Zeroizing;

use crate::keepassxc_client::{KeePassXcError, LookupSession};
use crate::parse_arguments::{CredactError, SecretSource};

const NO_SINGLE_ENTRY_CLASS: &str = "keepassxc reply had no single usable entry";
const INVALID_FIELD_CLASS: &str = "reference field was invalid";
const ABSENT_OR_AMBIGUOUS_FIELD_CLASS: &str = "requested field was absent or ambiguous";
const EMPTY_VALUE_CLASS: &str = "resolved value was empty";
const UNRESOLVED_REFERENCE_CLASS: &str = "keepassxc returned the unresolved reference";
const ABSENT_ENVIRONMENT_CLASS: &str = "environment value was absent";
const AMBIGUOUS_ENVIRONMENT_CLASS: &str = "environment name was ambiguous";
const NON_UTF8_ENVIRONMENT_CLASS: &str = "environment value was not valid UTF-8";
const EMPTY_ENVIRONMENT_CLASS: &str = "environment value was empty";

pub struct ResolvedSecret {
    pub source: SecretSource,
    pub value: Zeroizing<String>,
}

pub enum ResolutionOutcome {
    Success(Vec<ResolvedSecret>),
    Failure {
        secrets: Vec<ResolvedSecret>,
        error: CredactError,
    },
}

pub trait EntryLookup {
    fn lookup(&mut self, reference: &str) -> Result<Vec<Value>, KeePassXcError>;
}

impl EntryLookup for LookupSession {
    fn lookup(&mut self, reference: &str) -> Result<Vec<Value>, KeePassXcError> {
        LookupSession::lookup(self, reference)
    }
}

enum SourceResult {
    Success(Zeroizing<String>),
    Failure(String),
}

struct ParsedEntry<'a> {
    login: Option<&'a Value>,
    password: Option<&'a Value>,
    string_fields: &'a [Value],
}

fn parsed_entry_of(entries: &[Value]) -> Option<ParsedEntry<'_>> {
    let [entry] = entries else {
        return None;
    };
    let entry = entry.as_object()?;

    Some(ParsedEntry {
        login: entry.get("login"),
        password: entry.get("password"),
        string_fields: entry.get("stringFields")?.as_array()?,
    })
}

fn has_complete_escapes(segment: &str) -> bool {
    let bytes = segment.as_bytes();

    bytes.iter().enumerate().all(|(index, byte)| {
        *byte != b'%'
            || bytes
                .get(index + 1..index + 3)
                .is_some_and(|escape| escape.iter().all(u8::is_ascii_hexdigit))
    })
}

fn field_name_of(reference: &str) -> Option<String> {
    let parsed = url::Url::parse(reference).ok()?;
    let path = parsed.path().to_string();
    let segment = path.split('/').next_back()?;

    if segment.is_empty() || !has_complete_escapes(segment) {
        return None;
    }

    percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .ok()
        .map(|decoded| decoded.into_owned())
}

fn selected_value_of(entry: &ParsedEntry<'_>, field_name: &str) -> Option<Zeroizing<String>> {
    let string_of = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .map(|value| Zeroizing::new(value.to_string()))
    };

    if field_name == "username" {
        return string_of(entry.login);
    }

    if field_name == "password" {
        return string_of(entry.password);
    }

    let protected_name = format!("KPH: {field_name}");
    let mut matches = entry
        .string_fields
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|field| field.get(&protected_name));
    let first = matches.next()?;

    if matches.next().is_some() {
        return None;
    }

    string_of(Some(first))
}

fn resolved_reference_of(reference: &str, lookup: &mut dyn EntryLookup) -> SourceResult {
    let entries = match lookup.lookup(reference) {
        Ok(entries) => entries,
        Err(error) => return SourceResult::Failure(error.failure_class),
    };
    let Some(entry) = parsed_entry_of(&entries) else {
        return SourceResult::Failure(NO_SINGLE_ENTRY_CLASS.to_string());
    };
    let Some(field_name) = field_name_of(reference) else {
        return SourceResult::Failure(INVALID_FIELD_CLASS.to_string());
    };
    let Some(value) = selected_value_of(&entry, &field_name) else {
        return SourceResult::Failure(ABSENT_OR_AMBIGUOUS_FIELD_CLASS.to_string());
    };

    if value.is_empty() {
        return SourceResult::Failure(EMPTY_VALUE_CLASS.to_string());
    }

    if value.as_str() == reference {
        return SourceResult::Failure(UNRESOLVED_REFERENCE_CLASS.to_string());
    }

    SourceResult::Success(value)
}

fn resolved_environment_of(name: &str, environment: &[(OsString, OsString)]) -> SourceResult {
    let folded_name = name.to_ascii_lowercase();
    let mut matches = environment.iter().filter(|(variable, _)| {
        variable
            .to_str()
            .is_some_and(|variable| variable.to_ascii_lowercase() == folded_name)
    });
    let Some((_, value)) = matches.next() else {
        return SourceResult::Failure(ABSENT_ENVIRONMENT_CLASS.to_string());
    };

    if matches.next().is_some() {
        return SourceResult::Failure(AMBIGUOUS_ENVIRONMENT_CLASS.to_string());
    }

    let Some(value) = value.to_str() else {
        return SourceResult::Failure(NON_UTF8_ENVIRONMENT_CLASS.to_string());
    };

    if value.is_empty() {
        return SourceResult::Failure(EMPTY_ENVIRONMENT_CLASS.to_string());
    }

    SourceResult::Success(Zeroizing::new(value.to_string()))
}

pub fn resolve_secrets(
    sources: &[SecretSource],
    lookup: &mut dyn EntryLookup,
    environment: &[(OsString, OsString)],
) -> ResolutionOutcome {
    let mut environment_results: HashMap<String, SourceResult> = HashMap::new();
    let mut reference_results: HashMap<String, SourceResult> = HashMap::new();
    let mut secrets: Vec<ResolvedSecret> = Vec::new();
    let mut failure: Option<CredactError> = None;

    for source in sources {
        let result = match source {
            SecretSource::Environment(environment_source) => environment_results
                .entry(environment_source.name.to_ascii_lowercase())
                .or_insert_with(|| resolved_environment_of(&environment_source.name, environment)),
            SecretSource::KeePass(keepass_source) => reference_results
                .entry(keepass_source.reference.clone())
                .or_insert_with(|| resolved_reference_of(&keepass_source.reference, lookup)),
        };

        match result {
            SourceResult::Success(value) => secrets.push(ResolvedSecret {
                source: source.clone(),
                value: value.clone(),
            }),
            SourceResult::Failure(failure_class) => {
                failure.get_or_insert_with(|| {
                    CredactError::new(1, format!("credact: {}: {failure_class}", source.name()))
                });
            }
        }
    }

    match failure {
        None => ResolutionOutcome::Success(secrets),
        Some(error) => ResolutionOutcome::Failure { secrets, error },
    }
}

#[cfg(test)]
#[path = "resolve_secrets.test.rs"]
mod tests;
