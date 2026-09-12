use std::ffi::OsString;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentSource {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeePassSource {
    pub name: String,
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    Environment(EnvironmentSource),
    KeePass(KeePassSource),
}

impl SecretSource {
    pub fn name(&self) -> &str {
        match self {
            SecretSource::Environment(source) => &source.name,
            SecretSource::KeePass(source) => &source.name,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Invocation {
    pub command: OsString,
    pub command_arguments: Vec<OsString>,
    pub scan_output: bool,
    pub sources: Vec<SecretSource>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseResult {
    Help,
    Run(Invocation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredactError {
    pub exit_code: i32,
    pub message: String,
}

impl CredactError {
    pub fn new(exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CredactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CredactError {}

fn fail_usage<T>(message: &str) -> Result<T, CredactError> {
    Err(CredactError::new(2, message))
}

fn is_valid_environment_name(name: &str) -> bool {
    let mut characters = name.chars();

    match characters.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }

    characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn host_and_port(reference: &str) -> String {
    let after_prefix = &reference["keepassxc://".len()..];
    let stripped: String = after_prefix
        .chars()
        .filter(|character| !matches!(character, '\t' | '\n' | '\r'))
        .collect();
    let cut = stripped.find(['/', '?', '#']).unwrap_or(stripped.len());
    let head = &stripped[..cut];

    match head.rfind('@') {
        Some(index) => head[index + 1..].to_string(),
        None => head.to_string(),
    }
}

fn validate_reference(reference: &str) -> Result<(), CredactError> {
    if !reference.starts_with("keepassxc://") {
        return fail_usage("assignment references must use keepassxc://");
    }

    let parsed = match url::Url::parse(reference) {
        Ok(parsed) => parsed,
        Err(_) => return fail_usage("assignment reference is invalid"),
    };

    let host_is_present = matches!(parsed.host_str(), Some(host) if !host.is_empty());

    if !host_is_present
        || reference.contains('?')
        || reference.contains('#')
        || host_and_port(reference).contains('\\')
    {
        return fail_usage("assignment reference is invalid");
    }

    let final_slash = reference.rfind('/');

    match final_slash {
        Some(index) if index >= "keepassxc://".len() && index != reference.len() - 1 => Ok(()),
        _ => fail_usage("assignment reference must name a field"),
    }
}

fn parse_source(token: &str) -> Result<SecretSource, CredactError> {
    let equals_index = token.find('=');

    let Some(equals_index) = equals_index else {
        if !is_valid_environment_name(token) {
            return fail_usage("source has an invalid environment name");
        }

        return Ok(SecretSource::Environment(EnvironmentSource {
            name: token.to_string(),
        }));
    };

    if equals_index == 0 {
        return fail_usage("source has an invalid environment name");
    }

    let name = &token[..equals_index];
    let reference = &token[equals_index + 1..];

    if !is_valid_environment_name(name) {
        return fail_usage("source has an invalid environment name");
    }

    validate_reference(reference)?;

    Ok(SecretSource::KeePass(KeePassSource {
        name: name.to_string(),
        reference: reference.to_string(),
    }))
}

pub fn parse_arguments(argument_values: Vec<OsString>) -> Result<ParseResult, CredactError> {
    if argument_values.len() == 1 && argument_values[0] == "--help" {
        return Ok(ParseResult::Help);
    }

    let delimiter_index = argument_values.iter().position(|argument| argument == "--");

    let Some(delimiter_index) = delimiter_index else {
        return fail_usage("missing mandatory -- command delimiter");
    };

    let runner_arguments = &argument_values[..delimiter_index];
    let mut command_arguments: Vec<OsString> = argument_values[delimiter_index + 1..].to_vec();

    if command_arguments.is_empty() || command_arguments[0].is_empty() {
        return fail_usage("missing command after --");
    }

    let command = command_arguments.remove(0);

    let mut scan_output = true;
    let mut saw_source = false;
    let mut sources: Vec<SecretSource> = Vec::new();
    let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();

    for token in runner_arguments {
        if token == "--no-output-scan" {
            if saw_source || !scan_output {
                return fail_usage("--no-output-scan must appear once before sources");
            }

            scan_output = false;

            continue;
        }

        saw_source = true;

        let token = match token.to_str() {
            Some(token) => token,
            None => return fail_usage("source has an invalid environment name"),
        };

        let source = parse_source(token)?;
        let folded_name = source.name().to_ascii_lowercase();

        if !names.insert(folded_name) {
            return fail_usage("source environment names must be unique");
        }

        sources.push(source);
    }

    if sources.is_empty() {
        return fail_usage("at least one secret source is required");
    }

    Ok(ParseResult::Run(Invocation {
        command,
        command_arguments,
        scan_output,
        sources,
    }))
}

#[cfg(test)]
#[path = "parse_arguments.test.rs"]
mod tests;
