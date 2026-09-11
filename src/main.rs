use std::ffi::OsString;
use std::io::Write;

mod create_secret_representations;
mod keepassxc_box;
mod keepassxc_client;
mod parse_arguments;
mod redact_buffer;
mod resolve_secrets;
mod run_command;
mod terminate_child;

use keepassxc_client::{ClientOptions, LookupSession};
use parse_arguments::{parse_arguments, ParseResult};
use redact_buffer::redact_buffer;
use resolve_secrets::{resolve_secrets, ResolutionOutcome};
use run_command::{run_command, RunOptions};

const USAGE: &str = "Usage: credact [--no-output-scan] SOURCE [...] -- COMMAND [ARG ...]";
const HELP: &str = "Usage: credact [--no-output-scan] SOURCE [...] -- COMMAND [ARG ...]\n\nSOURCE is NAME (read from the environment) or NAME=keepassxc://entry/field.\nResolved values and documented common representations are removed from complete stdout and stderr before release.\n\n  --no-output-scan  Inherit the terminal directly for trusted interactive commands.\n  --help            Show this help when supplied as the only argument.\n";

fn write_stdout(text: &str) {
    let mut stdout = std::io::stdout();

    let _ = stdout.write_all(text.as_bytes());
}

fn write_diagnostic(message: &str, secret_values: &[&str], include_usage: bool) {
    let mut body = format!("{message}\n");

    if include_usage {
        body.push_str(USAGE);
        body.push('\n');
    }

    let redacted = redact_buffer(body.as_bytes(), secret_values);
    let mut stderr = std::io::stderr();

    let _ = stderr.write_all(&redacted);
}

fn run() -> i32 {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();

    let invocation = match parse_arguments(arguments) {
        Ok(ParseResult::Help) => {
            write_stdout(HELP);

            return 0;
        }
        Ok(ParseResult::Run(invocation)) => invocation,
        Err(error) => {
            write_diagnostic(&error.message, &[], true);

            return error.exit_code;
        }
    };

    let environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let outcome = {
        let mut lookup = LookupSession::new(ClientOptions::from_environment());

        resolve_secrets(&invocation.sources, &mut lookup, &environment)
    };

    let secrets = match outcome {
        ResolutionOutcome::Success(secrets) => secrets,
        ResolutionOutcome::Failure { secrets, error } => {
            let values: Vec<&str> = secrets.iter().map(|secret| secret.value.as_str()).collect();

            write_diagnostic(&error.message, &values, false);

            return error.exit_code;
        }
    };

    let result = {
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let mut stdout_lock = stdout.lock();
        let mut stderr_lock = stderr.lock();

        run_command(RunOptions {
            invocation: &invocation,
            secrets: &secrets,
            stdout: &mut stdout_lock,
            stderr: &mut stderr_lock,
        })
    };

    match result {
        Ok(exit_code) => exit_code,
        Err(error) => {
            let values: Vec<&str> = secrets.iter().map(|secret| secret.value.as_str()).collect();

            write_diagnostic(&error.message, &values, false);

            error.exit_code
        }
    }
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));

    let exit_code = match std::panic::catch_unwind(run) {
        Ok(exit_code) => exit_code,
        Err(_) => {
            let mut stderr = std::io::stderr();

            let _ = stderr.write_all(b"credact: unexpected failure\n");

            1
        }
    };

    std::process::exit(exit_code);
}
