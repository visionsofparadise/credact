use super::*;
use crate::parse_arguments::{EnvironmentSource, SecretSource};
use zeroize::Zeroizing;

struct Outcome {
    result: Result<i32, CredactError>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(invocation: &Invocation, secrets: &[ResolvedSecret]) -> Outcome {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = run_command(RunOptions {
        invocation,
        secrets,
        stdout: &mut stdout,
        stderr: &mut stderr,
    });

    Outcome {
        result,
        stdout,
        stderr,
    }
}

fn node_invocation(script: &str, scan_output: bool) -> Invocation {
    Invocation {
        command: OsString::from("node"),
        command_arguments: vec![OsString::from("-e"), OsString::from(script)],
        scan_output,
        sources: Vec::new(),
    }
}

fn flood_script(mebibytes: usize) -> String {
    format!(
        "const fs = require('node:fs');
const chunk = 64 * 1024;
const total = {mebibytes} * 1024 * 1024;
const writeAll = (descriptor, buffer) => {{
  let offset = 0;
  while (offset < buffer.length) {{
    try {{
      offset += fs.writeSync(descriptor, buffer, offset);
    }} catch (error) {{
      if (error.code !== 'EAGAIN') throw error;
    }}
  }}
}};
const stdoutChunk = Buffer.alloc(chunk, 'o');
const stderrChunk = Buffer.alloc(chunk, 'e');
for (let written = 0; written < total; written += chunk) {{
  writeAll(1, stdoutChunk);
  writeAll(2, stderrChunk);
}}"
    )
}

#[cfg(windows)]
#[test]
fn resolves_a_cmd_shim_and_passes_metacharacter_arguments_exactly() {
    use std::time::{SystemTime, UNIX_EPOCH};

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "credact-run-command-{}-{unique}",
        std::process::id()
    ));

    std::fs::create_dir_all(&directory).expect("the directory is created");
    std::fs::write(
        directory.join("print-arguments.cjs"),
        "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n",
    )
    .expect("the script is written");
    std::fs::write(
        directory.join("print-arguments.cmd"),
        "@node \"%~dp0print-arguments.cjs\" %*\r\n",
    )
    .expect("the shim is written");

    let arguments = [
        "has space",
        "quote\"inside",
        "100%",
        "%PATH%",
        "a&b",
        "a|b",
        "a^b",
        "trailing\\",
    ];
    let invocation = Invocation {
        command: directory.join("print-arguments").into_os_string(),
        command_arguments: arguments.iter().map(OsString::from).collect(),
        scan_output: true,
        sources: Vec::new(),
    };
    let outcome = run(&invocation, &[]);

    let _ = std::fs::remove_dir_all(&directory);

    assert_eq!(outcome.result, Ok(0));

    let received: Vec<String> =
        serde_json::from_slice(&outcome.stdout).expect("the shim prints its arguments as JSON");

    assert_eq!(received, arguments);
}

#[test]
fn maps_a_missing_command_to_127() {
    let invocation = Invocation {
        command: OsString::from("credact-missing-command"),
        command_arguments: Vec::new(),
        scan_output: true,
        sources: Vec::new(),
    };

    assert_eq!(
        run(&invocation, &[]).result,
        Err(CredactError::new(
            CredactErrorKind::Spawn,
            127,
            "credact: command was not found"
        ))
    );
}

#[test]
fn captures_ten_mebibytes_on_each_stream_without_deadlock() {
    let outcome = run(&node_invocation(&flood_script(10), true), &[]);

    assert_eq!(outcome.result, Ok(0));
    assert_eq!(outcome.stdout.len(), 10 * 1024 * 1024);
    assert_eq!(outcome.stderr.len(), 10 * 1024 * 1024);
    assert!(outcome.stdout.iter().all(|byte| *byte == b'o'));
    assert!(outcome.stderr.iter().all(|byte| *byte == b'e'));
}

#[test]
fn fails_with_the_output_limit_when_both_streams_exceed_the_cap() {
    let outcome = run(&node_invocation(&flood_script(40), true), &[]);

    assert_eq!(
        outcome.result,
        Err(CredactError::new(
            CredactErrorKind::OutputLimit,
            1,
            "credact: command output exceeded 64 MiB"
        ))
    );
    assert!(outcome.stdout.is_empty());
    assert!(outcome.stderr.is_empty());
}

#[test]
fn passes_the_child_exit_code_through() {
    for scan_output in [true, false] {
        let outcome = run(&node_invocation("process.exit(7)", scan_output), &[]);

        assert_eq!(outcome.result, Ok(7));
    }
}

#[test]
fn redacts_secret_values_from_both_streams() {
    let secrets = [ResolvedSecret {
        source: SecretSource::Environment(EnvironmentSource {
            name: "CREDACT_REDACTION_SECRET".to_string(),
        }),
        value: Zeroizing::new("correct-horse-battery-staple".to_string()),
    }];
    let script = "const value = process.env.CREDACT_REDACTION_SECRET;
process.stdout.write('before ' + value + ' after');
process.stderr.write('encoded ' + Buffer.from(value).toString('base64'));";
    let outcome = run(&node_invocation(script, true), &secrets);

    assert_eq!(outcome.result, Ok(0));
    assert_eq!(outcome.stdout, b"before  after");
    assert_eq!(outcome.stderr, b"encoded ");
}
