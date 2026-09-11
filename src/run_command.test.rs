use super::*;
use crate::parse_arguments::{EnvironmentSource, SecretSource};
use zeroize::Zeroizing;

fn secret(name: &str, value: &str) -> ResolvedSecret {
    ResolvedSecret {
        source: SecretSource::Environment(EnvironmentSource {
            name: name.to_string(),
        }),
        value: Zeroizing::new(value.to_string()),
    }
}

fn entry(name: &str, value: &str) -> (OsString, OsString) {
    (OsString::from(name), OsString::from(value))
}

#[test]
fn replaces_inherited_case_variants_of_a_secret_name() {
    let environment = child_environment_of(
        vec![
            entry("token", "lower"),
            entry("PATH", "inherited"),
            entry("Token", "mixed"),
        ],
        &[secret("TOKEN", "declared")],
    );

    assert_eq!(
        environment,
        vec![entry("PATH", "inherited"), entry("TOKEN", "declared")]
    );
}

#[test]
fn maps_spawn_errors_to_exit_codes() {
    #[cfg(windows)]
    let not_executable = std::io::Error::from_raw_os_error(193);
    #[cfg(unix)]
    let not_executable = std::io::Error::from_raw_os_error(8);

    let cases = [
        (
            std::io::Error::from(ErrorKind::NotFound),
            127,
            "credact: command was not found",
        ),
        (
            std::io::Error::from(ErrorKind::PermissionDenied),
            126,
            "credact: command is not executable",
        ),
        (not_executable, 126, "credact: command is not executable"),
        (
            std::io::Error::from(ErrorKind::InvalidInput),
            1,
            "credact: command could not start",
        ),
    ];

    for (error, exit_code, message) in cases {
        assert_eq!(
            spawn_error_of(&error),
            CredactError::new(CredactErrorKind::Spawn, exit_code, message)
        );
    }
}

#[test]
fn maps_exit_statuses() {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;

        assert_eq!(exit_code_of(ExitStatus::from_raw(7 << 8)), 7);
        assert_eq!(exit_code_of(ExitStatus::from_raw(15)), 143);
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;

        assert_eq!(exit_code_of(ExitStatus::from_raw(7)), 7);
    }
}
