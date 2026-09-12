use super::*;

fn arguments(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

fn expect_usage_failure(values: &[&str]) {
    let error = parse_arguments(arguments(values)).expect_err("expected a usage failure");

    assert_eq!(error.exit_code, 2);
}

#[test]
fn returns_help_only_for_a_sole_help_token() {
    assert_eq!(
        parse_arguments(arguments(&["--help"])).unwrap(),
        ParseResult::Help
    );
    assert_eq!(
        parse_arguments(arguments(&["-h"])).unwrap(),
        ParseResult::Help
    );

    expect_usage_failure(&["--help", "--", "node"]);
    expect_usage_failure(&["-h", "--", "node"]);
}

#[test]
fn returns_version_only_for_a_sole_version_token() {
    assert_eq!(
        parse_arguments(arguments(&["--version"])).unwrap(),
        ParseResult::Version
    );
    assert_eq!(
        parse_arguments(arguments(&["-V"])).unwrap(),
        ParseResult::Version
    );

    expect_usage_failure(&["--version", "--", "node"]);
    expect_usage_failure(&["-V", "--", "node"]);
}

#[test]
fn parses_environment_keepassxc_and_passthrough_sources() {
    let result = parse_arguments(arguments(&[
        "TOKEN=keepassxc://service/password",
        "--",
        "node",
    ]))
    .unwrap();

    assert_eq!(
        result,
        ParseResult::Run(Invocation {
            command: OsString::from("node"),
            command_arguments: Vec::new(),
            scan_output: true,
            sources: vec![SecretSource::KeePass(KeePassSource {
                name: "TOKEN".to_string(),
                reference: "keepassxc://service/password".to_string(),
            })],
        })
    );

    let result = parse_arguments(arguments(&["--no-output-scan", "TOKEN", "--", "node"])).unwrap();

    match result {
        ParseResult::Run(invocation) => {
            assert!(!invocation.scan_output);
            assert_eq!(
                invocation.sources,
                vec![SecretSource::Environment(EnvironmentSource {
                    name: "TOKEN".to_string()
                })]
            );
        }
        ParseResult::Help | ParseResult::Version => panic!("expected a run result"),
    }
}

#[test]
fn preserves_mixed_sources_and_command_arguments() {
    let result = parse_arguments(arguments(&[
        "FIRST",
        "SECOND=keepassxc://two/custom-field",
        "--",
        "program with spaces",
        "--option=value",
        "argument with spaces",
        "--",
    ]))
    .unwrap();

    assert_eq!(
        result,
        ParseResult::Run(Invocation {
            command: OsString::from("program with spaces"),
            command_arguments: arguments(&["--option=value", "argument with spaces", "--"]),
            scan_output: true,
            sources: vec![
                SecretSource::Environment(EnvironmentSource {
                    name: "FIRST".to_string()
                }),
                SecretSource::KeePass(KeePassSource {
                    name: "SECOND".to_string(),
                    reference: "keepassxc://two/custom-field".to_string(),
                }),
            ],
        })
    );
}

#[test]
fn rejects_case_insensitive_duplicate_names() {
    expect_usage_failure(&["Token", "TOKEN=keepassxc://two/password", "--", "node"]);
}

#[test]
fn rejects_invalid_invocations() {
    let invalid_invocations: Vec<Vec<&str>> = vec![
        vec![],
        vec!["TOKEN=keepassxc://service/password", "node"],
        vec!["--", "node"],
        vec!["TOKEN=keepassxc://service/password", "--"],
        vec!["TOKEN=keepassxc://service/password", "--", ""],
        vec!["1TOKEN", "--", "node"],
        vec!["1TOKEN=keepassxc://service/password", "--", "node"],
        vec!["TOKEN=", "--", "node"],
        vec!["TOKEN=https://service/password", "--", "node"],
        vec!["TOKEN=keepassxc://service", "--", "node"],
        vec!["TOKEN=keepassxc://service/", "--", "node"],
        vec!["TOKEN=keepassxc://service/password?mode=test", "--", "node"],
        vec!["TOKEN=keepassxc://service/password?", "--", "node"],
        vec!["TOKEN=keepassxc://service/password#fragment", "--", "node"],
        vec!["TOKEN=keepassxc://service/password#", "--", "node"],
        vec!["TOKEN=keepassxc:///password", "--", "node"],
        vec![
            "TOKEN=keepassxc://service/password",
            "--no-output-scan",
            "--",
            "node",
        ],
        vec![
            "--no-output-scan",
            "--no-output-scan",
            "TOKEN=keepassxc://service/password",
            "--",
            "node",
        ],
    ];

    for invocation in invalid_invocations {
        expect_usage_failure(&invocation);
    }
}

#[test]
fn rejects_invalid_references() {
    let error =
        parse_arguments(arguments(&["TOKEN=https://service/password", "--", "node"])).unwrap_err();

    assert_eq!(error.message, "assignment references must use keepassxc://");

    let error =
        parse_arguments(arguments(&["TOKEN=keepassxc://service", "--", "node"])).unwrap_err();

    assert_eq!(error.message, "assignment reference must name a field");

    let error = parse_arguments(arguments(&[
        "TOKEN=keepassxc://service/password?mode=test",
        "--",
        "node",
    ]))
    .unwrap_err();

    assert_eq!(error.message, "assignment reference is invalid");

    let error =
        parse_arguments(arguments(&["TOKEN=keepassxc://a:\\/f", "--", "node"])).unwrap_err();

    assert_eq!(error.message, "assignment reference is invalid");
}
