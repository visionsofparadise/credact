use super::*;
use serde_json::json;
use std::collections::HashMap;

fn resolve(variables: &[(&str, &str)], platform: Platform, container_exists: bool) -> PathBuf {
    let map: HashMap<String, String> = variables
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect();
    let variable_of = move |name: &str| map.get(name).cloned();
    let exists = move |path: &Path| container_exists && path.to_string_lossy().contains("app");

    resolve_socket_path(
        &SocketEnvironment {
            variable_of: &variable_of,
            temp_directory: PathBuf::from("/temporary"),
            exists: &exists,
        },
        platform,
    )
}

#[test]
fn derives_the_socket_path_per_platform() {
    assert_eq!(
        resolve(
            &[("KEEPASSXC_BROWSER_SOCKET_PATH", "//./pipe/custom")],
            Platform::Windows,
            false
        ),
        PathBuf::from("//./pipe/custom")
    );
    assert_eq!(
        resolve(
            &[
                ("KEEPASSXC_BROWSER_SOCKET_PATH", ""),
                ("USERNAME", "someone")
            ],
            Platform::Windows,
            false
        ),
        PathBuf::from(r"\\.\pipe\org.keepassxc.KeePassXC.BrowserServer_someone")
    );
    assert_eq!(
        resolve(&[], Platform::Windows, false),
        PathBuf::from(r"\\.\pipe\org.keepassxc.KeePassXC.BrowserServer_")
    );
    assert_eq!(
        resolve(&[], Platform::Other, false),
        Path::new("/temporary").join(SOCKET_NAME)
    );
    assert_eq!(
        resolve(&[("USER", "account")], Platform::Linux, false),
        Path::new("/temporary")
            .join("runtime-account")
            .join(SOCKET_NAME)
    );
    assert_eq!(
        resolve(&[], Platform::Linux, false),
        Path::new("/temporary").join("runtime-").join(SOCKET_NAME)
    );
}

#[test]
fn prefers_the_container_socket_on_linux_when_it_exists() {
    assert_eq!(
        resolve(
            &[("XDG_RUNTIME_DIR", "/run/user/1000")],
            Platform::Linux,
            false
        ),
        Path::new("/run/user/1000").join(SOCKET_NAME)
    );
    assert_eq!(
        resolve(
            &[("XDG_RUNTIME_DIR", "/run/user/1000")],
            Platform::Linux,
            true
        ),
        Path::new("/run/user/1000")
            .join("app")
            .join("org.keepassxc.KeePassXC")
            .join(SOCKET_NAME)
    );
}

#[test]
fn splits_complete_top_level_values_and_keeps_the_incomplete_tail() {
    let complete = br#"{"a":"}"}{"b":1}"#;
    let (values, consumed) = split_json_values(complete).expect("the buffer parses");

    assert_eq!(values, vec![json!({ "a": "}" }), json!({ "b": 1 })]);
    assert_eq!(consumed, complete.len());

    let partial = br#"{"a":"#;
    let (values, consumed) = split_json_values(partial).expect("the tail is incomplete");

    assert!(values.is_empty());
    assert_eq!(consumed, 0);

    let mixed = br#"{"a":1}{"b":"#;
    let (values, consumed) = split_json_values(mixed).expect("the tail is incomplete");

    assert_eq!(values, vec![json!({ "a": 1 })]);
    assert_eq!(&mixed[consumed..], br#"{"b":"#);

    assert!(split_json_values(b"not-json").is_err());
}
