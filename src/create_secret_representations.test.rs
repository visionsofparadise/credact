use super::*;

#[test]
fn creates_the_bounded_common_representation_set() {
    assert_eq!(
        create_secret_representations("z \"b"),
        vec![
            "z \"b", "z \\\"b", "z%20%22b", "z+%22b", "eiAiYg==", "eiAiYg", "7a202262", "7A202262"
        ]
    );
}

#[test]
fn creates_distinct_standard_and_url_safe_base64_forms() {
    let representations = create_secret_representations("\u{1F510}");

    assert!(representations.contains(&"8J+UkA==".to_string()));
    assert!(representations.contains(&"8J-UkA==".to_string()));
    assert!(representations.contains(&"8J-UkA".to_string()));
}

#[test]
fn ignores_an_empty_value() {
    assert_eq!(create_secret_representations(""), Vec::<String>::new());
}
