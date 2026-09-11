use super::*;

fn expect_redaction(input: &[u8], values: &[&str], expected: &[u8]) {
    let output = redact_buffer(input, values);

    assert_eq!(output.as_ref(), expected);

    for value in values {
        let pattern = value.as_bytes();

        if !pattern.is_empty() {
            assert!(!contains_subsequence(&output, pattern));
        }
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }

    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn redact_naively(input: &[u8], values: &[&str]) -> Vec<u8> {
    let mut seen = std::collections::HashSet::new();
    let mut patterns: Vec<Vec<u8>> = Vec::new();

    for value in values {
        let bytes = value.as_bytes().to_vec();

        if seen.insert(bytes.clone()) {
            patterns.push(bytes);
        }
    }

    patterns.retain(|pattern| !pattern.is_empty());
    patterns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));

    let mut output = input.to_vec();

    loop {
        let mut removed = false;

        'outer: for index in 0..output.len() {
            for pattern in &patterns {
                let end = index + pattern.len();

                if end <= output.len() && output[index..end] == pattern[..] {
                    output = [&output[..index], &output[end..]].concat();
                    removed = true;

                    break 'outer;
                }
            }
        }

        if !removed {
            return output;
        }
    }
}

#[test]
fn removes_literal_matches() {
    let cases: [(&str, &str); 5] = [
        ("secret-tail", "-tail"),
        ("head-secret-tail", "head--tail"),
        ("head-secret", "head-"),
        ("secretsecret", ""),
        ("secret-secret", "-"),
    ];

    for (input, expected) in cases {
        expect_redaction(input.as_bytes(), &["secret"], expected.as_bytes());
    }
}

#[test]
fn uses_the_longest_pattern_at_a_shared_start() {
    expect_redaction(b"abcab", &["ab", "abc", "ab"], b"");
}

#[test]
fn rescans_after_deletion_synthesizes_another_active_value() {
    expect_redaction(b"abXc", &["abc", "X"], b"");
}

#[test]
fn matches_utf8_byte_sequences() {
    expect_redaction(
        "before-\u{1F510}\u{79d8}\u{5bc6}-after".as_bytes(),
        &["\u{1F510}\u{79d8}\u{5bc6}"],
        b"before--after",
    );
}

#[test]
fn removes_common_escaped_and_encoded_representations() {
    let representations = [
        "z \"b", "z \\\"b", "z%20%22b", "z+%22b", "eiAiYg==", "eiAiYg", "7a202262", "7A202262",
    ];
    let input = representations.join("|");
    let expected = "|".repeat(representations.len() - 1);

    expect_redaction(input.as_bytes(), &["z \"b"], expected.as_bytes());
}

#[test]
fn preserves_binary_and_nul_surroundings() {
    let mut input = vec![0u8, 255, 1];

    input.extend_from_slice(b"secret");
    input.extend_from_slice(&[2, 0, 254]);

    expect_redaction(&input, &["secret"], &[0, 255, 1, 2, 0, 254]);
}

#[test]
fn returns_the_original_clean_buffer() {
    let input = b"clean output with secre prefix";

    match redact_buffer(input, &["secret"]) {
        Cow::Borrowed(borrowed) => assert_eq!(borrowed.as_ptr(), input.as_ptr()),
        Cow::Owned(_) => panic!("expected the original buffer to be borrowed"),
    }
}

#[test]
fn leaves_incomplete_prefixes_and_an_empty_input_unchanged() {
    expect_redaction(b"secre", &["secret"], b"secre");
    assert_eq!(redact_buffer(&[], &["secret"]).as_ref(), b"");
}

#[test]
fn ignores_empty_values_defensively() {
    let input = b"unchanged";

    match redact_buffer(input, &["", ""]) {
        Cow::Borrowed(borrowed) => assert_eq!(borrowed.as_ptr(), input.as_ptr()),
        Cow::Owned(_) => panic!("expected the original buffer to be borrowed"),
    }
}

#[test]
fn handles_many_generations_of_synthesized_boundary_matches() {
    let started_at = std::time::Instant::now();
    let pairs = 4_000;
    let mut input = "a".repeat(pairs).into_bytes();

    input.push(b'X');
    input.extend(std::iter::repeat_n(b'b', pairs));

    assert_eq!(redact_buffer(&input, &["X", "ab"]).as_ref(), b"");
    assert!(started_at.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn matches_the_leftmost_longest_fixed_point_definition_exhaustively_on_small_inputs() {
    let alphabet = ['a', 'b', 'c'];
    let pattern_sets: [&[&str]; 4] = [
        &["a", "ab"],
        &["ab", "abc", "bc"],
        &["b", "ac", "abc"],
        &["aa", "aab", "ba"],
    ];
    let mut inputs = vec![String::new()];

    for length in 1..=7 {
        let previous: Vec<String> = inputs
            .iter()
            .filter(|input| input.len() == length - 1)
            .cloned()
            .collect();

        for input in previous {
            for byte in alphabet {
                inputs.push(format!("{input}{byte}"));
            }
        }
    }

    for input in &inputs {
        for patterns in pattern_sets {
            let bytes = input.as_bytes();

            assert_eq!(
                redact_buffer(bytes, patterns).as_ref(),
                redact_naively(bytes, patterns).as_slice(),
                "input={input:?} patterns={patterns:?}"
            );
        }
    }
}
