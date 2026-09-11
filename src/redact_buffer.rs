use aho_corasick::{AhoCorasick, Anchored, Input, MatchKind, StartKind};
use std::borrow::Cow;
use zeroize::Zeroizing;

use crate::create_secret_representations::create_secret_representations;

pub fn redact_buffer<'a>(input: &'a [u8], values: &[&str]) -> Cow<'a, [u8]> {
    let mut patterns: Vec<Zeroizing<Vec<u8>>> = Vec::new();

    for value in values {
        for representation in create_secret_representations(value) {
            let bytes = representation.into_bytes();

            if !patterns
                .iter()
                .any(|pattern| pattern.as_slice() == bytes.as_slice())
            {
                patterns.push(Zeroizing::new(bytes));
            }
        }
    }

    if input.is_empty() || patterns.is_empty() {
        return Cow::Borrowed(input);
    }

    let automaton = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .start_kind(StartKind::Anchored)
        .build(patterns.iter().map(|pattern| pattern.as_slice()))
        .expect("the pattern set builds into an automaton");

    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(input.to_vec());
    let mut write = 0usize;
    let mut read = 0usize;
    let mut removed = false;

    while read < buffer.len() {
        let found = automaton.find(Input::new(&buffer[read..]).anchored(Anchored::Yes));

        match found {
            None => {
                buffer[write] = buffer[read];
                write += 1;
                read += 1;
            }
            Some(matched) => {
                let matched_length = matched.len();

                read += matched_length;
                removed = true;

                let replay_count = std::cmp::min(automaton.max_pattern_len() - 1, write);

                buffer.copy_within(write - replay_count..write, read - replay_count);

                write -= replay_count;
                read -= replay_count;
            }
        }
    }

    if removed {
        Cow::Owned(buffer[..write].to_vec())
    } else {
        Cow::Borrowed(input)
    }
}

#[cfg(test)]
#[path = "redact_buffer.test.rs"]
mod tests;
