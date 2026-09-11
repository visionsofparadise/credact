use base64::Engine;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

const ENCODE_URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

const LOWER_NIBBLES: &[u8; 16] = b"0123456789abcdef";
const UPPER_NIBBLES: &[u8; 16] = b"0123456789ABCDEF";

fn hex_encode(bytes: &[u8], nibbles: &[u8; 16]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        output.push(nibbles[(byte >> 4) as usize] as char);
        output.push(nibbles[(byte & 0x0f) as usize] as char);
    }

    output
}

pub fn create_secret_representations(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let json = serde_json::to_string(value).expect("a string always serializes to JSON");
    let json_body = json[1..json.len() - 1].to_string();
    let percent_encoded =
        percent_encoding::utf8_percent_encode(value, ENCODE_URI_COMPONENT).to_string();
    let form_encoded: String = url::form_urlencoded::byte_serialize(bytes).collect();
    let standard = base64::engine::general_purpose::STANDARD.encode(bytes);
    let url_safe = base64::engine::general_purpose::URL_SAFE.encode(bytes);
    let url_safe_no_pad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let hex_lower = hex_encode(bytes, LOWER_NIBBLES);
    let hex_upper = hex_encode(bytes, UPPER_NIBBLES);

    let candidates = [
        value.to_string(),
        json_body,
        percent_encoded,
        form_encoded,
        standard,
        url_safe,
        url_safe_no_pad,
        hex_lower,
        hex_upper,
    ];

    let mut seen = std::collections::HashSet::new();
    let mut representations = Vec::new();

    for candidate in candidates {
        if candidate.is_empty() {
            continue;
        }

        if seen.insert(candidate.clone()) {
            representations.push(candidate);
        }
    }

    representations
}

#[cfg(test)]
#[path = "create_secret_representations.test.rs"]
mod tests;
