use super::*;

const ALICE_SECRET: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
const BOB_SECRET: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
const VECTOR_NONCE: &str = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
const MESSAGE: &str = concat!(
    "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c6129",
    "6cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde",
    "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705"
);
const EXPECTED_BOX: &str = concat!(
    "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a",
    "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae",
    "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74",
    "e355a5"
);

fn bytes_of(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("the text is hex"))
        .collect()
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn array_of<const LENGTH: usize>(hex: &str) -> [u8; LENGTH] {
    bytes_of(hex)
        .try_into()
        .expect("the text is the right length")
}

fn secret_of(hex: &str) -> SecretKey {
    SecretKey::from(array_of::<KEY_LENGTH>(hex))
}

fn session_of(their_public_key: &str, secret_key: &str) -> SalsaBox {
    session_box_of(&bytes_of(their_public_key), &secret_of(secret_key))
        .expect("the key is accepted")
}

#[test]
fn reproduces_libsodiums_crypto_box_vector() {
    let sealed = seal(
        &session_of(BOB_PUBLIC, ALICE_SECRET),
        &array_of(VECTOR_NONCE),
        &bytes_of(MESSAGE),
    )
    .expect("the message seals");

    assert_eq!(hex_of(&sealed), EXPECTED_BOX);
}

#[test]
fn opens_the_vector_from_the_other_side_of_the_exchange() {
    let opened = open(
        &session_of(ALICE_PUBLIC, BOB_SECRET),
        &array_of(VECTOR_NONCE),
        &bytes_of(EXPECTED_BOX),
    );

    assert_eq!(opened.as_deref().map(hex_of), Some(MESSAGE.to_string()));
}

#[test]
fn derives_the_same_key_from_either_side() {
    let sealed = seal(
        &session_of(BOB_PUBLIC, ALICE_SECRET),
        &array_of(VECTOR_NONCE),
        b"synthetic-plaintext",
    )
    .expect("the message seals");
    let opened = open(
        &session_of(ALICE_PUBLIC, BOB_SECRET),
        &array_of(VECTOR_NONCE),
        &sealed,
    );

    assert_eq!(opened.as_deref(), Some(b"synthetic-plaintext".as_slice()));
}

#[test]
fn returns_none_when_a_ciphertext_byte_is_flipped() {
    let mut tampered = bytes_of(EXPECTED_BOX);

    tampered[40] ^= 0x01;

    assert!(open(
        &session_of(ALICE_PUBLIC, BOB_SECRET),
        &array_of(VECTOR_NONCE),
        &tampered
    )
    .is_none());
}

#[test]
fn returns_none_when_the_nonce_differs() {
    let other_nonce = increment_nonce(&array_of(VECTOR_NONCE));

    assert!(open(
        &session_of(ALICE_PUBLIC, BOB_SECRET),
        &other_nonce,
        &bytes_of(EXPECTED_BOX)
    )
    .is_none());
}

#[test]
fn increments_a_nonce_as_a_little_endian_integer() {
    let mut carrying = [0u8; NONCE_LENGTH];

    carrying[0] = 0xff;
    carrying[1] = 0xff;

    let incremented = increment_nonce(&carrying);

    assert_eq!(hex_of(&incremented), format!("000001{}", "00".repeat(21)));
    assert_eq!(hex_of(&carrying), format!("ffff{}", "00".repeat(22)));
}

#[test]
fn wraps_an_all_ones_nonce_to_zero() {
    assert_eq!(
        hex_of(&increment_nonce(&[0xff; NONCE_LENGTH])),
        "00".repeat(NONCE_LENGTH)
    );
}

#[test]
fn generates_distinct_key_pairs_with_a_full_length_public_key() {
    let first = generate_secret_key().public_key();
    let second = generate_secret_key().public_key();

    assert_eq!(first.as_bytes().len(), KEY_LENGTH);
    assert_eq!(second.as_bytes().len(), KEY_LENGTH);
    assert_ne!(first, second);
}

#[test]
fn generates_a_distinct_twenty_four_byte_nonce() {
    assert_eq!(random_nonce().len(), NONCE_LENGTH);
    assert_ne!(random_nonce(), random_nonce());
}
