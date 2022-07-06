use jsonwebtoken::{
    crypto::{sign, verify},
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen_test::*;
use crate::utils::*;

wasm_bindgen_test_configure!(run_in_browser);

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    company: String,
    exp: i64,
}

#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_pk8() {
    let privkey = include_bytes!("private_ed25519_key.pk8");
    let pubkey = include_bytes!("public_ed25519_key.pk8");

    let encrypted =
        sign(b"hello world", &EncodingKey::from_ed_der(privkey), Algorithm::EdDSA).unwrap();
    let is_valid =
        verify(&encrypted, b"hello world", &DecodingKey::from_ed_der(pubkey), Algorithm::EdDSA)
            .unwrap();
    assert!(is_valid);
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_sign_verification_pem() {
    let privkey_pem = include_bytes!("private_ed25519_key.pem");
    let pubkey_pem = include_bytes!("public_ed25519_key.pem");
    let encrypted =
        sign(b"hello world", &EncodingKey::from_ed_pem(privkey_pem).unwrap(), Algorithm::EdDSA)
            .unwrap();
    let is_valid = verify(
        &encrypted,
        b"hello world",
        &DecodingKey::from_ed_pem(pubkey_pem).unwrap(),
        Algorithm::EdDSA,
    )
        .unwrap();
    assert!(is_valid);
}

#[cfg(feature = "use_pem")]
#[test]
#[wasm_bindgen_test]
fn round_trip_claim() {
    let privkey_pem = include_bytes!("private_ed25519_key.pem");
    let pubkey_pem = include_bytes!("public_ed25519_key.pem");
    let my_claims = Claims {
        sub: "b@b.com".to_string(),
        company: "ACME".to_string(),
        exp: unix_timestamp() + 10000,
    };
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &my_claims,
        &EncodingKey::from_ed_pem(privkey_pem).unwrap(),
    )
        .unwrap();
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_ed_pem(pubkey_pem).unwrap(),
        &Validation::new(Algorithm::EdDSA),
    )
        .unwrap();
    assert_eq!(my_claims, token_data.claims);
}
