use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}

pub(crate) fn decode<const N: usize>(value: &str) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| Error::Protocol("invalid hex length or encoding"))?;
    Ok(bytes)
}

pub(crate) fn public(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

pub(crate) fn exchange(
    secret: &[u8; 32],
    peer: [u8; 32],
    info: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let shared = Zeroizing::new(MontgomeryPoint(peer).mul_clamped(*secret).to_bytes());
    if bool::from(shared.ct_eq(&[0; 32])) {
        return Err(Error::Crypto("non-contributory X25519 key"));
    }
    derive(shared.as_ref(), None, info)
}

pub(crate) fn derive(key: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut output = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(salt, key)
        .expand(info, output.as_mut())
        .map_err(|_| Error::Crypto("HKDF output length"))?;
    Ok(output)
}

pub(crate) fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let nonce = random::<12>()?;
    let ciphertext = ChaCha20Poly1305::new(key.into())
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Crypto("encryption failed"))?;
    let mut packet = Vec::with_capacity(12 + ciphertext.len());
    packet.extend(nonce);
    packet.extend(ciphertext);
    Ok(hex::encode(packet))
}

pub(crate) fn decrypt(key: &[u8; 32], packet: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = hex::decode(packet).map_err(|_| Error::Protocol("invalid ciphertext hex"))?;
    if bytes.len() < 28 {
        return Err(Error::Protocol("truncated ciphertext"));
    }
    ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto("authentication tag mismatch"))
}

pub(crate) fn verify(key: &VerifyingKey, message: &[u8], signature: &str) -> Result<()> {
    key.verify_strict(message, &Signature::from_bytes(&decode(signature)?))
        .map_err(|_| Error::Crypto("signature mismatch"))
}

// This is ThomeAuth's documented format, not RFC 8785: integral floats are
// written as integers, including -0.0. Sorting is explicit because callers may
// enable serde_json's preserve_order feature through Cargo feature unification.
pub(crate) fn canonical(value: &Value) -> String {
    match value {
        Value::Object(object) => {
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_unstable_by_key(|(key, _)| *key);
            let fields: Vec<_> = entries
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical(value)
                    )
                })
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(array) => format!(
            "[{}]",
            array.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Number(number) if number.is_f64() => {
            let value = number.as_f64().unwrap();
            if value == 0.0 {
                "0".into()
            } else if value.fract() == 0.0 {
                format!("{value:.0}")
            } else {
                number.to_string()
            }
        }
        _ => value.to_string(),
    }
}
