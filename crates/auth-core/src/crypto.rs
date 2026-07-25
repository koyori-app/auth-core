//! トークンの AES-256-GCM 暗号化。
//!
//! 鍵は HKDF-SHA256 で鍵材料から導出する。鍵材料の先頭を切り取って直接鍵に使う
//! 方式ではないため、鍵材料の長さが 32 バイトを超えていても全体がエントロピーに寄与する。
//!
//! フォーマット: `base64url(nonce(12B) + ciphertext)`

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, anyhow};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

const NONCE_LEN: usize = 12;
const MIN_KEY_MATERIAL_LEN: usize = 32;
const HKDF_INFO: &[u8] = b"auth-core/token/v1";

pub fn encrypt_token(key_material: &str, plaintext: &str) -> Result<String, anyhow::Error> {
    let key = derive_key(key_material)?;
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow!("encrypt token: {e}"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(out))
}

pub fn decrypt_token(key_material: &str, encoded: &str) -> Result<String, anyhow::Error> {
    let key = derive_key(key_material)?;
    let cipher = Aes256Gcm::new(&key.into());

    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decode encrypted token")?;
    if bytes.len() <= NONCE_LEN {
        return Err(anyhow!("encrypted token too short"));
    }

    let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| anyhow!("invalid nonce length"))?;
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow!("decrypt token: {e}"))?;

    String::from_utf8(plaintext).context("token utf8")
}

fn derive_key(key_material: &str) -> Result<[u8; 32], anyhow::Error> {
    if key_material.len() < MIN_KEY_MATERIAL_LEN {
        return Err(anyhow!(
            "token encryption key must be at least {MIN_KEY_MATERIAL_LEN} bytes"
        ));
    }
    let hk = Hkdf::<Sha256>::new(None, key_material.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .map_err(|e| anyhow!("hkdf expand: {e}"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        "a".repeat(32)
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let enc = encrypt_token(&key(), "ghs_test_token").unwrap();
        assert_eq!(decrypt_token(&key(), &enc).unwrap(), "ghs_test_token");
    }

    #[test]
    fn rejects_short_key_material() {
        let short = "a".repeat(MIN_KEY_MATERIAL_LEN - 1);
        assert!(encrypt_token(&short, "token").is_err());
        assert!(decrypt_token(&short, "whatever").is_err());
    }

    #[test]
    fn derived_key_is_not_a_prefix_of_key_material() {
        // 先頭切り取り方式との取り違えを検知する。
        let material = key();
        let derived = derive_key(&material).unwrap();
        assert_ne!(derived, material.as_bytes()[..32]);
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let a = encrypt_token(&key(), "same").unwrap();
        let b = encrypt_token(&key(), "same").unwrap();
        assert_ne!(a, b, "nonce reuse would make ciphertexts identical");
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let enc = encrypt_token(&key(), "secret").unwrap();
        assert!(decrypt_token(&"b".repeat(32), &enc).is_err());
    }

    #[test]
    fn decrypt_rejects_truncated_ciphertext() {
        let enc = encrypt_token(&key(), "secret").unwrap();
        let truncated = URL_SAFE_NO_PAD.encode(&URL_SAFE_NO_PAD.decode(&enc).unwrap()[..NONCE_LEN]);
        assert!(decrypt_token(&key(), &truncated).is_err());
    }
}
