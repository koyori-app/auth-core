//! PKCE (RFC 7636) ヘルパ。

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use sha2::{Digest, Sha256};

pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

/// 32 バイト乱数の code_verifier と S256 code_challenge を生成する。
pub fn generate_pkce_pair() -> PkcePair {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let code_verifier = URL_SAFE_NO_PAD.encode(buf);
    let digest = Sha256::digest(code_verifier.as_bytes());
    let code_challenge = URL_SAFE_NO_PAD.encode(digest);
    PkcePair {
        code_verifier,
        code_challenge,
    }
}

/// OAuth state パラメータ（16 バイト乱数, base64url）。
pub fn generate_state() -> String {
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        let pair = generate_pkce_pair();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pair.code_verifier.as_bytes()));
        assert_eq!(pair.code_challenge, expected);
    }

    #[test]
    fn generated_states_differ() {
        assert_ne!(generate_state(), generate_state());
    }
}
