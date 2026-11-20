//! GitHub App の JWT 発行。

use anyhow::Context;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

use crate::GithubAppCredentials;

#[derive(Debug, Serialize)]
struct AppJwtClaims {
    iss: String,
    iat: i64,
    exp: i64,
}

/// App 認証用の JWT（RS256）を発行する。有効期限は 9 分。
pub(crate) fn create_app_jwt(credentials: &GithubAppCredentials) -> Result<String, anyhow::Error> {
    let now = Utc::now();
    let claims = AppJwtClaims {
        iss: credentials.app_id.clone(),
        // iat を 60 秒前に設定してサーバ時刻のわずかなズレによる「issued in future」拒否を防ぐ
        iat: (now - Duration::seconds(60)).timestamp(),
        exp: (now + Duration::minutes(9)).timestamp(),
    };
    let key = EncodingKey::from_rsa_pem(credentials.private_key_pem.as_bytes())
        .context("parse github app private key PEM")?;
    encode(&Header::new(Algorithm::RS256), &claims, &key).context("encode github app jwt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
    use serde::Deserialize;

    const TEST_PRIVATE_KEY: &[u8] = include_bytes!("../testdata/private_rsa_key.pem");
    const TEST_PUBLIC_KEY: &[u8] = include_bytes!("../testdata/public_rsa_key.pem");

    #[derive(Debug, Deserialize)]
    struct DecodedAppJwtClaims {
        iss: String,
        iat: i64,
        exp: i64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct MalformedNbfClaims {
        sub: String,
        nbf: String,
        exp: i64,
    }

    #[test]
    fn rejects_invalid_private_key() {
        let credentials = GithubAppCredentials::new("123", "not a pem");
        assert!(create_app_jwt(&credentials).is_err());
    }

    #[test]
    fn creates_verifiable_rs256_app_jwt_with_expected_lifetime() {
        let credentials =
            GithubAppCredentials::new("123", String::from_utf8(TEST_PRIVATE_KEY.to_vec()).unwrap());

        let token = create_app_jwt(&credentials).unwrap();
        assert_eq!(decode_header(&token).unwrap().alg, Algorithm::RS256);

        let key = DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY).unwrap();
        let decoded =
            decode::<DecodedAppJwtClaims>(&token, &key, &Validation::new(Algorithm::RS256))
                .unwrap();

        assert_eq!(decoded.claims.iss, "123");
        assert_eq!(decoded.claims.exp - decoded.claims.iat, 10 * 60);
        assert!(decoded.claims.iat <= Utc::now().timestamp());
        assert!(decoded.claims.exp > Utc::now().timestamp());
    }

    #[test]
    fn rejects_malformed_nbf_claim() {
        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY).unwrap();
        let claims = MalformedNbfClaims {
            sub: "attacker".to_owned(),
            nbf: "99999999999".to_owned(),
            exp: Utc::now().timestamp() + 60 * 60,
        };
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();

        let key = DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_nbf = true;

        assert!(
            decode::<MalformedNbfClaims>(&token, &key, &validation).is_err(),
            "a malformed nbf claim must not bypass validation",
        );
    }
}
