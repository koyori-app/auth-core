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

    #[test]
    fn rejects_invalid_private_key() {
        let credentials = GithubAppCredentials::new("123", "not a pem");
        assert!(create_app_jwt(&credentials).is_err());
    }
}
