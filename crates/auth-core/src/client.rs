//! OAuth トークン交換・更新と、OIDC 標準の userinfo 取得。
//!
//! ホスト固有の userinfo 取得（GitHub の verified email 選択など）は
//! 各プロバイダークレートの [`crate::provider::OAuthProvider`] 実装側にある。

use chrono::{DateTime, Utc};
use reqwest::header::ACCEPT;
use serde::Deserialize;

use crate::provider::{ProviderConfig, ProviderEndpoints, ProviderUserInfo};

#[derive(Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// トークンエンドポイントの応答。
///
/// GitHub は失敗も 200 で `{"error": "bad_refresh_token", ...}` の形で返すので、
/// `access_token` が無い応答を `error` から読めるようにしておく。
#[derive(Debug, Deserialize)]
struct OAuthTokenJson {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

impl OAuthTokenJson {
    fn into_token_response(self, now: DateTime<Utc>) -> Result<TokenResponse, anyhow::Error> {
        let Some(access_token) = self.access_token else {
            return Err(anyhow::anyhow!(
                "token endpoint returned no access_token: {}: {}",
                self.error.as_deref().unwrap_or("unknown_error"),
                self.error_description.as_deref().unwrap_or("")
            ));
        };
        Ok(TokenResponse {
            access_token,
            refresh_token: self.refresh_token,
            expires_at: self
                .expires_in
                .map(|secs| now + chrono::Duration::seconds(secs)),
        })
    }
}

#[derive(Debug, Deserialize)]
struct OidcUserInfo {
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

/// 認可コードをアクセストークンに交換する（PKCE の code_verifier 付き）。
pub async fn exchange_code(
    http: &reqwest::Client,
    endpoints: &ProviderEndpoints,
    credentials: &ProviderConfig,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse, anyhow::Error> {
    let response = http
        .post(&endpoints.token_url)
        .header(ACCEPT, "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", credentials.client_id.as_str()),
            ("client_secret", credentials.client_secret.as_str()),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await?
        .error_for_status()?;

    let token: OAuthTokenJson = response.json().await?;
    token.into_token_response(Utc::now())
}

/// リフレッシュトークンで新しいアクセストークンを取る（RFC 6749 §6）。
///
/// リフレッシュトークンを回転させるプロバイダーがある（GitHub App のユーザー
/// アクセストークンは更新のたびに新しいリフレッシュトークンを返し、古いものは
/// 使えなくなる）。戻り値の `refresh_token` が `Some` なら、呼び出し側は
/// アクセストークンと一緒に保存し直すこと。
pub async fn refresh_access_token(
    http: &reqwest::Client,
    endpoints: &ProviderEndpoints,
    credentials: &ProviderConfig,
    refresh_token: &str,
) -> Result<TokenResponse, anyhow::Error> {
    let response = http
        .post(&endpoints.token_url)
        .header(ACCEPT, "application/json")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", credentials.client_id.as_str()),
            ("client_secret", credentials.client_secret.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?;

    let token: OAuthTokenJson = response.json().await?;
    token.into_token_response(Utc::now())
}

/// OIDC 標準の userinfo エンドポイントからユーザー情報を取得する。
pub async fn fetch_oidc_user(
    http: &reqwest::Client,
    userinfo_url: &str,
    access_token: &str,
) -> Result<ProviderUserInfo, anyhow::Error> {
    let user: OidcUserInfo = http
        .get(userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let username = user
        .preferred_username
        .or(user.name)
        .unwrap_or_else(|| user.sub.clone());

    Ok(ProviderUserInfo {
        provider_user_id: user.sub,
        email: user.email,
        email_verified: user.email_verified,
        username,
        avatar_url: user.picture,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<TokenResponse, anyhow::Error> {
        let now = DateTime::parse_from_rfc3339("2026-10-10T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        serde_json::from_str::<OAuthTokenJson>(json)
            .unwrap()
            .into_token_response(now)
    }

    #[test]
    fn a_rotated_refresh_token_and_expiry_are_returned() {
        let token = parse(
            r#"{"access_token":"ghu_new","refresh_token":"ghr_new","expires_in":28800,
                "refresh_token_expires_in":15897600,"token_type":"bearer","scope":""}"#,
        )
        .unwrap();
        assert_eq!(token.access_token, "ghu_new");
        assert_eq!(token.refresh_token.as_deref(), Some("ghr_new"));
        assert_eq!(
            token.expires_at.unwrap().to_rfc3339(),
            "2026-10-10T08:00:00+00:00"
        );
    }

    /// GitHub は失敗も 200 で返す。access_token の無い応答を成功として扱わない。
    #[test]
    fn an_error_body_with_200_is_an_error() {
        let err = parse(
            r#"{"error":"bad_refresh_token","error_description":"The refresh token passed is incorrect or expired."}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("bad_refresh_token"), "{err}");
    }

    /// 期限の無いトークン（OAuth App など）は expires_at も refresh_token も無い。
    #[test]
    fn a_non_expiring_token_has_no_expiry() {
        let token = parse(r#"{"access_token":"gho_x","token_type":"bearer"}"#).unwrap();
        assert!(token.refresh_token.is_none());
        assert!(token.expires_at.is_none());
    }
}
