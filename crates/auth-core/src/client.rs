//! OAuth トークン交換と、OIDC 標準の userinfo 取得。
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

#[derive(Debug, Deserialize)]
struct OAuthTokenJson {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
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
    let expires_at = token
        .expires_in
        .map(|secs| Utc::now() + chrono::Duration::seconds(secs));

    Ok(TokenResponse {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at,
    })
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
