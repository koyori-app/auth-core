//! OAuth プロバイダーの抽象と、認可 URL の組み立て。

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

/// プロバイダーの各エンドポイント。OIDC discovery で動的に解決する場合もある。
#[derive(Debug, Clone)]
pub struct ProviderEndpoints {
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: Vec<&'static str>,
    pub use_oidc_id_token: bool,
}

/// プロバイダーから取得したユーザー情報を正規化したもの。
#[derive(Debug, Clone)]
pub struct ProviderUserInfo {
    pub provider_user_id: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub username: String,
    pub avatar_url: Option<String>,
}

/// OAuth クライアント資格情報。
#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub client_id: String,
    pub client_secret: String,
}

/// OAuth ログインプロバイダー。
///
/// 実装は別クレート（`auth-core-github` / `auth-core-gitlab` など）にある。
/// `Box<dyn OAuthProvider>` で扱えるよう `async_trait` を使っている。
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// DB や設定で使うプロバイダー識別子。
    fn slug(&self) -> &str;

    async fn endpoints(&self, http: &Client) -> Result<ProviderEndpoints, anyhow::Error>;

    async fn fetch_user_info(
        &self,
        http: &Client,
        endpoints: &ProviderEndpoints,
        access_token: &str,
    ) -> Result<ProviderUserInfo, anyhow::Error>;
}

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
}

/// OIDC Discovery（`.well-known/openid-configuration`）でエンドポイントを取得する。
pub async fn fetch_oidc_discovery(
    http: &Client,
    issuer_url: &str,
) -> Result<ProviderEndpoints, anyhow::Error> {
    let issuer = issuer_url.trim_end_matches('/');
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let doc: OidcDiscoveryDocument = http
        .get(&discovery_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let userinfo_url = doc
        .userinfo_endpoint
        .ok_or_else(|| anyhow::anyhow!("OIDC discovery document missing userinfo_endpoint"))?;

    Ok(ProviderEndpoints {
        authorize_url: doc.authorization_endpoint,
        token_url: doc.token_endpoint,
        userinfo_url,
        scopes: vec!["openid", "email", "profile"],
        use_oidc_id_token: true,
    })
}

/// PKCE 付きの認可 URL を組み立てる。
pub fn build_authorize_url(
    endpoints: &ProviderEndpoints,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> String {
    let scope = endpoints.scopes.join(" ");
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        endpoints.authorize_url,
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&scope),
        urlencoding::encode(state),
        urlencoding::encode(code_challenge),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> ProviderEndpoints {
        ProviderEndpoints {
            authorize_url: "https://example.com/oauth/authorize".into(),
            token_url: "https://example.com/oauth/token".into(),
            userinfo_url: "https://example.com/api/user".into(),
            scopes: vec!["read_user", "email"],
            use_oidc_id_token: false,
        }
    }

    #[test]
    fn authorize_url_percent_encodes_parameters() {
        let url = build_authorize_url(
            &endpoints(),
            "client id",
            "https://app.example.com/callback?x=1",
            "st/ate",
            "chal+lenge",
        );
        assert!(url.starts_with("https://example.com/oauth/authorize?"));
        assert!(url.contains("client_id=client%20id"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback%3Fx%3D1"));
        assert!(url.contains("state=st%2Fate"));
        assert!(url.contains("code_challenge=chal%2Blenge"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn authorize_url_joins_scopes_with_space() {
        let url = build_authorize_url(&endpoints(), "id", "https://cb", "s", "c");
        assert!(url.contains("scope=read_user%20email"));
    }
}
