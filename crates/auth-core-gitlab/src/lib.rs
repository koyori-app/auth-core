//! GitLab（gitlab.com / セルフホスト）の OAuth ログインプロバイダー。

use anyhow::Error;
use async_trait::async_trait;
use auth_core::provider::{OAuthProvider, ProviderEndpoints, ProviderUserInfo};
use auth_core::url_guard::normalize_instance_url;
use reqwest::Client;
use serde::Deserialize;

pub const SLUG: &str = "gitlab";
pub const SELF_HOSTED_SLUG: &str = "gitlab_selfhosted";

const GITLAB_COM: &str = "https://gitlab.com";

/// gitlab.com の OAuth ログインプロバイダー。
#[derive(Debug, Clone, Default)]
pub struct GitlabProvider;

/// セルフホスト GitLab の OAuth ログインプロバイダー。
#[derive(Debug, Clone)]
pub struct GitlabSelfHostedProvider {
    instance_url: String,
}

impl GitlabSelfHostedProvider {
    /// インスタンス URL を検証してから保持する。
    ///
    /// URL はユーザー入力なので、プライベート IP やクラウドメタデータへ向いていないことを
    /// [`normalize_instance_url`] で確認する（SSRF 対策）。
    pub fn new(instance_url: &str) -> Result<Self, Error> {
        Ok(Self {
            instance_url: normalize_instance_url(instance_url)?,
        })
    }

    pub fn instance_url(&self) -> &str {
        &self.instance_url
    }
}

fn endpoints_for(base: &str) -> ProviderEndpoints {
    ProviderEndpoints {
        authorize_url: format!("{base}/oauth/authorize"),
        token_url: format!("{base}/oauth/token"),
        userinfo_url: format!("{base}/api/v4/user"),
        scopes: vec!["read_user"],
        use_oidc_id_token: false,
    }
}

#[derive(Debug, Deserialize)]
struct GitLabUser {
    id: i64,
    username: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    confirmed_at: Option<String>,
    avatar_url: Option<String>,
}

async fn fetch_gitlab_user(
    http: &Client,
    userinfo_url: &str,
    access_token: &str,
) -> Result<ProviderUserInfo, Error> {
    let user: GitLabUser = http
        .get(userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(ProviderUserInfo {
        provider_user_id: user.id.to_string(),
        email: user.email.clone(),
        // GitLab は確認済みメールに confirmed_at が入る。
        email_verified: user.confirmed_at.as_ref().map(|_| true),
        username: user.username,
        avatar_url: user.avatar_url,
    })
}

#[async_trait]
impl OAuthProvider for GitlabProvider {
    fn slug(&self) -> &str {
        SLUG
    }

    async fn endpoints(&self, _http: &Client) -> Result<ProviderEndpoints, Error> {
        Ok(endpoints_for(GITLAB_COM))
    }

    async fn fetch_user_info(
        &self,
        http: &Client,
        endpoints: &ProviderEndpoints,
        access_token: &str,
    ) -> Result<ProviderUserInfo, Error> {
        fetch_gitlab_user(http, &endpoints.userinfo_url, access_token).await
    }
}

#[async_trait]
impl OAuthProvider for GitlabSelfHostedProvider {
    fn slug(&self) -> &str {
        SELF_HOSTED_SLUG
    }

    async fn endpoints(&self, _http: &Client) -> Result<ProviderEndpoints, Error> {
        Ok(endpoints_for(&self.instance_url))
    }

    async fn fetch_user_info(
        &self,
        http: &Client,
        endpoints: &ProviderEndpoints,
        access_token: &str,
    ) -> Result<ProviderUserInfo, Error> {
        fetch_gitlab_user(http, &endpoints.userinfo_url, access_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gitlab_com_endpoints_point_at_saas() {
        let http = Client::new();
        let e = GitlabProvider.endpoints(&http).await.unwrap();
        assert_eq!(e.authorize_url, "https://gitlab.com/oauth/authorize");
        assert_eq!(e.token_url, "https://gitlab.com/oauth/token");
        assert_eq!(e.userinfo_url, "https://gitlab.com/api/v4/user");
    }

    #[test]
    fn self_hosted_rejects_private_instance_url() {
        assert!(GitlabSelfHostedProvider::new("https://192.168.1.1").is_err());
        assert!(GitlabSelfHostedProvider::new("https://[::ffff:169.254.169.254]").is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn self_hosted_endpoints_use_normalized_instance_url() {
        // localhost は明示的に許可されている（開発用途）。末尾スラッシュは落ちる。
        let provider = GitlabSelfHostedProvider::new("http://localhost:8080/").unwrap();
        assert_eq!(provider.instance_url(), "http://localhost:8080");

        let e = provider.endpoints(&Client::new()).await.unwrap();
        assert_eq!(e.authorize_url, "http://localhost:8080/oauth/authorize");
        assert_eq!(e.userinfo_url, "http://localhost:8080/api/v4/user");
    }
}
