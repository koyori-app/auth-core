//! GitHub の OAuth ログインプロバイダー。

use anyhow::Error;
use async_trait::async_trait;
use auth_core::provider::{OAuthProvider, ProviderEndpoints, ProviderUserInfo};
use reqwest::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;

pub const SLUG: &str = "github";

const DEFAULT_USER_AGENT: &str = "auth-core";

/// GitHub（github.com）の OAuth ログインプロバイダー。
#[derive(Debug, Clone)]
pub struct GithubProvider {
    user_agent: String,
}

impl GithubProvider {
    /// GitHub API は User-Agent を要求するため、利用側のアプリ名を渡す。
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
        }
    }
}

impl Default for GithubProvider {
    fn default() -> Self {
        Self::new(DEFAULT_USER_AGENT)
    }
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: i64,
    login: String,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[async_trait]
impl OAuthProvider for GithubProvider {
    fn slug(&self) -> &str {
        SLUG
    }

    async fn endpoints(&self, _http: &Client) -> Result<ProviderEndpoints, Error> {
        Ok(ProviderEndpoints {
            authorize_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_url: "https://api.github.com/user".to_string(),
            scopes: vec!["read:user", "user:email"],
            use_oidc_id_token: false,
        })
    }

    async fn fetch_user_info(
        &self,
        http: &Client,
        endpoints: &ProviderEndpoints,
        access_token: &str,
    ) -> Result<ProviderUserInfo, Error> {
        let user: GitHubUser = http
            .get(&endpoints.userinfo_url)
            .headers(self.headers(access_token))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let emails: Vec<GitHubEmail> = http
            .get(format!("{}/emails", endpoints.userinfo_url))
            .headers(self.headers(access_token))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let (email, email_verified) = pick_verified_email(&emails);

        Ok(ProviderUserInfo {
            provider_user_id: user.id.to_string(),
            email,
            email_verified,
            username: user.login,
            avatar_url: user.avatar_url,
        })
    }
}

impl GithubProvider {
    fn headers(&self, access_token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {access_token}"))
                .unwrap_or_else(|_| HeaderValue::from_static("Bearer invalid")),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static(DEFAULT_USER_AGENT)),
        );
        headers
    }
}

/// verified なメールのみを候補にし、primary を優先して選ぶ。
///
/// 未検証のメールを採用すると、他人のメールアドレスを登録した GitHub アカウントで
/// 既存ユーザーに紐付けられてしまうため、verified でないものは一切使わない。
fn pick_verified_email(emails: &[GitHubEmail]) -> (Option<String>, Option<bool>) {
    let verified: Vec<&GitHubEmail> = emails.iter().filter(|e| e.verified).collect();
    let pick = verified
        .iter()
        .find(|e| e.primary)
        .copied()
        .or(verified.first().copied());

    match pick {
        Some(e) => (Some(e.email.clone()), Some(true)),
        None => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_email_uses_verified_primary_only() {
        let emails = vec![
            GitHubEmail {
                email: "unverified@example.com".into(),
                primary: true,
                verified: false,
            },
            GitHubEmail {
                email: "verified@example.com".into(),
                primary: false,
                verified: true,
            },
        ];
        let (email, verified) = pick_verified_email(&emails);
        assert_eq!(email.as_deref(), Some("verified@example.com"));
        assert_eq!(verified, Some(true));
    }

    #[test]
    fn github_email_none_when_no_verified() {
        let emails = vec![GitHubEmail {
            email: "bad@example.com".into(),
            primary: true,
            verified: false,
        }];
        let (email, verified) = pick_verified_email(&emails);
        assert!(email.is_none());
        assert!(verified.is_none());
    }

    #[test]
    fn github_email_prefers_primary_among_verified() {
        let emails = vec![
            GitHubEmail {
                email: "secondary@example.com".into(),
                primary: false,
                verified: true,
            },
            GitHubEmail {
                email: "primary@example.com".into(),
                primary: true,
                verified: true,
            },
        ];
        let (email, _) = pick_verified_email(&emails);
        assert_eq!(email.as_deref(), Some("primary@example.com"));
    }
}
