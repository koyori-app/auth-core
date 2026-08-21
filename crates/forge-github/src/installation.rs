//! GitHub App のインストールに対する API 操作。

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use chrono::{DateTime, Duration, FixedOffset, Utc};
use forge_core::{Repository, TokenProvider};
use reqwest::Client;
use serde::Deserialize;

use crate::jwt::create_app_jwt;
use crate::{GithubAppCredentials, GithubAppOAuthCredentials};

const DEFAULT_API_BASE: &str = "https://api.github.com";
/// OAuth のトークン交換は API ではなく github.com 側にある。
const DEFAULT_OAUTH_BASE: &str = "https://github.com";
const DEFAULT_USER_AGENT: &str = "forge-github";
const ACCEPT_GITHUB_JSON: &str = "application/vnd.github+json";
/// `/installation/repositories` の 1 ページあたり件数（GitHub の上限）。
/// 既定は 30 件で、org のインストールは簡単に超える。
const REPOSITORIES_PER_PAGE: usize = 100;
/// ページ送りの上限。1 インストールで 10,000 リポジトリは実運用では出ない。
const REPOSITORIES_MAX_PAGES: usize = 100;
/// `/user/installations` の 1 ページあたり件数（GitHub の上限）。
const INSTALLATIONS_PER_PAGE: usize = 100;
/// ページ送りの上限。1 ユーザーが 10,000 インストールに属することは実運用では出ない。
const INSTALLATIONS_MAX_PAGES: usize = 100;

/// 次のページを取りに行くか。
///
/// 1 ページ分に満たない応答が来たら終わり。`total_count` が分かる場合は、
/// 総数に達した時点でも打ち切る（末尾ページがちょうど満杯のときの無駄打ちを防ぐ）。
fn has_more_pages(
    fetched: usize,
    collected: usize,
    total_count: Option<usize>,
    per_page: usize,
) -> bool {
    if fetched < per_page {
        return false;
    }
    match total_count {
        Some(total) => collected < total,
        None => true,
    }
}

/// インストール情報。
#[derive(Debug, Clone)]
pub struct InstallationInfo {
    pub id: i64,
    pub account_login: String,
    pub created_at: DateTime<FixedOffset>,
}

/// Installation Access Token とその有効期限。
#[derive(Debug, Clone)]
pub struct InstallationAccessToken {
    pub token: String,
    pub expires_at: DateTime<FixedOffset>,
}

#[derive(Debug, Deserialize)]
struct AccountJson {
    login: String,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenJson {
    token: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
struct InstallationJson {
    id: i64,
    account: AccountJson,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct RepositoryJson {
    full_name: String,
    owner: AccountJson,
}

#[derive(Debug, Deserialize)]
struct UserInstallationJson {
    id: i64,
}

#[derive(Debug, Deserialize)]
struct UserInstallationsJson {
    /// そのユーザーが見えるインストールの総数。
    #[serde(default)]
    total_count: Option<usize>,
    installations: Vec<UserInstallationJson>,
}

/// OAuth のトークン交換の応答。GitHub は失敗時も 200 を返し、
/// `error` フィールドで理由を伝えてくる。
#[derive(Debug, Deserialize)]
struct UserAccessTokenJson {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InstallationRepositoriesJson {
    /// インストールが見えるリポジトリの総数。GitHub は常に返すが、
    /// 欠けていてもページ末尾の判定だけで打ち切れるようにしておく。
    #[serde(default)]
    total_count: Option<usize>,
    repositories: Vec<RepositoryJson>,
}

/// GitHub App としての API クライアント。
#[derive(Debug, Clone)]
pub struct GithubApp {
    http: Client,
    api_base: String,
    oauth_base: String,
    user_agent: String,
    credentials: GithubAppCredentials,
    oauth_credentials: Option<GithubAppOAuthCredentials>,
}

impl GithubApp {
    pub fn new(http: Client, credentials: GithubAppCredentials) -> Self {
        Self {
            http,
            api_base: DEFAULT_API_BASE.to_string(),
            oauth_base: DEFAULT_OAUTH_BASE.to_string(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
            credentials,
            oauth_credentials: None,
        }
    }

    /// API のベース URL を差し替える（GitHub Enterprise やテスト用のスタブ向け）。
    pub fn with_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.api_base = api_base.into().trim_end_matches('/').to_string();
        self
    }

    /// OAuth（ユーザー認可）のベース URL を差し替える。
    ///
    /// トークン交換だけは `api.github.com` ではなく `github.com` 側にあるため、
    /// [`Self::with_api_base`] とは別に持つ。
    pub fn with_oauth_base(mut self, oauth_base: impl Into<String>) -> Self {
        self.oauth_base = oauth_base.into().trim_end_matches('/').to_string();
        self
    }

    /// インストール時のユーザー認可に使う資格情報を設定する。
    ///
    /// これを渡さないと [`Self::verify_installation_access`] は使えない。
    pub fn with_oauth_credentials(mut self, credentials: GithubAppOAuthCredentials) -> Self {
        self.oauth_credentials = Some(credentials);
        self
    }

    /// GitHub API は User-Agent を要求するため、利用側のアプリ名を渡せるようにする。
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// App 認証用の JWT を発行する。
    pub fn app_jwt(&self) -> Result<String, anyhow::Error> {
        create_app_jwt(&self.credentials)
    }

    /// このインストールを [`forge_core::TokenProvider`] として扱えるようにする。
    pub fn installation(&self, installation_id: i64) -> InstallationSource {
        InstallationSource {
            app: self.clone(),
            installation_id,
        }
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        bearer: &str,
    ) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.api_base))
            .header("Authorization", format!("Bearer {bearer}"))
            .header("Accept", ACCEPT_GITHUB_JSON)
            .header("User-Agent", self.user_agent.clone())
    }

    pub async fn installation_access_token(
        &self,
        installation_id: i64,
    ) -> Result<InstallationAccessToken, anyhow::Error> {
        let jwt = self.app_jwt()?;
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/app/installations/{installation_id}/access_tokens"),
                &jwt,
            )
            .send()
            .await
            .context("github installation token request")?;
        let body: InstallationTokenJson = parse_ok(response, "github installation token").await?;
        Ok(InstallationAccessToken {
            token: body.token,
            expires_at: DateTime::parse_from_rfc3339(&body.expires_at)
                .context("parse token expires_at")?,
        })
    }

    pub async fn fetch_installation(
        &self,
        installation_id: i64,
    ) -> Result<InstallationInfo, anyhow::Error> {
        let jwt = self.app_jwt()?;
        let response = self
            .request(
                reqwest::Method::GET,
                &format!("/app/installations/{installation_id}"),
                &jwt,
            )
            .send()
            .await
            .context("github get installation")?;
        let body: InstallationJson = parse_ok(response, "github get installation").await?;
        Ok(InstallationInfo {
            id: body.id,
            account_login: body.account.login,
            created_at: DateTime::parse_from_rfc3339(&body.created_at)
                .context("parse installation created_at")?,
        })
    }

    /// インストールコールバックで受け取った `installation_id` を API 経由で検証する。
    ///
    /// - `expected_installation_id` が `Some` なら、それと一致することを要求する
    ///   （再連携時に state へ束縛した installation を守る）
    /// - `None`（新規インストール）なら、`max_age` 以内に作成されたものだけ受け付ける。
    ///   これがないと、攻撃者が自分の古い installation の ID を差し込んで
    ///   他人のプロジェクトに紐付けられてしまう
    pub async fn verify_installation(
        &self,
        installation_id: i64,
        expected_installation_id: Option<i64>,
        max_age: Duration,
    ) -> Result<InstallationInfo, anyhow::Error> {
        let info = self.fetch_installation(installation_id).await?;
        check_installation_binding(
            &info,
            installation_id,
            expected_installation_id,
            Utc::now().fixed_offset(),
            max_age,
        )?;
        Ok(info)
    }

    pub async fn delete_installation(&self, installation_id: i64) -> Result<(), anyhow::Error> {
        let jwt = self.app_jwt()?;
        let response = self
            .request(
                reqwest::Method::DELETE,
                &format!("/app/installations/{installation_id}"),
                &jwt,
            )
            .send()
            .await
            .context("github delete installation")?;

        let status = response.status();
        // 既に消えている場合は成功扱いにする（削除の冪等性）。
        if status.is_success()
            || status == reqwest::StatusCode::NOT_FOUND
            || status == reqwest::StatusCode::GONE
        {
            return Ok(());
        }

        let body = response.text().await.unwrap_or_default();
        Err(anyhow!(
            "github delete installation failed: {status} {body}"
        ))
    }

    /// インストールがアクセスできるリポジトリを列挙する。
    ///
    /// App JWT ではなく Installation Access Token を使う。
    pub async fn list_repositories(
        &self,
        installation_access_token: &str,
    ) -> Result<Vec<Repository>, anyhow::Error> {
        let mut repositories = Vec::new();

        for page in 1..=REPOSITORIES_MAX_PAGES {
            let response = self
                .request(
                    reqwest::Method::GET,
                    &format!(
                        "/installation/repositories?per_page={REPOSITORIES_PER_PAGE}&page={page}"
                    ),
                    installation_access_token,
                )
                .send()
                .await
                .context("github list installation repositories")?;
            let body: InstallationRepositoriesJson =
                parse_ok(response, "github list repositories").await?;

            let fetched = body.repositories.len();
            for repo in body.repositories {
                let (_, name) = repo
                    .full_name
                    .split_once('/')
                    .ok_or_else(|| anyhow!("invalid repository full_name: {}", repo.full_name))?;
                repositories.push(Repository::new(repo.owner.login, name));
            }

            if !has_more_pages(
                fetched,
                repositories.len(),
                body.total_count,
                REPOSITORIES_PER_PAGE,
            ) {
                break;
            }
        }

        Ok(repositories)
    }

    /// インストール時のユーザー認可で受け取った `code` を、ユーザーアクセストークンに交換する。
    ///
    /// GitHub は code が無効・使用済み・期限切れのときも HTTP 200 を返し、
    /// `error` フィールドで理由を伝えてくる。その場合は `Ok(None)` にして、
    /// 通信できなかった場合（`Err`）と区別できるようにしている。
    pub async fn exchange_user_code(&self, code: &str) -> Result<Option<String>, anyhow::Error> {
        let credentials = self
            .oauth_credentials
            .as_ref()
            .ok_or_else(|| anyhow!("github app oauth credentials are not configured"))?;

        let response = self
            .http
            .post(format!("{}/login/oauth/access_token", self.oauth_base))
            .header("Accept", "application/json")
            .header("User-Agent", self.user_agent.clone())
            .form(&[
                ("client_id", credentials.client_id.as_str()),
                ("client_secret", credentials.client_secret.as_str()),
                ("code", code),
            ])
            .send()
            .await
            .context("github exchange user code")?;

        let body: UserAccessTokenJson = parse_ok(response, "github exchange user code").await?;
        if body.error.is_some() {
            // code そのものが無効・使用済み・期限切れ。拒否として扱う。
            return Ok(None);
        }
        match body.access_token {
            Some(token) if !token.is_empty() => Ok(Some(token)),
            // error も access_token も無い応答は想定外なので、拒否ではなく異常として扱う。
            _ => Err(anyhow!("github exchange user code returned no access token")),
        }
    }

    /// ユーザーアクセストークンで、そのユーザーがアクセスできるインストールを列挙する。
    ///
    /// App JWT でも Installation Access Token でもなく、
    /// [`Self::exchange_user_code`] で得たユーザーアクセストークンを使う。
    pub async fn list_user_installation_ids(
        &self,
        user_access_token: &str,
    ) -> Result<Vec<i64>, anyhow::Error> {
        let mut ids = Vec::new();

        for page in 1..=INSTALLATIONS_MAX_PAGES {
            let response = self
                .request(
                    reqwest::Method::GET,
                    &format!("/user/installations?per_page={INSTALLATIONS_PER_PAGE}&page={page}"),
                    user_access_token,
                )
                .send()
                .await
                .context("github list user installations")?;
            let body: UserInstallationsJson =
                parse_ok(response, "github list user installations").await?;

            let fetched = body.installations.len();
            ids.extend(body.installations.into_iter().map(|i| i.id));

            if !has_more_pages(fetched, ids.len(), body.total_count, INSTALLATIONS_PER_PAGE) {
                break;
            }
        }

        Ok(ids)
    }

    /// インストール時のユーザー認可で受け取った `code` の主が、
    /// `installation_id` のインストールにアクセスできるかを GitHub に問い合わせる。
    ///
    /// これが `Ok(false)` なら、そのユーザーは当該インストールの持ち主でも
    /// メンバーでもない（他人の installation_id を差し込まれた場合を含む）。
    /// 通信できなかったときは `Err` を返すので、拒否と一時障害を取り違えない。
    pub async fn verify_installation_access(
        &self,
        code: &str,
        installation_id: i64,
    ) -> Result<bool, anyhow::Error> {
        let Some(user_access_token) = self.exchange_user_code(code).await? else {
            return Ok(false);
        };
        let ids = self.list_user_installation_ids(&user_access_token).await?;
        Ok(ids.contains(&installation_id))
    }
}

/// 特定のインストールに紐づくトークン供給元。
#[derive(Debug, Clone)]
pub struct InstallationSource {
    app: GithubApp,
    installation_id: i64,
}

impl InstallationSource {
    pub fn installation_id(&self) -> i64 {
        self.installation_id
    }

    pub async fn list_repositories(&self) -> Result<Vec<Repository>, anyhow::Error> {
        let token = self
            .app
            .installation_access_token(self.installation_id)
            .await?;
        self.app.list_repositories(&token.token).await
    }
}

#[async_trait]
impl TokenProvider for InstallationSource {
    async fn access_token(&self) -> Result<String, anyhow::Error> {
        Ok(self
            .app
            .installation_access_token(self.installation_id)
            .await?
            .token)
    }
}

/// installation の束縛条件を判定する（テスト可能な純関数）。
///
/// `now` を引数で受けるのは、時刻依存の分岐をテストできるようにするため。
fn check_installation_binding(
    info: &InstallationInfo,
    installation_id: i64,
    expected_installation_id: Option<i64>,
    now: DateTime<FixedOffset>,
    max_age: Duration,
) -> Result<(), anyhow::Error> {
    if info.id != installation_id {
        return Err(anyhow!(
            "installation id mismatch: api={} query={installation_id}",
            info.id
        ));
    }

    match expected_installation_id {
        Some(expected) if expected != installation_id => Err(anyhow!(
            "installation id does not match oauth state binding"
        )),
        Some(_) => Ok(()),
        // 新規インストール: 攻撃者が自分の古い installation の ID を差し込むのを防ぐため、
        // state の有効期間内に作成されたものだけ受け付ける。
        None if info.created_at < now - max_age => Err(anyhow!(
            "installation is too old to bind on first connect (created_at={})",
            info.created_at
        )),
        None => Ok(()),
    }
}

async fn parse_ok<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    context: &str,
) -> Result<T, anyhow::Error> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("{context} failed: {status} {body}"));
    }
    response
        .json()
        .await
        .with_context(|| format!("parse {context} response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_AGE_SECS: i64 = 600;

    #[test]
    fn stops_when_page_is_not_full() {
        assert!(!has_more_pages(30, 30, Some(30), REPOSITORIES_PER_PAGE));
        assert!(!has_more_pages(0, 100, Some(100), REPOSITORIES_PER_PAGE));
    }

    #[test]
    fn continues_while_pages_are_full() {
        // 既定の 30 件で切れていた頃の境界。次のページを取りに行く。
        assert!(has_more_pages(
            REPOSITORIES_PER_PAGE,
            REPOSITORIES_PER_PAGE,
            Some(250),
            REPOSITORIES_PER_PAGE
        ));
        // total_count が無くても、満杯なら続ける
        assert!(has_more_pages(
            REPOSITORIES_PER_PAGE,
            REPOSITORIES_PER_PAGE,
            None,
            REPOSITORIES_PER_PAGE
        ));
    }

    #[test]
    fn stops_when_total_count_is_reached_on_a_full_page() {
        assert!(!has_more_pages(
            REPOSITORIES_PER_PAGE,
            REPOSITORIES_PER_PAGE,
            Some(REPOSITORIES_PER_PAGE),
            REPOSITORIES_PER_PAGE
        ));
    }

    #[test]
    fn page_size_comes_from_the_argument() {
        // per_page を引数で受ける（関数の中で定数を直に見ない）ことの回帰ガード。
        // 同じ「30 件取れた」でも、1 ページ 30 件なら続き、1 ページ 100 件なら終わる。
        // 定数を直に見る実装に戻すと、この 2 つが同じ結果になって落ちる。
        assert!(has_more_pages(30, 30, Some(100), 30));
        assert!(!has_more_pages(30, 30, Some(100), 100));
    }

    fn now() -> DateTime<FixedOffset> {
        DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z").unwrap()
    }

    fn info(id: i64, created_at: &str) -> InstallationInfo {
        InstallationInfo {
            id,
            account_login: "acme".into(),
            created_at: DateTime::parse_from_rfc3339(created_at).unwrap(),
        }
    }

    fn check(
        info: &InstallationInfo,
        installation_id: i64,
        expected: Option<i64>,
    ) -> Result<(), anyhow::Error> {
        check_installation_binding(
            info,
            installation_id,
            expected,
            now(),
            Duration::seconds(MAX_AGE_SECS),
        )
    }

    #[test]
    fn rejects_when_api_id_differs_from_query() {
        // API が別の installation を返したら、その ID を信用しない。
        assert!(check(&info(2, "2026-07-26T11:59:00Z"), 1, None).is_err());
    }

    #[test]
    fn rejects_installation_not_matching_state_binding() {
        // 再連携時: state に束縛済みの installation 以外は受け付けない。
        assert!(check(&info(1, "2020-01-01T00:00:00Z"), 1, Some(99)).is_err());
    }

    #[test]
    fn accepts_installation_matching_state_binding_regardless_of_age() {
        // 束縛済みなら作成日時は問わない（既存の古い installation への再連携）。
        assert!(check(&info(1, "2020-01-01T00:00:00Z"), 1, Some(1)).is_ok());
    }

    #[test]
    fn rejects_stale_installation_on_first_connect() {
        // 新規連携で古い installation ID を差し込む攻撃を防ぐ。
        let stale = info(1, "2026-07-26T11:49:59Z"); // 600 秒 + 1 秒前
        assert!(check(&stale, 1, None).is_err());
    }

    #[test]
    fn accepts_fresh_installation_on_first_connect() {
        let fresh = info(1, "2026-07-26T11:50:01Z"); // 600 秒以内
        assert!(check(&fresh, 1, None).is_ok());
    }
}
