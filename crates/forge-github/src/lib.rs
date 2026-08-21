//! GitHub App の API クライアント。
//!
//! App JWT の発行、Installation Access Token の取得、インストール情報の検証、
//! インストール先リポジトリの一覧、インストール時のユーザー認可の検証を提供する。
//!
//! `Installation` 系の型は GitHub 固有の語彙なのでこのクレートの中に閉じる。
//! ホスト中立に扱いたい場合は [`forge_core::TokenProvider`] 経由で使う。

mod installation;
mod jwt;

pub use installation::{GithubApp, InstallationAccessToken, InstallationInfo, InstallationSource};

/// GitHub App の資格情報。App JWT の発行に必要なのはこの 2 つだけ。
#[derive(Clone)]
pub struct GithubAppCredentials {
    pub app_id: String,
    /// RSA 秘密鍵（PEM 形式）
    pub private_key_pem: String,
}

impl GithubAppCredentials {
    pub fn new(app_id: impl Into<String>, private_key_pem: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            private_key_pem: private_key_pem.into(),
        }
    }
}

// 秘密鍵をログに出さない。
impl std::fmt::Debug for GithubAppCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubAppCredentials")
            .field("app_id", &self.app_id)
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

/// GitHub App のユーザー認可（インストール時の OAuth）に使う資格情報。
///
/// App JWT 用の [`GithubAppCredentials`] とは別物で、
/// App 設定ページの Client ID / Client secret を指す。
#[derive(Clone)]
pub struct GithubAppOAuthCredentials {
    pub client_id: String,
    pub client_secret: String,
}

impl GithubAppOAuthCredentials {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}

// client secret をログに出さない。
impl std::fmt::Debug for GithubAppOAuthCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubAppOAuthCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}
