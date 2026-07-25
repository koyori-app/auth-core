//! OAuth 2.0 / OIDC のコア。
//!
//! プロトコル層だけを扱い、DB スキーマや特定のストレージには依存しない。
//! OAuth state の保存先は [`state::StateStore`] trait として切ってあるので、
//! 利用側が Redis なりの実装を与える。
//!
//! 個別のプロバイダ実装（GitHub / GitLab 等）は別クレートにある。

pub mod client;
pub mod crypto;
pub mod pkce;
pub mod provider;
pub mod state;
pub mod url_guard;

pub use provider::{OAuthProvider, ProviderConfig, ProviderEndpoints, ProviderUserInfo};
pub use state::StateStore;
