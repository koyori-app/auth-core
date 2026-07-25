//! OAuth state の保存・消費と、リダイレクト先の検証。
//!
//! 保存先は [`StateStore`] trait として切ってあり、このクレートは Redis 等の
//! 特定のストレージに依存しない。state payload の型も利用側が決める
//! （アプリ固有のフィールドを載せられるようにするため）。

use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;
use url::Url;

/// OAuth state の TTL（秒）。仕様: 10 分。
pub const STATE_TTL_SECS: u64 = 10 * 60;

const KEY_PREFIX: &str = "oauth:state:";

/// OAuth state の保存先。
///
/// `consume` は取得と削除を原子的に行うこと（state の使い捨てを保証し、
/// リプレイを防ぐため）。Redis なら `GETDEL` が該当する。
#[async_trait]
pub trait StateStore: Send + Sync {
    async fn store(&self, key: &str, value: &str, ttl_secs: u64) -> Result<(), anyhow::Error>;
    async fn consume(&self, key: &str) -> Result<Option<String>, anyhow::Error>;
}

/// state を [`STATE_TTL_SECS`] の TTL 付きで保存する。
pub async fn store_state<S, P>(store: &S, state: &str, payload: &P) -> Result<(), anyhow::Error>
where
    S: StateStore + ?Sized,
    P: Serialize + Sync,
{
    let value = serde_json::to_string(payload)?;
    store
        .store(&format!("{KEY_PREFIX}{state}"), &value, STATE_TTL_SECS)
        .await
}

/// state を取得して即削除する（使い捨て）。
pub async fn consume_state<S, P>(store: &S, state: &str) -> Result<Option<P>, anyhow::Error>
where
    S: StateStore + ?Sized,
    P: DeserializeOwned,
{
    let Some(raw) = store.consume(&format!("{KEY_PREFIX}{state}")).await? else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_str(&raw)?))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedirectValidationError {
    #[error("redirect path must be a relative path starting with /")]
    NotRelative,
    #[error("redirect path contains disallowed characters or patterns")]
    DisallowedPattern,
    #[error("redirect path must stay on the configured frontend origin")]
    OriginMismatch,
    #[error("invalid frontend base URL")]
    InvalidBase,
}

/// `redirect_after` を相対パスとして検証・正規化する（オープンリダイレクト対策）。
pub fn sanitize_redirect_path(path: &str) -> Result<String, RedirectValidationError> {
    let path = path.trim();
    if !path.starts_with('/') {
        return Err(RedirectValidationError::NotRelative);
    }
    if path.starts_with("//")
        || path.contains("://")
        || path.contains(':')
        || path.contains('\\')
        || path.contains('@')
        || path.contains("..")
    {
        return Err(RedirectValidationError::DisallowedPattern);
    }
    Ok(path.to_string())
}

/// フロントへのリダイレクト URL を組み立てる（同一 origin のみ許可）。
pub fn build_frontend_redirect(
    frontend_base: &str,
    redirect_after: &str,
) -> Result<String, RedirectValidationError> {
    let path = sanitize_redirect_path(redirect_after)?;
    let base = Url::parse(frontend_base.trim_end_matches('/'))
        .map_err(|_| RedirectValidationError::InvalidBase)?;

    let joined = base
        .join(path.trim_start_matches('/'))
        .map_err(|_| RedirectValidationError::InvalidBase)?;

    if joined.origin() != base.origin() {
        return Err(RedirectValidationError::OriginMismatch);
    }

    Ok(joined.to_string())
}

/// OAuth プロバイダーが error を返した場合のフロントリダイレクト URL。
pub fn build_frontend_oauth_error_redirect(
    frontend_base: &str,
    redirect_after: &str,
) -> Result<String, RedirectValidationError> {
    let base_url = build_frontend_redirect(frontend_base, redirect_after)?;
    let mut url = Url::parse(&base_url).map_err(|_| RedirectValidationError::InvalidBase)?;
    url.query_pairs_mut()
        .append_pair("oauth_error", "authorization_failed");
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn sanitize_rejects_protocol_relative() {
        assert_eq!(
            sanitize_redirect_path("//evil.com"),
            Err(RedirectValidationError::DisallowedPattern)
        );
    }

    #[test]
    fn sanitize_rejects_absolute_url() {
        assert_eq!(
            sanitize_redirect_path("https://evil.com"),
            Err(RedirectValidationError::NotRelative)
        );
    }

    #[test]
    fn sanitize_rejects_colon_and_at() {
        assert!(sanitize_redirect_path("/foo:bar").is_err());
        assert!(sanitize_redirect_path("/user@host").is_err());
    }

    #[test]
    fn sanitize_accepts_safe_relative_path() {
        assert_eq!(
            sanitize_redirect_path("/dashboard"),
            Ok("/dashboard".to_string())
        );
    }

    #[test]
    fn build_redirect_stays_on_frontend_origin() {
        let url = build_frontend_redirect("https://app.example.com", "/settings/profile").unwrap();
        assert_eq!(url, "https://app.example.com/settings/profile");
    }

    #[test]
    fn build_redirect_rejects_open_redirect_via_path() {
        assert!(build_frontend_redirect("https://app.example.com", "//evil.com/phish").is_err());
    }

    #[test]
    fn oauth_error_redirect_includes_query_param() {
        let url = build_frontend_oauth_error_redirect("https://app.example.com", "/login").unwrap();
        assert!(url.contains("oauth_error=authorization_failed"));
        assert!(url.starts_with("https://app.example.com/login"));
    }

    #[derive(Default)]
    struct MemoryStore {
        entries: Mutex<HashMap<String, String>>,
    }

    #[async_trait]
    impl StateStore for MemoryStore {
        async fn store(&self, key: &str, value: &str, _ttl: u64) -> Result<(), anyhow::Error> {
            self.entries
                .lock()
                .unwrap()
                .insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn consume(&self, key: &str) -> Result<Option<String>, anyhow::Error> {
            Ok(self.entries.lock().unwrap().remove(key))
        }
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct Payload {
        code_verifier: String,
    }

    #[tokio::test]
    async fn state_roundtrips_and_is_single_use() {
        let store = MemoryStore::default();
        let payload = Payload {
            code_verifier: "verifier".into(),
        };
        store_state(&store, "abc", &payload).await.unwrap();

        let got: Option<Payload> = consume_state(&store, "abc").await.unwrap();
        assert_eq!(got, Some(payload));

        // 2 回目は取れない（使い捨て）。
        let again: Option<Payload> = consume_state(&store, "abc").await.unwrap();
        assert_eq!(again, None);
    }

    #[tokio::test]
    async fn state_keys_are_namespaced() {
        let store = MemoryStore::default();
        store_state(
            &store,
            "abc",
            &Payload {
                code_verifier: "v".into(),
            },
        )
        .await
        .unwrap();
        assert!(
            store
                .entries
                .lock()
                .unwrap()
                .contains_key("oauth:state:abc")
        );
    }
}
