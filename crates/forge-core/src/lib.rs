//! Git ホスティングサービス連携の、ホスト中立な抽象。
//!
//! GitHub の Installation Access Token、GitLab の Project Access Token のように、
//! API 呼び出しに使うトークンの入手方法はホストごとに違う。その違いを
//! [`TokenProvider`] の裏に隠し、利用側は「トークンが取れる何か」として扱えるようにする。
//!
//! ホスト固有の語彙（GitHub の `Installation` など）はこのクレートには置かない。
//! 各実装クレートの中に閉じること。
//!
//! このクレートは意図的に小さい。実装が増えて共通化すべき操作が見えてから広げる。

use async_trait::async_trait;

/// ホストへの API 呼び出しに使うアクセストークンを供給する。
///
/// 実装は期限切れトークンの更新を内部で行ってよい。呼び出し側は必要になるたびに
/// [`TokenProvider::access_token`] を呼び、返ってきたトークンを長期保持しないこと。
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn access_token(&self) -> Result<String, anyhow::Error>;
}

/// ホスト中立のリポジトリ識別子。
///
/// GitHub の `full_name`（`owner/name`）や GitLab の `path_with_namespace` は
/// 各実装クレート側でこの形に正規化する。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Repository {
    pub owner: String,
    pub name: String,
}

impl Repository {
    pub fn new(owner: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            name: name.into(),
        }
    }
}

impl std::fmt::Display for Repository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}
