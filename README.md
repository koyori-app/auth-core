# auth-core

Git ホスティングサービスとの連携に必要な土台を提供する Rust クレート群。

リポジトリ名は `auth-core` だが、スコープは認証だけではない。GitLab や Gitea には
GitHub App に相当する機構がなく、その役割を OAuth トークンが担うため、認証層と
API クライアント層は実際には地続きになる。そのため両者を同じリポジトリに置き、
分離はクレート境界で行っている。

利用側は必要なクレートだけを依存に書けばよい。Cargo の消費単位はリポジトリでは
なくクレートなので、`auth-core` だけを指定すれば `forge-*` はコンパイルされない。

## クレート

| クレート | 役割 |
|---|---|
| `auth-core` | OAuth 2.0 / OIDC のコア。PKCE・state 管理・トークン暗号化・SSRF ガード・`OAuthProvider` trait |
| `auth-core-github` | GitHub の OAuth ログインプロバイダ |
| `auth-core-gitlab` | GitLab（SaaS / セルフホスト）の OAuth ログインプロバイダ |
| `forge-core` | ホスト中立の連携抽象。`TokenProvider` trait と `Repository` 型 |
| `forge-github` | GitHub App の API クライアント（App JWT / Installation Access Token / リポジトリ一覧） |

`auth-core` は Redis などの特定のストレージに依存しない。OAuth state の保存先は
`auth_core::state::StateStore` trait として切ってあるので、利用側が実装を与える。

## 設計方針

- **コアの抽象にホスト固有の語彙を漏らさない。** `InstallationAccessToken` のような
  GitHub 用語は `forge-github` の中に閉じ、`forge-core` の trait シグネチャには出さない
- **実装クレート名にホスト名が入るのは自然。** 利用側が選んで依存するため
- **使う予定のない抽象を先回りして定義しない。** 実装が 1 つしかない段階で
  trait を広げても、2 例目で形が変わるだけになる

## ライセンス

MIT
