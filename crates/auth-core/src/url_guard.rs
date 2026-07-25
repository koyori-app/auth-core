//! セルフホストインスタンスの URL 検証（SSRF 対策）。
//!
//! ユーザーが任意のインスタンス URL を指定できるプロバイダ（GitLab セルフホスト、
//! 汎用 OIDC など）で使う。プライベート IP・リンクローカル・クラウドメタデータへの
//! 到達を拒否する。

use std::net::{IpAddr, ToSocketAddrs};

use url::Url;

fn resolve_socket_addrs(host: &str) -> Result<Vec<std::net::SocketAddr>, anyhow::Error> {
    let lookup = || -> Result<Vec<std::net::SocketAddr>, anyhow::Error> {
        (host, 443)
            .to_socket_addrs()
            .map_err(|e| anyhow::anyhow!("instance_url DNS resolution failed: {e}"))
            .map(|iter| iter.collect())
    };
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::task::block_in_place(lookup)
    } else {
        lookup()
    }
}

fn is_localhost_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_restricted_ip(ip: IpAddr) -> bool {
    // IPv4-mapped IPv6（::ffff:a.b.c.d）を IPv4 へ正規化してから判定する。
    // 正規化しないと ::ffff:169.254.169.254（クラウドメタデータ）や ::ffff:10.0.0.1 が
    // v6 分岐のどの条件にも当たらず制限をすり抜ける。
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (v6.segments()[0] & 0xff00) == 0xfe00 // link-local fe80::/10
        }
    }
}

fn is_localhost_ip(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn validate_resolved_host(host: &str) -> Result<(), anyhow::Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_restricted_ip(ip) && !is_localhost_ip(ip) {
            anyhow::bail!("instance_url must not target a private or restricted IP address");
        }
        return Ok(());
    }

    let addrs: Vec<IpAddr> = resolve_socket_addrs(host)?
        .into_iter()
        .map(|addr| addr.ip())
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("instance_url host could not be resolved");
    }

    for ip in addrs {
        if is_restricted_ip(ip) && !is_localhost_ip(ip) {
            anyhow::bail!("instance_url must not resolve to a private or restricted IP address");
        }
    }

    Ok(())
}

pub fn validate_instance_url(raw: &str) -> Result<(), anyhow::Error> {
    let parsed = Url::parse(raw)?;
    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        anyhow::bail!("instance_url must use https (http is only allowed for localhost)");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("instance_url must include a host"))?;
    if scheme == "http" && !is_localhost_host(host) {
        anyhow::bail!("instance_url over http is only allowed for localhost");
    }
    validate_resolved_host(host)?;
    Ok(())
}

/// 末尾スラッシュを落として検証済みの URL を返す。
pub fn normalize_instance_url(raw: &str) -> Result<String, anyhow::Error> {
    let trimmed = raw.trim().trim_end_matches('/');
    validate_instance_url(trimmed)?;
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_ip_literal() {
        assert!(validate_instance_url("https://192.168.1.1").is_err());
        assert!(validate_instance_url("https://10.0.0.5").is_err());
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_bypass() {
        // ::ffff:169.254.169.254 = クラウドメタデータ 169.254.169.254 の v6 マップ形式。
        // 正規化前は v6 分岐をすり抜けていた（SSRF）。https を使うのは、http だと
        // localhost 以外は scheme チェックで先に弾かれ IP 判定に到達しないため。
        assert!(validate_instance_url("https://[::ffff:169.254.169.254]").is_err());
        assert!(validate_instance_url("https://[::ffff:a9fe:a9fe]").is_err());
        // プライベート v4 のマップ形式も同様に拒否する。
        assert!(validate_instance_url("https://[::ffff:10.0.0.1]").is_err());
        assert!(validate_instance_url("https://[::ffff:192.168.0.1]").is_err());
    }

    #[test]
    fn rejects_ipv6_metadata_and_local() {
        assert!(validate_instance_url("https://[fe80::1]").is_err()); // link-local
        assert!(validate_instance_url("https://[fc00::1]").is_err()); // ULA
    }

    #[test]
    fn allows_localhost_instance() {
        assert!(validate_instance_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_instance_url("http://localhost:8080").is_ok());
    }

    #[test]
    fn normalize_strips_trailing_slash() {
        assert_eq!(
            normalize_instance_url("  http://localhost:8080/  ").unwrap(),
            "http://localhost:8080"
        );
    }
}
