//! Small helpers: token handling, input validation, temp files, HMAC.

use axum::http::{header, HeaderMap};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use subtle::ConstantTimeEq;

pub const OTP_DIGITS: usize = 8;

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// 256 bits of OS randomness, URL-safe.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Uniformly distributed numeric one-time code with `OTP_DIGITS` digits.
pub fn random_otp() -> String {
    // 4_000_000_000 is an exact multiple of 10^8, so rejection sampling is unbiased.
    loop {
        let mut b = [0u8; 4];
        OsRng.fill_bytes(&mut b);
        let v = u32::from_be_bytes(b);
        if v < 4_000_000_000 {
            return format!("{:0width$}", v % 100_000_000, width = OTP_DIGITS);
        }
    }
}

pub fn ct_eq_str(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub fn hmac_hex(key: &[u8; 32], label: &str, parts: &[&[u8]]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(label.as_bytes());
    mac.update(&[0u8]);
    for p in parts {
        // Length prefix prevents ambiguity between concatenated fields.
        mac.update(&(p.len() as u32).to_be_bytes());
        mac.update(p);
    }
    hex::encode(mac.finalize().into_bytes())
}

pub fn hmac_verify(key: &[u8; 32], label: &str, parts: &[&[u8]], expected_hex: &str) -> bool {
    ct_eq_str(&hmac_hex(key, label, parts), expected_hex)
}

/// Returns the lowercase canonical email, or `None` if it is not acceptable.
pub fn normalize_email(raw: &str) -> Option<String> {
    let e = raw.trim().to_ascii_lowercase();
    if e.len() < 6 || e.len() > 254 {
        return None;
    }
    let (local, domain) = e.split_once('@')?;
    if local.is_empty() || local.len() > 64 || domain.contains('@') {
        return None;
    }
    if !local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-'))
    {
        return None;
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || labels.last().map(|l| l.len() < 2).unwrap_or(true) {
        return None;
    }
    for l in labels {
        if l.is_empty()
            || l.len() > 63
            || l.starts_with('-')
            || l.ends_with('-')
            || !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return None;
        }
    }
    Some(e)
}

/// Strip path components and control characters from a client-supplied filename.
pub fn safe_filename(raw: &str) -> String {
    let last = raw.rsplit(|c| c == '/' || c == '\\').next().unwrap_or("");
    let cleaned: String = last.chars().filter(|c| !c.is_control()).collect();
    let cleaned: String = cleaned.trim().chars().take(180).collect();
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        "file".to_string()
    } else {
        cleaned
    }
}

/// Client MIME types are informational only. Anything odd becomes octet-stream.
pub fn safe_mime(raw: &str) -> String {
    let base = raw.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let ok_chars = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '!' | '#' | '$' | '&' | '^' | '_' | '.' | '+' | '-'))
    };
    match base.split_once('/') {
        Some((a, b)) if base.len() <= 100 && ok_chars(a) && ok_chars(b) => base,
        _ => "application/octet-stream".to_string(),
    }
}

/// `Content-Disposition` value that forces a download with a safe filename.
pub fn content_disposition(filename: &str) -> String {
    let ascii: String = filename
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_ascii_control() && !matches!(c, '"' | '\\' | '%' | ';') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(
        "attachment; filename=\"{}\"; filename*=UTF-8''{}",
        ascii,
        urlencoding::encode(filename)
    )
}

/// Client address for rate limiting and audit hashing.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            let v = v.trim();
            if v.parse::<IpAddr>().is_ok() {
                return v.to_string();
            }
        }
    }
    peer.ip().to_string()
}

pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// A temporary file that is removed when dropped, including on early returns
/// and panics. Temp files must live only under Veyra's private 0700 temp directory.
/// This is cleanup, not guaranteed forensic erasure on flash/storage media.
pub struct TempPath(PathBuf);

impl TempPath {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_validation() {
        assert_eq!(normalize_email("  Alice@Example.COM ").as_deref(), Some("alice@example.com"));
        assert!(normalize_email("a@b").is_none());
        assert!(normalize_email("no-at-sign.example.com").is_none());
        assert!(normalize_email("a b@example.com").is_none());
        assert!(normalize_email("a@@example.com").is_none());
        assert!(normalize_email("a@exa mple.com").is_none());
        assert!(normalize_email("a\r\nbcc:x@example.com").is_none());
        assert!(normalize_email(".a@example.com").is_none());
        assert!(normalize_email("a@-example.com").is_none());
        assert!(normalize_email("a@example.c").is_none());
    }

    #[test]
    fn filename_sanitizing() {
        assert_eq!(safe_filename("../../etc/passwd"), "passwd");
        assert_eq!(safe_filename("C:\\Users\\me\\report.pdf"), "report.pdf");
        assert_eq!(safe_filename(".."), "file");
        assert_eq!(safe_filename(""), "file");
        assert_eq!(safe_filename("a\u{0}b\nc.txt"), "abc.txt");
        assert_eq!(safe_filename(&"x".repeat(500)).chars().count(), 180);
    }

    #[test]
    fn mime_sanitizing() {
        assert_eq!(safe_mime("Text/Plain; charset=utf-8"), "text/plain");
        assert_eq!(safe_mime("garbage"), "application/octet-stream");
        assert_eq!(safe_mime("a/b\r\nX: y"), "application/octet-stream");
    }

    #[test]
    fn content_disposition_is_header_safe() {
        let v = content_disposition("na\"me;\u{e9}.txt");
        assert!(v.starts_with("attachment; filename=\""));
        assert!(!v[..v.find("filename*").unwrap()].contains("\"me"));
        assert!(v.contains("filename*=UTF-8''"));
        assert!(axum::http::HeaderValue::from_str(&v).is_ok());
    }

    #[test]
    fn otp_has_fixed_length_and_digits() {
        for _ in 0..200 {
            let c = random_otp();
            assert_eq!(c.len(), OTP_DIGITS);
            assert!(c.chars().all(|ch| ch.is_ascii_digit()));
        }
    }

    #[test]
    fn hmac_binds_all_fields() {
        let key = [7u8; 32];
        let a = hmac_hex(&key, "otp", &[b"ab", b"c"]);
        let b = hmac_hex(&key, "otp", &[b"a", b"bc"]);
        assert_ne!(a, b);
        assert!(hmac_verify(&key, "otp", &[b"ab", b"c"], &a));
        assert!(!hmac_verify(&key, "ip", &[b"ab", b"c"], &a));
        assert!(!hmac_verify(&[8u8; 32], "otp", &[b"ab", b"c"], &a));
    }

    #[test]
    fn tokens_are_unique_and_hashing_is_stable() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(hash_token(&a), hash_token(&a));
        assert_eq!(hash_token(&a).len(), 64);
    }
}
