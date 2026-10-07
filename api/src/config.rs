//! Runtime configuration, validated at startup. Invalid or unsafe settings
//! make the process refuse to start instead of silently degrading security.

use anyhow::{bail, Context, Result};
use std::{env, path::PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Environment {
    Production,
    Development,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SmtpTls {
    /// Implicit TLS (SMTPS, usually port 465)
    Wrapper,
    /// STARTTLS upgrade (usually port 587)
    StartTls,
    /// Plaintext, only permitted in development
    None,
}

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: String,
    pub public_base_url: String,
    pub data_dir: PathBuf,
    pub master_key: String,
    pub storage_driver: String,
    pub s3_endpoint: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_region: String,
    pub s3_access_key: Option<String>,
    pub s3_secret_key: Option<String>,
    pub max_upload_bytes: u64,
    pub otp_ttl_minutes: i64,
    pub session_ttl_hours: i64,
    pub environment: Environment,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_tls: SmtpTls,
    pub smtp_user: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from: String,
    /// Trust `X-Real-IP` set by the reverse proxy. Enable only behind a proxy
    /// that overwrites this header.
    pub trust_proxy: bool,
    /// If set, only this address may become the first administrator.
    pub admin_email: Option<String>,
    /// Allow generating a new master key even though stored objects exist
    /// (makes all existing objects permanently unreadable).
    pub allow_new_master: bool,
}

const PLACEHOLDER_KEYS: [&str; 2] = [
    "replace-with-32-byte-base64-secret",
    "ZGV2LXZleXJhLW1hc3Rlci1rZXktMzItYnl0ZXMtbG9uZw==",
];
const MIN_MASTER_SECRET_CHARS: usize = 32;
const GIB: u64 = 1024 * 1024 * 1024;

fn req(name: &str) -> Result<String> {
    env::var(name).with_context(|| format!("missing required environment variable {name}"))
}

fn opt(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn parse_num<T: std::str::FromStr>(name: &str, default: T) -> Result<T> {
    match opt(name) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<T>()
            .map_err(|_| anyhow::anyhow!("{name} has an invalid numeric value")),
    }
}

fn parse_bool(name: &str, default: bool) -> Result<bool> {
    match opt(name) {
        None => Ok(default),
        Some(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            _ => bail!("{name} must be true or false"),
        },
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let environment = match opt("VEYRA_ENV").as_deref().map(str::to_ascii_lowercase) {
            None => Environment::Production,
            Some(v) if v == "production" => Environment::Production,
            Some(v) if v == "development" => Environment::Development,
            Some(_) => bail!("VEYRA_ENV must be `production` or `development`"),
        };

        let master_key = req("VEYRA_MASTER_ENCRYPTION_KEY")?;
        if master_key.chars().count() < MIN_MASTER_SECRET_CHARS {
            bail!(
                "VEYRA_MASTER_ENCRYPTION_KEY must be at least {MIN_MASTER_SECRET_CHARS} characters \
                 (generate one with `openssl rand -base64 48`)"
            );
        }
        if environment == Environment::Production && PLACEHOLDER_KEYS.contains(&master_key.as_str()) {
            bail!("VEYRA_MASTER_ENCRYPTION_KEY is a published placeholder value; generate a unique secret");
        }

        let storage_driver = env::var("STORAGE_DRIVER").unwrap_or_else(|_| "local".into());
        if storage_driver != "local" && storage_driver != "s3" {
            bail!("STORAGE_DRIVER must be `local` or `s3`");
        }

        let max_upload_bytes: u64 = parse_num("MAX_UPLOAD_BYTES", 5 * GIB)?;
        if max_upload_bytes == 0 || max_upload_bytes > 64 * GIB {
            bail!("MAX_UPLOAD_BYTES must be between 1 and 64 GiB");
        }
        if storage_driver == "s3" {
            if opt("S3_BUCKET").is_none() {
                bail!("S3_BUCKET is required when STORAGE_DRIVER=s3");
            }
            // Objects are uploaded with a single PUT, which S3 limits to 5 GiB.
            if max_upload_bytes > 4 * GIB {
                bail!("MAX_UPLOAD_BYTES must be at most 4 GiB with STORAGE_DRIVER=s3");
            }
        }

        let otp_ttl_minutes: i64 = parse_num("OTP_TTL_MINUTES", 10)?;
        if !(1..=60).contains(&otp_ttl_minutes) {
            bail!("OTP_TTL_MINUTES must be between 1 and 60");
        }
        let session_ttl_hours: i64 = parse_num("SESSION_TTL_HOURS", 24)?;
        if !(1..=720).contains(&session_ttl_hours) {
            bail!("SESSION_TTL_HOURS must be between 1 and 720");
        }

        let smtp_host = opt("SMTP_HOST");
        if environment == Environment::Production && smtp_host.is_none() {
            bail!("SMTP_HOST is required in production because verification codes are delivered by email");
        }
        let smtp_port: u16 = parse_num("SMTP_PORT", 587)?;
        let smtp_tls = match opt("SMTP_TLS").as_deref().map(str::to_ascii_lowercase).as_deref() {
            None => {
                if smtp_port == 465 {
                    SmtpTls::Wrapper
                } else {
                    SmtpTls::StartTls
                }
            }
            Some("tls") | Some("wrapper") => SmtpTls::Wrapper,
            Some("starttls") => SmtpTls::StartTls,
            Some("none") => SmtpTls::None,
            Some(_) => bail!("SMTP_TLS must be one of: tls, starttls, none"),
        };
        if smtp_tls == SmtpTls::None && environment == Environment::Production {
            bail!("SMTP_TLS=none is not allowed in production");
        }

        let admin_email = opt("VEYRA_ADMIN_EMAIL").map(|e| e.trim().to_ascii_lowercase());

        Ok(Self {
            database_url: req("DATABASE_URL")?,
            bind: env::var("VEYRA_BIND").unwrap_or_else(|_| "127.0.0.1:4000".into()),
            public_base_url: env::var("VEYRA_PUBLIC_BASE_URL")
                .unwrap_or_else(|_| "http://localhost".into())
                .trim_end_matches('/')
                .to_string(),
            data_dir: PathBuf::from(env::var("VEYRA_DATA_DIR").unwrap_or_else(|_| "./data".into())),
            master_key,
            storage_driver,
            s3_endpoint: opt("S3_ENDPOINT"),
            s3_bucket: opt("S3_BUCKET"),
            s3_region: env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
            s3_access_key: opt("S3_ACCESS_KEY"),
            s3_secret_key: opt("S3_SECRET_KEY"),
            max_upload_bytes,
            otp_ttl_minutes,
            session_ttl_hours,
            environment,
            smtp_host,
            smtp_port,
            smtp_tls,
            smtp_user: opt("SMTP_USER"),
            smtp_password: opt("SMTP_PASSWORD"),
            smtp_from: env::var("SMTP_FROM").unwrap_or_else(|_| "Veyra <no-reply@example.com>".into()),
            trust_proxy: parse_bool("VEYRA_TRUST_PROXY", false)?,
            admin_email,
            allow_new_master: parse_bool("VEYRA_ALLOW_NEW_MASTER", false)?,
        })
    }

    pub fn is_development(&self) -> bool {
        self.environment == Environment::Development
    }

    /// Cookies are marked `Secure` whenever the public URL is HTTPS.
    pub fn cookie_secure(&self) -> bool {
        self.public_base_url.starts_with("https://")
    }
}
