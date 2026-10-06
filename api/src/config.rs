use anyhow::{Context, Result};
use std::{env, path::PathBuf};

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
    pub environment: String,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_user: Option<String>,
    pub smtp_password: Option<String>,
    pub smtp_from: String,
}

fn req(name: &str) -> Result<String> { env::var(name).with_context(|| format!("missing required environment variable {name}")) }
fn opt(name: &str) -> Option<String> { env::var(name).ok().filter(|v| !v.is_empty()) }

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: req("DATABASE_URL")?,
            bind: env::var("VEYRA_BIND").unwrap_or_else(|_| "0.0.0.0:4000".into()),
            public_base_url: env::var("VEYRA_PUBLIC_BASE_URL").unwrap_or_else(|_| "http://localhost".into()),
            data_dir: PathBuf::from(env::var("VEYRA_DATA_DIR").unwrap_or_else(|_| "./data".into())),
            master_key: req("VEYRA_MASTER_ENCRYPTION_KEY")?,
            storage_driver: env::var("STORAGE_DRIVER").unwrap_or_else(|_| "local".into()),
            s3_endpoint: opt("S3_ENDPOINT"),
            s3_bucket: opt("S3_BUCKET"),
            s3_region: env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
            s3_access_key: opt("S3_ACCESS_KEY"),
            s3_secret_key: opt("S3_SECRET_KEY"),
            max_upload_bytes: env::var("MAX_UPLOAD_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(5 * 1024 * 1024 * 1024),
            otp_ttl_minutes: env::var("OTP_TTL_MINUTES").ok().and_then(|v| v.parse().ok()).unwrap_or(10),
            environment: env::var("VEYRA_ENV").unwrap_or_else(|_| "development".into()),
            session_ttl_hours: env::var("SESSION_TTL_HOURS").ok().and_then(|v| v.parse().ok()).unwrap_or(24),
            smtp_host: opt("SMTP_HOST"),
            smtp_port: env::var("SMTP_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(587),
            smtp_user: opt("SMTP_USER"),
            smtp_password: opt("SMTP_PASSWORD"),
            smtp_from: env::var("SMTP_FROM").unwrap_or_else(|_| "Veyra <no-reply@example.com>".into()),
        })
    }
}
