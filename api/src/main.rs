mod auth;
mod cleanup;
mod config;
mod crypto_service;
mod db;
mod download;
mod error;
mod mail;
mod ratelimit;
mod state;
mod storage;
mod transfers;
mod util;

use anyhow::{bail, Context, Result};
use axum::{
    extract::{DefaultBodyLimit, Request},
    http::HeaderValue,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use config::Config;
use hkdf::Hkdf;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tracing::info;

const MAX_CONCURRENT_ENCRYPTIONS: usize = 4;
const MAX_CONCURRENT_DOWNLOADS: usize = 64;

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    if !h.contains_key("cache-control") {
        h.insert("cache-control", HeaderValue::from_static("no-store"));
    }
    resp
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn ready(axum::extract::State(s): axum::extract::State<AppState>) -> Result<Json<Value>, error::AppError> {
    sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&s.db).await?;
    Ok(Json(json!({ "status": "ready" })))
}

fn derive_server_key(secret: &str) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"veyra-server-key-salt-v1"), secret.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"veyra-hmac-key-v1", &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

#[cfg(unix)]
fn restrict_dir(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_path: &std::path::Path) {}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();

    let cfg = Config::from_env()?;
    if cfg.is_development() {
        tracing::warn!("running in DEVELOPMENT mode: verification codes are printed to the log when SMTP is not configured");
    }
    if !cfg.cookie_secure() {
        tracing::warn!("VEYRA_PUBLIC_BASE_URL is not https: session cookies will not be marked Secure");
    }

    tokio::fs::create_dir_all(&cfg.data_dir).await?;
    restrict_dir(&cfg.data_dir);
    let tmp_dir = cfg.data_dir.join("tmp");
    tokio::fs::create_dir_all(&tmp_dir).await?;
    restrict_dir(&tmp_dir);
    // No request can own these files at startup: remove leftovers of a previous crash.
    cleanup::purge_tmp(&tmp_dir, None).await;

    let db = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&cfg.database_url)
        .await
        .context("database connection failed")?;
    db::migrate(&db).await.context("database migration failed")?;

    let store = storage::build_store(&cfg).await?;

    // Never silently replace the master key when encrypted data exists.
    let master_exists = crypto_service::master_file_path(&cfg.data_dir).exists();
    let files_exist: i64 = sqlx::query_scalar("SELECT count(*) FROM files WHERE status = 'active'")
        .fetch_one(&db)
        .await?;
    if !master_exists && files_exist > 0 && !cfg.allow_new_master {
        if crypto_service::legacy_master_exists(&cfg.data_dir) {
            bail!(
                "this data directory was created by Veyra 0.1, whose objects use a CP-ABE construction that was \
                 found to be insecure and are not readable by this version. Remove or re-send existing transfers, \
                 then start with VEYRA_ALLOW_NEW_MASTER=true to create a new master key"
            );
        }
        bail!("master key file is missing but encrypted transfers exist; restore it from backup");
    }
    let (public, master) = crypto_service::load_or_create(
        &cfg.data_dir,
        &cfg.master_key,
        !master_exists && (files_exist == 0 || cfg.allow_new_master),
    )?;

    let server_key = derive_server_key(&cfg.master_key)?;
    let bind = cfg.bind.clone();
    let max_body = usize::try_from(cfg.max_upload_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(1024 * 1024);

    let state = AppState {
        cfg: Arc::new(cfg),
        db,
        store,
        master: Arc::new(master),
        public: Arc::new(public),
        limiter: Arc::new(ratelimit::RateLimiter::new()),
        server_key: Arc::new(server_key),
        crypto_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_ENCRYPTIONS)),
        download_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS)),
        dummy_hash: Arc::new(auth::make_dummy_hash()?),
    };

    cleanup::spawn(state.clone());

    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/auth/register", post(auth::register))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/me", get(auth::me))
        .route(
            "/api/v1/transfers",
            get(transfers::list_transfers)
                // Only the upload route accepts large bodies; everything else keeps axum's 2 MiB default.
                .merge(post(transfers::send_transfer).layer(DefaultBodyLimit::max(max_body))),
        )
        .route("/api/v1/transfers/:id/revoke", post(transfers::revoke))
        .route("/api/v1/admin/users", get(auth::admin_list_users))
        .route("/api/v1/admin/users/:id/attributes", post(auth::admin_attributes))
        .route("/api/v1/download/:token", get(download::public_transfer))
        .route("/api/v1/download/:token/request-verification", post(download::request_download_otp))
        .route("/api/v1/download/:token/verify", post(download::verify_download))
        .route("/api/v1/download/:token/status", get(download::download_status))
        .route("/api/v1/download/:token/file", get(download::download_file))
        .layer(middleware::from_fn(security_headers))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await.with_context(|| format!("cannot bind {bind}"))?;
    info!(bind = %bind, "Veyra API started");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}
