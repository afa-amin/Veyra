use crate::{config::Config, ratelimit::RateLimiter, storage::ObjectStore};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;
use veyra_core::{MasterSecretKey, PublicKey};

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: PgPool,
    pub store: Arc<dyn ObjectStore>,
    pub master: Arc<MasterSecretKey>,
    pub public: Arc<PublicKey>,
    pub limiter: Arc<RateLimiter>,
    /// HMAC key for one-time codes and IP pseudonymization (derived from the master secret).
    pub server_key: Arc<[u8; 32]>,
    /// Bounds concurrent CPU/disk heavy crypto jobs.
    pub crypto_slots: Arc<Semaphore>,
    /// Bounds concurrent streaming downloads (each holds a blocking thread).
    pub download_slots: Arc<Semaphore>,
    /// Valid Argon2 hash used to equalize login timing for unknown accounts.
    pub dummy_hash: Arc<String>,
}

impl AppState {
    /// Best-effort audit trail: failures are logged but never fail the request.
    pub async fn audit(
        &self,
        user_id: Option<Uuid>,
        transfer_id: Option<Uuid>,
        event: &str,
        metadata: serde_json::Value,
    ) {
        let result = sqlx::query(
            "INSERT INTO audit_events (id, user_id, transfer_id, event, metadata) VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(transfer_id)
        .bind(event)
        .bind(metadata)
        .execute(&self.db)
        .await;
        if let Err(e) = result {
            tracing::error!(error = ?e, event, "failed to write audit event");
        }
    }

    pub fn tmp_dir(&self) -> std::path::PathBuf {
        self.cfg.data_dir.join("tmp")
    }
}
