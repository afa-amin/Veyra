//! Background maintenance: expiry, deletion of dead objects, session purging.

use crate::state::AppState;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

const INTERVAL: Duration = Duration::from_secs(300);
const STALE_TMP_AGE: Duration = Duration::from_secs(6 * 3600);

/// Delete an encrypted object and mark its file row as deleted. Failures are
/// retried by the periodic sweep.
pub async fn delete_object(s: &AppState, key: &str) {
    match s.store.delete(key).await {
        Ok(()) => {
            let r = sqlx::query("UPDATE files SET status = 'deleted', deleted_at = now() WHERE object_key = $1")
                .bind(key)
                .execute(&s.db)
                .await;
            if let Err(e) = r {
                tracing::error!(error = ?e, "could not mark file as deleted");
            }
        }
        Err(e) => tracing::error!(error = ?e, "could not delete encrypted object (will retry)"),
    }
}

/// Remove everything left in the temp directory (used at startup, when no request can own those files).
pub async fn purge_tmp(dir: &std::path::Path, max_age: Option<Duration>) {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if let Some(age) = max_age {
            let old_enough = entry
                .metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map(|d| d >= age)
                .unwrap_or(false);
            if !old_enough {
                continue;
            }
        }
        if let Err(e) = tokio::fs::remove_file(&path).await {
            tracing::warn!(error = ?e, "could not remove stale temp file");
        }
    }
}

async fn sweep(s: &AppState) -> anyhow::Result<()> {
    sqlx::query("UPDATE transfers SET status = 'expired' WHERE status = 'active' AND expires_at <= now()")
        .execute(&s.db)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at <= now()").execute(&s.db).await?;
    sqlx::query("DELETE FROM download_sessions WHERE expires_at <= now()").execute(&s.db).await?;
    sqlx::query("DELETE FROM otp_challenges WHERE created_at < now() - interval '2 days'")
        .execute(&s.db)
        .await?;
    sqlx::query("DELETE FROM download_attempts WHERE created_at < now() - interval '180 days'")
        .execute(&s.db)
        .await?;

    // Files whose transfer is no longer active hold ciphertext that nobody can use.
    let dead: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT f.id, f.object_key FROM files f \
         WHERE f.status = 'active' \
         AND NOT EXISTS (SELECT 1 FROM transfers t WHERE t.file_id = f.id AND t.status = 'active') \
         LIMIT 200",
    )
    .fetch_all(&s.db)
    .await?;
    for (_, key) in dead {
        delete_object(s, &key).await;
    }

    s.limiter.purge(Duration::from_secs(7200));
    purge_tmp(&s.tmp_dir(), Some(STALE_TMP_AGE)).await;
    Ok(())
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = sweep(&state).await {
                tracing::error!(error = ?e, "maintenance sweep failed");
            }
            tokio::time::sleep(INTERVAL).await;
        }
    });
}
