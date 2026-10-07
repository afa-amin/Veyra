//! Recipient flow: link metadata, one-time code, authorization, streaming download.

use crate::{
    auth::MessageOut,
    cleanup,
    error::AppError,
    mail,
    state::AppState,
    util::{
        bearer_token, client_ip, content_disposition, hash_token, hmac_hex, hmac_verify, normalize_email,
        random_otp, random_token, TempPath, OTP_DIGITS,
    },
};
use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    time::Duration as StdDuration,
};
use uuid::Uuid;
use veyra_core::{StreamDecryptor, VeyraError};

const DOWNLOAD_COOKIE: &str = "veyra_dl";
const OTP_LABEL: &str = "otp-v1";
const MAX_CODES_PER_HOUR: i64 = 5;
const MAX_ATTEMPTS_PER_CODE: i32 = 5;
const MAX_FAILURES_PER_DAY: i64 = 10;
const DOWNLOAD_SESSION_MINUTES: i64 = 30;

#[derive(Deserialize)]
pub struct RequestBody {
    email: String,
}

#[derive(Deserialize)]
pub struct VerifyBody {
    email: String,
    code: String,
}

fn otp_hash(s: &AppState, transfer_id: Uuid, email: &str, code: &str) -> String {
    hmac_hex(
        &s.server_key,
        OTP_LABEL,
        &[&transfer_id.as_bytes()[..], email.as_bytes(), code.as_bytes()],
    )
}

async fn record_attempt(s: &AppState, transfer_id: Uuid, email: &str, success: bool, ip: &str) {
    let ip_hash = hmac_hex(&s.server_key, "ip-v1", &[ip.as_bytes()]);
    let email: String = email.chars().take(254).collect();
    let r = sqlx::query(
        "INSERT INTO download_attempts (id, transfer_id, recipient_email, success, ip_hash) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(transfer_id)
    .bind(email)
    .bind(success)
    .bind(ip_hash)
    .execute(&s.db)
    .await;
    if let Err(e) = r {
        tracing::error!(error = ?e, "failed to record download attempt");
    }
}

/// Resolve a link token to an active, unexpired transfer.
async fn find_active(s: &AppState, token: &str) -> Result<(Uuid, String), AppError> {
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, recipient_email FROM transfers WHERE token_hash = $1 AND status = 'active' AND expires_at > now()",
    )
    .bind(hash_token(token))
    .fetch_optional(&s.db)
    .await?;
    row.ok_or(AppError::NotFound)
}

pub async fn public_transfer(
    State(s): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<Value>, AppError> {
    let ip = client_ip(&headers, peer, s.cfg.trust_proxy);
    s.limiter.check(&format!("link-ip:{ip}"), 120, StdDuration::from_secs(60))?;
    let row: Option<(String, i64, DateTime<Utc>)> = sqlx::query_as(
        "SELECT f.original_filename, f.size_bytes, t.expires_at FROM transfers t JOIN files f ON f.id = t.file_id \
         WHERE t.token_hash = $1 AND t.status = 'active' AND t.expires_at > now() AND f.status = 'active'",
    )
    .bind(hash_token(&token))
    .fetch_optional(&s.db)
    .await?;
    let (name, size, expires) = row.ok_or(AppError::NotFound)?;
    // The recipient address is intentionally not disclosed to link holders.
    Ok(Json(json!({
        "original_filename": name,
        "size_bytes": size,
        "expires_at": expires.to_rfc3339(),
    })))
}

pub async fn request_download_otp(
    State(s): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(body): Json<RequestBody>,
) -> Result<Json<MessageOut>, AppError> {
    let ip = client_ip(&headers, peer, s.cfg.trust_proxy);
    s.limiter.check(&format!("otp-request-ip:{ip}"), 20, StdDuration::from_secs(3600))?;
    let (tid, recipient) = find_active(&s, &token).await?;
    s.limiter.check(&format!("otp-request-link:{tid}"), 10, StdDuration::from_secs(3600))?;

    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM otp_challenges WHERE transfer_id = $1 AND created_at > now() - interval '1 hour'",
    )
    .bind(tid)
    .fetch_one(&s.db)
    .await?;
    if recent >= MAX_CODES_PER_HOUR {
        return Err(AppError::TooManyRequests);
    }

    // The response never reveals whether the address matched the recipient.
    let generic = || {
        Json(MessageOut {
            message: "If the address matches the recipient of this transfer, a verification code has been sent.".into(),
        })
    };
    let candidate = normalize_email(&body.email);
    let email = match candidate {
        Some(ref e) if *e == recipient => e.clone(),
        _ => {
            record_attempt(&s, tid, candidate.as_deref().unwrap_or("invalid"), false, &ip).await;
            return Ok(generic());
        }
    };

    let code = random_otp();
    let code_hash = otp_hash(&s, tid, &email, &code);
    let expires = Utc::now() + Duration::minutes(s.cfg.otp_ttl_minutes);
    let mut tx = s.db.begin().await?;
    sqlx::query("UPDATE otp_challenges SET consumed = true WHERE transfer_id = $1 AND consumed = false")
        .bind(tid)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO otp_challenges (id, transfer_id, code_hash, expires_at) VALUES ($1,$2,$3,$4)")
        .bind(Uuid::new_v4())
        .bind(tid)
        .bind(code_hash)
        .bind(expires)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // Delivered in the background so response timing does not depend on the SMTP server.
    let cfg = s.cfg.clone();
    let ttl = s.cfg.otp_ttl_minutes;
    tokio::spawn(async move {
        if let Err(e) = mail::send_otp(&cfg, &email, &code, ttl).await {
            tracing::error!(error = ?e, "failed to send verification email");
        }
    });
    s.audit(None, Some(tid), "recipient.code_requested", json!({})).await;
    Ok(generic())
}

pub async fn verify_download(
    State(s): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(token): Path<String>,
    Json(body): Json<VerifyBody>,
) -> Result<(CookieJar, Json<Value>), AppError> {
    let ip = client_ip(&headers, peer, s.cfg.trust_proxy);
    s.limiter.check(&format!("otp-verify-ip:{ip}"), 30, StdDuration::from_secs(900))?;
    let (tid, recipient) = find_active(&s, &token).await?;

    // Hard cap on guesses per transfer across all codes issued in the last 24 hours.
    let failures: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(attempts), 0)::bigint FROM otp_challenges \
         WHERE transfer_id = $1 AND created_at > now() - interval '24 hours'",
    )
    .bind(tid)
    .fetch_one(&s.db)
    .await?;
    if failures >= MAX_FAILURES_PER_DAY {
        return Err(AppError::TooManyRequests);
    }

    let email = normalize_email(&body.email);
    let code = body.code.trim();
    let well_formed = code.len() == OTP_DIGITS && code.chars().all(|c| c.is_ascii_digit());
    let email = match email {
        Some(e) if e == recipient && well_formed => e,
        other => {
            record_attempt(&s, tid, other.as_deref().unwrap_or("invalid"), false, &ip).await;
            return Err(AppError::Forbidden);
        }
    };

    let mut tx = s.db.begin().await?;
    let row: Option<(Uuid, String, DateTime<Utc>, i32)> = sqlx::query_as(
        "SELECT id, code_hash, expires_at, attempts FROM otp_challenges \
         WHERE transfer_id = $1 AND consumed = false ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
    )
    .bind(tid)
    .fetch_optional(&mut *tx)
    .await?;
    let (challenge_id, code_hash, challenge_expires, attempts) = row.ok_or(AppError::Forbidden)?;
    if challenge_expires <= Utc::now() || attempts >= MAX_ATTEMPTS_PER_CODE {
        return Err(AppError::Forbidden);
    }

    if !hmac_verify(
        &s.server_key,
        OTP_LABEL,
        &[&tid.as_bytes()[..], email.as_bytes(), code.as_bytes()],
        &code_hash,
    ) {
        sqlx::query("UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = $1")
            .bind(challenge_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        record_attempt(&s, tid, &email, false, &ip).await;
        s.audit(None, Some(tid), "recipient.code_rejected", json!({})).await;
        return Err(AppError::Forbidden);
    }

    sqlx::query("UPDATE otp_challenges SET consumed = true WHERE id = $1")
        .bind(challenge_id)
        .execute(&mut *tx)
        .await?;
    let access = random_token();
    let access_expires = Utc::now() + Duration::minutes(DOWNLOAD_SESSION_MINUTES);
    sqlx::query("INSERT INTO download_sessions (id, transfer_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)")
        .bind(Uuid::new_v4())
        .bind(tid)
        .bind(hash_token(&access))
        .bind(access_expires)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE transfers SET verified_at = now() WHERE id = $1")
        .bind(tid)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE recipients SET verified_at = now() WHERE transfer_id = $1")
        .bind(tid)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    s.audit(None, Some(tid), "recipient.verified", json!({})).await;

    // The session is delivered as an HttpOnly cookie scoped to this link so the browser can
    // stream the file straight to disk. The bearer token is also returned for API clients.
    let cookie = Cookie::build((DOWNLOAD_COOKIE, access.clone()))
        .path(format!("/api/v1/download/{token}"))
        .http_only(true)
        .secure(s.cfg.cookie_secure())
        .same_site(SameSite::Strict)
        .build();
    Ok((
        jar.add(cookie),
        Json(json!({ "access_token": access, "expires_at": access_expires.to_rfc3339() })),
    ))
}

fn download_token(jar: &CookieJar, headers: &HeaderMap) -> Option<String> {
    bearer_token(headers).or_else(|| jar.get(DOWNLOAD_COOKIE).map(|c| c.value().to_string()))
}

/// Validate the download session and return the transfer it belongs to.
async fn session_transfer(s: &AppState, token: &str, access: &str) -> Result<Uuid, AppError> {
    let (tid, _) = find_active(s, token).await?;
    let owner: Option<Uuid> = sqlx::query_scalar(
        "SELECT transfer_id FROM download_sessions WHERE token_hash = $1 AND expires_at > now()",
    )
    .bind(hash_token(access))
    .fetch_optional(&s.db)
    .await?;
    match owner {
        Some(t) if t == tid => Ok(tid),
        _ => Err(AppError::Forbidden),
    }
}

pub async fn download_status(
    State(s): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(token): Path<String>,
) -> Result<Json<Value>, AppError> {
    let access = download_token(&jar, &headers).ok_or(AppError::Unauthorized)?;
    let tid = session_transfer(&s, &token, &access).await?;
    let row: (i32, Option<i32>, DateTime<Utc>) =
        sqlx::query_as("SELECT download_count, download_limit, expires_at FROM transfers WHERE id = $1")
            .bind(tid)
            .fetch_one(&s.db)
            .await?;
    let remaining = row.1.map(|limit| (limit - row.0).max(0));
    Ok(Json(json!({
        "ready": remaining.map(|r| r > 0).unwrap_or(true),
        "remaining": remaining,
        "expires_at": row.2.to_rfc3339(),
    })))
}

struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx
            .blocking_send(Ok(Bytes::copy_from_slice(buf)))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client disconnected"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

type TransferInfo = (String, String, Option<String>, Option<i32>, i32, bool, String, i64, String);

async fn release_slot(s: &AppState, tid: Uuid) {
    let r = sqlx::query("UPDATE transfers SET download_count = GREATEST(download_count - 1, 0) WHERE id = $1")
        .bind(tid)
        .execute(&s.db)
        .await;
    if let Err(e) = r {
        tracing::error!(error = ?e, "failed to release download slot");
    }
}

async fn recipient_attributes(s: &AppState, mode: &str, email: &str) -> Result<Vec<String>, AppError> {
    if mode != "restricted" {
        return Ok(vec!["clearance>=1".to_string()]);
    }
    let row: Option<Value> = sqlx::query_scalar("SELECT attributes FROM users WHERE lower(email) = $1")
        .bind(email)
        .fetch_optional(&s.db)
        .await?;
    let value = row.ok_or(AppError::Forbidden)?;
    Ok(serde_json::from_value::<Vec<String>>(value).unwrap_or_default())
}

async fn finalize_download(s: &AppState, tid: Uuid, ok: bool, email: &str, ip: &str, object_key: &str, destroy: bool) {
    record_attempt(s, tid, email, ok, ip).await;
    if !ok {
        s.audit(None, Some(tid), "file.download_failed", json!({})).await;
        return;
    }
    s.audit(None, Some(tid), "file.downloaded", json!({})).await;
    let state: Result<Option<(i32, Option<i32>)>, sqlx::Error> =
        sqlx::query_as("SELECT download_count, download_limit FROM transfers WHERE id = $1")
            .bind(tid)
            .fetch_optional(&s.db)
            .await;
    let exhausted = destroy || matches!(state, Ok(Some((count, Some(limit)))) if count >= limit);
    if exhausted {
        let r = sqlx::query("UPDATE transfers SET status = 'downloaded' WHERE id = $1 AND status = 'active'")
            .bind(tid)
            .execute(&s.db)
            .await;
        if let Err(e) = r {
            tracing::error!(error = ?e, "failed to close transfer");
        }
        cleanup::delete_object(s, object_key).await;
    }
}

pub async fn download_file(
    State(s): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(token): Path<String>,
) -> Result<Response, AppError> {
    let ip = client_ip(&headers, peer, s.cfg.trust_proxy);
    s.limiter.check(&format!("download-ip:{ip}"), 60, StdDuration::from_secs(900))?;
    let access = download_token(&jar, &headers).ok_or(AppError::Unauthorized)?;
    let tid = session_transfer(&s, &token, &access).await?;

    let info: Option<TransferInfo> = sqlx::query_as(
        "SELECT t.recipient_email, t.access_mode, t.access_policy->>'expression', t.download_limit, t.download_count, \
         t.destroy_after_first, f.object_key, f.size_bytes, f.original_filename \
         FROM transfers t JOIN files f ON f.id = t.file_id \
         WHERE t.id = $1 AND t.status = 'active' AND t.expires_at > now() AND f.status = 'active'",
    )
    .bind(tid)
    .fetch_optional(&s.db)
    .await?;
    let (recipient, mode, policy, _limit, _count, destroy, object_key, size, filename) =
        info.ok_or(AppError::NotFound)?;
    let policy = policy.ok_or_else(|| AppError::Internal(anyhow::anyhow!("transfer has no policy")))?;

    // Authorization happens BEFORE a download slot is consumed, so a recipient who does not
    // satisfy the policy cannot burn the sender's download allowance.
    let attrs = veyra_core::effective_attributes(&recipient_attributes(&s, &mode, &recipient).await?);
    let tree = veyra_core::parse_policy(&policy)?;
    let attr_set: HashSet<String> = attrs.iter().cloned().collect();
    if !tree.satisfied_by(&attr_set) {
        record_attempt(&s, tid, &recipient, false, &ip).await;
        s.audit(None, Some(tid), "file.access_denied", json!({})).await;
        return Err(AppError::Forbidden);
    }

    let permit = s
        .download_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::TooManyRequests)?;

    // Reserve a download slot atomically.
    {
        let mut tx = s.db.begin().await?;
        let row: Option<(i32, Option<i32>)> = sqlx::query_as(
            "SELECT download_count, download_limit FROM transfers \
             WHERE id = $1 AND status = 'active' AND expires_at > now() FOR UPDATE",
        )
        .bind(tid)
        .fetch_optional(&mut *tx)
        .await?;
        let (count, limit) = row.ok_or(AppError::Forbidden)?;
        if matches!(limit, Some(l) if count >= l) {
            return Err(AppError::Forbidden);
        }
        sqlx::query("UPDATE transfers SET download_count = download_count + 1 WHERE id = $1")
            .bind(tid)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }

    // Locate the ciphertext (local objects are read in place, remote ones go to a guarded temp file).
    let (source_path, temp_guard): (PathBuf, Option<TempPath>) = match s.store.local_path(&object_key).await {
        Some(p) => (p, None),
        None => {
            let guard = TempPath::new(s.tmp_dir().join(format!("dl-{}.vobj", Uuid::new_v4())));
            if let Err(e) = s.store.get_file(&object_key, guard.path()).await {
                release_slot(&s, tid).await;
                return Err(e);
            }
            (guard.path().to_path_buf(), Some(guard))
        }
    };

    // Decrypt on a blocking thread and stream chunks to the client. Plaintext never touches the disk.
    let (init_tx, init_rx) = tokio::sync::oneshot::channel::<Result<(), VeyraError>>();
    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    let pk = s.public.clone();
    let master = s.master.clone();
    let key_owner = recipient.clone();
    let handle = tokio::task::spawn_blocking(move || -> bool {
        let _permit = permit;
        let _guard = temp_guard;
        let opened = (|| -> Result<StreamDecryptor<std::io::BufReader<std::fs::File>>, VeyraError> {
            let sk = veyra_core::keygen(&pk, &master, &key_owner, &attrs, &mut rand::rngs::OsRng)?;
            let file = std::fs::File::open(&source_path)?;
            StreamDecryptor::new(&pk, &sk, std::io::BufReader::new(file))
        })();
        let decryptor = match opened {
            Ok(d) => {
                let _ = init_tx.send(Ok(()));
                d
            }
            Err(e) => {
                let _ = init_tx.send(Err(e));
                return false;
            }
        };
        match decryptor.decrypt_to(ChannelWriter { tx: body_tx.clone() }) {
            Ok(_) => true,
            Err(e) => {
                tracing::error!(error = %e, "streaming decryption failed");
                let _ = body_tx.blocking_send(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "decryption failed",
                )));
                false
            }
        }
    });

    match init_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            release_slot(&s, tid).await;
            return Err(e.into());
        }
        Err(_) => {
            release_slot(&s, tid).await;
            return Err(AppError::Internal(anyhow::anyhow!("decryption task ended unexpectedly")));
        }
    }

    let state = s.clone();
    let task_recipient = recipient.clone();
    let task_key = object_key.clone();
    tokio::spawn(async move {
        let ok = handle.await.unwrap_or(false);
        finalize_download(&state, tid, ok, &task_recipient, &ip, &task_key, destroy).await;
    });

    let stream = futures_util::stream::unfold(body_rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, content_disposition(&filename))
        .header(header::CONTENT_LENGTH, size.to_string())
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from_stream(stream))
        .map_err(|e| AppError::Internal(e.into()))
}
