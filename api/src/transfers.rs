//! Creating, listing and revoking transfers.

use crate::{
    auth::{authenticate, authenticate_csrf, MessageOut},
    error::AppError,
    state::AppState,
    util::{hash_token, normalize_email, random_token, safe_filename, safe_mime, TempPath},
};
use axum::{
    extract::{multipart::Field, Multipart, Path, State},
    http::HeaderMap,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::json;
use std::{collections::HashMap, io::Write, time::Duration as StdDuration};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
use veyra_core::VeyraError;

const MAX_TEXT_FIELD: usize = 8 * 1024;

#[derive(Serialize)]
pub struct TransferOut {
    id: Uuid,
    original_filename: String,
    size_bytes: i64,
    mime_type: String,
    recipient_email: String,
    access_mode: String,
    expires_at: String,
    download_limit: Option<i32>,
    download_count: i32,
    status: String,
    created_at: String,
}

#[derive(Serialize)]
pub struct TransferCreatedOut {
    #[serde(flatten)]
    transfer: TransferOut,
    secure_link: String,
}

struct Upload {
    guard: TempPath,
    size: u64,
    filename: String,
    mime: String,
}

struct NewTransfer {
    transfer_id: Uuid,
    file_id: Uuid,
    sender_id: Uuid,
    filename: String,
    mime: String,
    size: u64,
    object_key: String,
    recipient: String,
    access_mode: String,
    policy_expr: String,
    requirements: Vec<String>,
    token_hash: String,
    expires_at: DateTime<Utc>,
    download_limit: Option<i32>,
    destroy: bool,
}

#[cfg(unix)]
fn open_private_std(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn open_private_std(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).open(path)
}

async fn read_text(mut field: Field<'_>) -> Result<String, AppError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = field.chunk().await.map_err(|_| AppError::bad("Invalid form data"))? {
        if buf.len() + chunk.len() > MAX_TEXT_FIELD {
            return Err(AppError::bad("A form field is too long"));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|_| AppError::bad("Invalid form data"))
}

fn parse_bounded(fields: &HashMap<String, String>, name: &str, default: i64, min: i64, max: i64) -> Result<i64, AppError> {
    match fields.get(name).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        None => Ok(default),
        Some(v) => {
            let n: i64 = v.parse().map_err(|_| AppError::bad("Invalid transfer options"))?;
            if (min..=max).contains(&n) {
                Ok(n)
            } else {
                Err(AppError::bad("Invalid transfer options"))
            }
        }
    }
}

async fn receive_file(s: &AppState, mut field: Field<'_>) -> Result<Upload, AppError> {
    let filename = safe_filename(field.file_name().unwrap_or("file"));
    let mime = safe_mime(field.content_type().unwrap_or("application/octet-stream"));
    // Multipart parsing does not expose the final file size before the file body is
    // consumed, while the Veyra object format authenticates plaintext_size in its
    // header/AAD. Keep the unavoidable plaintext staging file strictly inside the
    // private 0700 Veyra temp directory, with a random non-descriptive name.
    let path = s.tmp_dir().join(format!("upload-{}.tmp", Uuid::new_v4()));
    let guard = TempPath::new(path.clone());

    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(&path).await?;

    let mut size = 0u64;
    while let Some(chunk) = field.chunk().await.map_err(|_| AppError::bad("The upload was interrupted"))? {
        size += chunk.len() as u64;
        if size > s.cfg.max_upload_bytes {
            return Err(AppError::bad("The file is larger than the allowed maximum"));
        }
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    file.sync_all().await?;
    // The guard removes this plaintext file on every normal/error/panic path.
    // Startup cleanup and the periodic maintenance sweep remove crash leftovers.
    Ok(Upload { guard, size, filename, mime })
}

pub async fn send_transfer(
    State(s): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
    mut mp: Multipart,
) -> Result<Json<TransferCreatedOut>, AppError> {
    let session = authenticate_csrf(&s, &jar, &headers).await?;
    s.limiter.check(&format!("send:{}", session.user_id), 60, StdDuration::from_secs(3600))?;

    let mut upload: Option<Upload> = None;
    let mut fields: HashMap<String, String> = HashMap::new();
    while let Some(field) = mp.next_field().await.map_err(|_| AppError::bad("Invalid upload"))? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                if upload.is_some() {
                    return Err(AppError::bad("Only one file can be sent at a time"));
                }
                upload = Some(receive_file(&s, field).await?);
            }
            "recipient_email" | "access_mode" | "policy_expression" | "expires_hours"
            | "download_limit" | "destroy_after_first" => {
                fields.insert(name.clone(), read_text(field).await?);
            }
            // Unknown fields (including the legacy `policy_requirements`) are ignored:
            // requirements are always derived server-side from the validated expression.
            _ => {}
        }
    }

    let upload = upload.ok_or_else(|| AppError::bad("Choose a file to send"))?;
    if upload.size == 0 {
        return Err(AppError::bad("The file is empty"));
    }
    let recipient = normalize_email(fields.get("recipient_email").map(String::as_str).unwrap_or(""))
        .ok_or_else(|| AppError::bad("Enter a valid recipient email"))?;
    let access_mode = match fields.get("access_mode").map(|v| v.trim()).unwrap_or("simple") {
        "simple" => "simple",
        "restricted" => "restricted",
        _ => return Err(AppError::bad("Invalid access mode")),
    }
    .to_string();
    let expires_hours = parse_bounded(&fields, "expires_hours", 72, 1, 720)?;
    let download_limit: Option<i32> = match fields.get("download_limit").map(|v| v.trim()) {
        None | Some("") => Some(1),
        Some("unlimited") => None,
        Some(_) => Some(parse_bounded(&fields, "download_limit", 1, 1, 1000)? as i32),
    };
    let destroy = fields.get("destroy_after_first").map(|v| v.trim() == "true").unwrap_or(false);

    let (policy_expr, requirements) = if access_mode == "restricted" {
        let raw = fields.get("policy_expression").map(String::as_str).unwrap_or("");
        let tree = veyra_core::parse_policy(raw).map_err(|_| AppError::bad("Choose at least one valid access requirement"))?;
        let mut ids: Vec<String> = tree.collect_attributes().into_iter().map(|a| a.id()).collect();
        ids.sort();
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE lower(email) = $1)")
            .bind(&recipient)
            .fetch_one(&s.db)
            .await?;
        if !exists {
            return Err(AppError::bad("Restricted transfers require the recipient to have a Veyra account"));
        }
        (tree.to_string(), ids)
    } else {
        ("clearance>=1".to_string(), vec!["clearance>=1".to_string()])
    };

    // Encrypt on a blocking thread, bounded by a semaphore, into a guarded temp file.
    let transfer_id = Uuid::new_v4();
    let permit = s
        .crypto_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| AppError::Internal(anyhow::anyhow!("crypto job queue closed")))?;
    let pk = veyra_core::public_for_policy(&s.public, &s.master, &policy_expr)?;
    let enc_guard = TempPath::new(s.tmp_dir().join(format!("{transfer_id}.vobj")));
    {
        let plain_path = upload.guard.path().to_path_buf();
        let enc_path = enc_guard.path().to_path_buf();
        let (filename, mime, size, policy) =
            (upload.filename.clone(), upload.mime.clone(), upload.size, policy_expr.clone());
        tokio::task::spawn_blocking(move || -> Result<(), VeyraError> {
            let input = std::fs::File::open(&plain_path)?;
            let output = open_private_std(&enc_path)?;
            let mut reader = std::io::BufReader::new(input);
            let mut writer = std::io::BufWriter::new(output);
            veyra_core::encrypt_reader(
                &pk,
                &policy,
                &filename,
                &mime,
                size,
                &mut reader,
                &mut writer,
                veyra_core::DEFAULT_CHUNK_SIZE,
                &mut rand::rngs::OsRng,
            )?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            Ok(())
        })
        .await
        .map_err(|e| AppError::Internal(e.into()))??;
    }
    drop(permit);
    let Upload { guard, size, filename, mime } = upload;
    drop(guard); // the plaintext copy is removed as soon as encryption has finished

    let object_key = format!("{}/{}.vobj", session.user_id, transfer_id);
    s.store.put_file(&object_key, enc_guard.path()).await?;
    drop(enc_guard);

    let token = random_token();
    let expires_at = Utc::now() + Duration::hours(expires_hours);
    let record = NewTransfer {
        transfer_id,
        file_id: Uuid::new_v4(),
        sender_id: session.user_id,
        filename: filename.clone(),
        mime: mime.clone(),
        size,
        object_key: object_key.clone(),
        recipient: recipient.clone(),
        access_mode: access_mode.clone(),
        policy_expr,
        requirements,
        token_hash: hash_token(&token),
        expires_at,
        download_limit,
        destroy,
    };
    if let Err(e) = insert_transfer(&s, &record).await {
        if let Err(del) = s.store.delete(&object_key).await {
            tracing::error!(error = ?del, "could not remove orphaned object after failed insert");
        }
        return Err(e);
    }

    s.audit(
        Some(session.user_id),
        Some(transfer_id),
        "transfer.created",
        json!({ "size_bytes": size, "access_mode": access_mode, "expires_hours": expires_hours }),
    )
    .await;

    let secure_link = format!("{}/#/download/{}", s.cfg.public_base_url, token);
    Ok(Json(TransferCreatedOut {
        transfer: TransferOut {
            id: transfer_id,
            original_filename: filename,
            size_bytes: size as i64,
            mime_type: mime,
            recipient_email: recipient,
            access_mode,
            expires_at: expires_at.to_rfc3339(),
            download_limit,
            download_count: 0,
            status: "active".into(),
            created_at: Utc::now().to_rfc3339(),
        },
        secure_link,
    }))
}

async fn insert_transfer(s: &AppState, t: &NewTransfer) -> Result<(), AppError> {
    let mut tx = s.db.begin().await?;
    sqlx::query(
        "INSERT INTO files (id, original_filename, size_bytes, mime_type, object_key, sender_id) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(t.file_id)
    .bind(&t.filename)
    .bind(t.size as i64)
    .bind(&t.mime)
    .bind(&t.object_key)
    .bind(t.sender_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO transfers (id, file_id, sender_id, recipient_email, access_mode, access_policy, token_hash, \
         expires_at, download_limit, destroy_after_first) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(t.transfer_id)
    .bind(t.file_id)
    .bind(t.sender_id)
    .bind(&t.recipient)
    .bind(&t.access_mode)
    .bind(json!({ "requirements": t.requirements, "expression": t.policy_expr }))
    .bind(&t.token_hash)
    .bind(t.expires_at)
    .bind(t.download_limit)
    .bind(t.destroy)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO recipients (id, transfer_id, email) VALUES ($1,$2,$3)")
        .bind(Uuid::new_v4())
        .bind(t.transfer_id)
        .bind(&t.recipient)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO access_policies (id, transfer_id, expression, requirements) VALUES ($1,$2,$3,$4)")
        .bind(Uuid::new_v4())
        .bind(t.transfer_id)
        .bind(&t.policy_expr)
        .bind(json!(t.requirements))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

type TransferRow = (Uuid, String, i64, String, String, String, DateTime<Utc>, Option<i32>, i32, String, DateTime<Utc>);

pub async fn list_transfers(State(s): State<AppState>, jar: CookieJar) -> Result<Json<Vec<TransferOut>>, AppError> {
    let session = authenticate(&s, &jar).await?;
    let rows: Vec<TransferRow> = sqlx::query_as(
        "SELECT t.id, f.original_filename, f.size_bytes, f.mime_type, t.recipient_email, t.access_mode, t.expires_at, \
         t.download_limit, t.download_count, \
         CASE WHEN t.status = 'active' AND t.expires_at <= now() THEN 'expired' ELSE t.status END AS status, \
         t.created_at \
         FROM transfers t JOIN files f ON f.id = t.file_id \
         WHERE t.sender_id = $1 ORDER BY t.created_at DESC LIMIT 100",
    )
    .bind(session.user_id)
    .fetch_all(&s.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| TransferOut {
                id: r.0,
                original_filename: r.1,
                size_bytes: r.2,
                mime_type: r.3,
                recipient_email: r.4,
                access_mode: r.5,
                expires_at: r.6.to_rfc3339(),
                download_limit: r.7,
                download_count: r.8,
                status: r.9,
                created_at: r.10.to_rfc3339(),
            })
            .collect(),
    ))
}

pub async fn revoke(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Json<MessageOut>, AppError> {
    let session = authenticate_csrf(&s, &jar, &headers).await?;
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE transfers t SET status = 'revoked' FROM files f \
         WHERE t.id = $1 AND t.sender_id = $2 AND t.status = 'active' AND f.id = t.file_id \
         RETURNING f.object_key",
    )
    .bind(id)
    .bind(session.user_id)
    .fetch_optional(&s.db)
    .await?;
    let (object_key,) = row.ok_or(AppError::NotFound)?;
    crate::cleanup::delete_object(&s, &object_key).await;
    s.audit(Some(session.user_id), Some(id), "transfer.revoked", json!({})).await;
    Ok(Json(MessageOut { message: "Access revoked and the encrypted file was deleted".into() }))
}
