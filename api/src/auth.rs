//! Accounts, sessions, CSRF protection and administrator endpoints.

use crate::{
    error::AppError,
    state::AppState,
    util::{client_ip, ct_eq_str, hash_token, normalize_email, random_token},
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration as StdDuration};
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "veyra_session";
pub const CSRF_COOKIE: &str = "veyra_csrf";
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 256;
const REGISTER_LOCK_ID: i64 = 727_301;
const MAX_ATTRIBUTES_PER_USER: usize = 64;

#[derive(Deserialize)]
pub struct AuthBody {
    email: String,
    password: String,
    display_name: Option<String>,
}

#[derive(Serialize)]
pub struct UserOut {
    id: Uuid,
    email: String,
    display_name: String,
    role: String,
    attributes: Value,
}

#[derive(Serialize)]
pub struct SessionOut {
    user: UserOut,
}

#[derive(Serialize)]
pub struct MessageOut {
    pub message: String,
}

#[derive(Deserialize)]
pub struct AttributesBody {
    attributes: Vec<String>,
}

/// An authenticated session.
pub struct Session {
    pub user_id: Uuid,
    pub role: String,
    csrf_hash: String,
}

impl Session {
    pub fn require_admin(&self) -> Result<(), AppError> {
        if self.role == "admin" {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

pub async fn hash_password(password: String) -> Result<String, AppError> {
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))
    })
    .await
    .map_err(|e| AppError::Internal(e.into()))?
    .map_err(AppError::Internal)
}

/// A valid hash of a random password; verifying against it costs the same as a real check.
pub fn make_dummy_hash() -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(random_token().as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("dummy hash failed: {e}"))
}

async fn verify_password(password: String, hash: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .ok()
            .map(|p| Argon2::default().verify_password(password.as_bytes(), &p).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

fn session_cookie(s: &AppState, name: &'static str, value: String, http_only: bool) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .http_only(http_only)
        .secure(s.cfg.cookie_secure())
        .same_site(SameSite::Strict)
        .build()
}

async fn create_session(s: &AppState, jar: CookieJar, user_id: Uuid) -> Result<(CookieJar, UserOut), AppError> {
    let token = random_token();
    let csrf = random_token();
    let expires = Utc::now() + Duration::hours(s.cfg.session_ttl_hours);
    sqlx::query("INSERT INTO sessions (id, token_hash, user_id, csrf_hash, expires_at) VALUES ($1,$2,$3,$4,$5)")
        .bind(Uuid::new_v4())
        .bind(hash_token(&token))
        .bind(user_id)
        .bind(hash_token(&csrf))
        .bind(expires)
        .execute(&s.db)
        .await?;
    let jar = jar
        .add(session_cookie(s, SESSION_COOKIE, token, true))
        // Readable by the SPA: double-submit CSRF token.
        .add(session_cookie(s, CSRF_COOKIE, csrf, false));
    let user = get_user(s, user_id).await?;
    Ok((jar, user))
}

async fn get_user(s: &AppState, id: Uuid) -> Result<UserOut, AppError> {
    let row: Option<(Uuid, String, String, String, Value)> =
        sqlx::query_as("SELECT id, email, display_name, role, attributes FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&s.db)
            .await?;
    let (id, email, display_name, role, attributes) = row.ok_or(AppError::NotFound)?;
    Ok(UserOut { id, email, display_name, role, attributes })
}

pub async fn authenticate(s: &AppState, jar: &CookieJar) -> Result<Session, AppError> {
    let token = jar.get(SESSION_COOKIE).map(|c| c.value().to_string()).ok_or(AppError::Unauthorized)?;
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        "SELECT s.user_id, u.role, s.csrf_hash FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(hash_token(&token))
    .fetch_optional(&s.db)
    .await?;
    let (user_id, role, csrf_hash) = row.ok_or(AppError::Unauthorized)?;
    Ok(Session { user_id, role, csrf_hash })
}

/// Authenticate and verify the double-submit CSRF token (required for every state change).
pub async fn authenticate_csrf(s: &AppState, jar: &CookieJar, headers: &HeaderMap) -> Result<Session, AppError> {
    let session = authenticate(s, jar).await?;
    let supplied = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Forbidden)?;
    if !ct_eq_str(&hash_token(supplied), &session.csrf_hash) {
        return Err(AppError::Forbidden);
    }
    Ok(session)
}

fn validate_display_name(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty() || name.chars().count() > 80 || name.chars().any(|c| c.is_control()) {
        None
    } else {
        Some(name.to_string())
    }
}

pub async fn register(
    State(s): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<AuthBody>,
) -> Result<(CookieJar, Json<SessionOut>), AppError> {
    let ip = client_ip(&headers, peer, s.cfg.trust_proxy);
    s.limiter.check(&format!("register:{ip}"), 10, StdDuration::from_secs(3600))?;

    let email = normalize_email(&body.email).ok_or_else(|| AppError::bad("Enter a valid email address"))?;
    if body.password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AppError::bad("Use a password of at least 12 characters"));
    }
    if body.password.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::bad("The password is too long"));
    }
    let display = validate_display_name(body.display_name.as_deref().unwrap_or(""))
        .ok_or_else(|| AppError::bad("Enter a name (up to 80 characters)"))?;
    let hash = hash_password(body.password).await?;

    let mut tx = s.db.begin().await?;
    // Serialize registrations so that two simultaneous first registrations cannot both become admin.
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(REGISTER_LOCK_ID).execute(&mut *tx).await?;
    let admins: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE role = 'admin'")
        .fetch_one(&mut *tx)
        .await?;
    let make_admin = admins == 0
        && match &s.cfg.admin_email {
            Some(allowed) => allowed == &email,
            None => true,
        };
    let role = if make_admin { "admin" } else { "user" };

    let inserted = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users (id, email, password_hash, display_name, role, attributes) \
         VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(&email)
    .bind(hash)
    .bind(display)
    .bind(role)
    .bind(json!(["clearance>=1", "department=general", "role=member"]))
    .fetch_one(&mut *tx)
    .await;
    let id = match inserted {
        Ok(id) => id,
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
            return Err(AppError::Conflict)
        }
        Err(e) => return Err(e.into()),
    };
    tx.commit().await?;

    if make_admin {
        tracing::warn!(email = %email, "first administrator account created");
    }
    let (jar, user) = create_session(&s, jar, id).await?;
    s.audit(Some(id), None, "user.registered", json!({ "role": role })).await;
    Ok((jar, Json(SessionOut { user })))
}

pub async fn login(
    State(s): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<AuthBody>,
) -> Result<(CookieJar, Json<SessionOut>), AppError> {
    let ip = client_ip(&headers, peer, s.cfg.trust_proxy);
    let window = StdDuration::from_secs(900);
    s.limiter.check(&format!("login-ip:{ip}"), 30, window)?;
    let email = body.email.trim().to_ascii_lowercase();
    s.limiter.check(&format!("login-email:{email}"), 10, window)?;
    if body.password.len() > MAX_PASSWORD_BYTES || email.len() > 254 {
        return Err(AppError::Unauthorized);
    }

    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE lower(email) = $1")
            .bind(&email)
            .fetch_optional(&s.db)
            .await?;
    // Unknown accounts still pay for one Argon2 verification so timing does not reveal them.
    let (id, hash) = match row {
        Some((id, hash)) => (Some(id), hash),
        None => (None, (*s.dummy_hash).clone()),
    };
    let ok = verify_password(body.password, hash).await;
    let id = match (ok, id) {
        (true, Some(id)) => id,
        _ => {
            s.audit(None, None, "user.login_failed", json!({})).await;
            return Err(AppError::Unauthorized);
        }
    };
    let (jar, user) = create_session(&s, jar, id).await?;
    s.audit(Some(id), None, "user.login", json!({})).await;
    Ok((jar, Json(SessionOut { user })))
}

pub async fn logout(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<(CookieJar, Json<MessageOut>), AppError> {
    let session = authenticate_csrf(&s, &jar, &headers).await?;
    if let Some(c) = jar.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(hash_token(c.value()))
            .execute(&s.db)
            .await?;
    }
    s.audit(Some(session.user_id), None, "user.logout", json!({})).await;
    let jar = jar
        .remove(Cookie::build((SESSION_COOKIE, "")).path("/").build())
        .remove(Cookie::build((CSRF_COOKIE, "")).path("/").build());
    Ok((jar, Json(MessageOut { message: "Logged out".into() })))
}

pub async fn me(State(s): State<AppState>, jar: CookieJar) -> Result<Json<UserOut>, AppError> {
    let session = authenticate(&s, &jar).await?;
    Ok(Json(get_user(&s, session.user_id).await?))
}

pub async fn admin_list_users(State(s): State<AppState>, jar: CookieJar) -> Result<Json<Vec<UserOut>>, AppError> {
    let session = authenticate(&s, &jar).await?;
    session.require_admin()?;
    let rows: Vec<(Uuid, String, String, String, Value)> = sqlx::query_as(
        "SELECT id, email, display_name, role, attributes FROM users ORDER BY created_at LIMIT 500",
    )
    .fetch_all(&s.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, email, display_name, role, attributes)| UserOut { id, email, display_name, role, attributes })
            .collect(),
    ))
}

pub async fn admin_attributes(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<AttributesBody>,
) -> Result<Json<UserOut>, AppError> {
    let session = authenticate_csrf(&s, &jar, &headers).await?;
    session.require_admin()?;
    if body.attributes.len() > MAX_ATTRIBUTES_PER_USER {
        return Err(AppError::bad("Too many attributes"));
    }
    let mut normalized: Vec<String> = Vec::new();
    for raw in &body.attributes {
        let id = veyra_core::normalize_attribute(raw)
            .map_err(|_| AppError::bad("Invalid attribute. Use clearance>=N, department=x, role=x, project=x or organization=x"))?;
        if !normalized.contains(&id) {
            normalized.push(id);
        }
    }
    let result = sqlx::query("UPDATE users SET attributes = $1 WHERE id = $2")
        .bind(json!(normalized))
        .bind(id)
        .execute(&s.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    s.audit(
        Some(session.user_id),
        None,
        "admin.attributes_updated",
        json!({ "target_user": id, "attributes": normalized }),
    )
    .await;
    Ok(Json(get_user(&s, id).await?))
}
