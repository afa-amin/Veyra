use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use tracing::error;
use veyra_core::VeyraError;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    /// The message is always a curated static string, never user input or internals.
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("conflict")]
    Conflict,
    #[error("too many requests")]
    TooManyRequests,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl AppError {
    pub fn bad(msg: &str) -> Self {
        AppError::BadRequest(msg.to_string())
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Internal(e.into())
    }
}

impl From<VeyraError> for AppError {
    fn from(e: VeyraError) -> Self {
        match e {
            VeyraError::AccessDenied => AppError::Forbidden,
            VeyraError::InvalidPolicy(_) | VeyraError::UnknownAttribute(_) => {
                AppError::bad("Invalid access requirements")
            }
            other => AppError::Internal(other.into()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", "Authentication is required".to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "Access denied".to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found", "Not found".to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.clone()),
            AppError::Conflict => (StatusCode::CONFLICT, "conflict", "The resource already exists".to_string()),
            AppError::TooManyRequests => (
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_requests",
                "Too many attempts. Please wait and try again later.".to_string(),
            ),
            AppError::Internal(e) => {
                error!(error = ?e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", "Something went wrong".to_string())
            }
        };
        let mut resp = (status, Json(json!({ "error": code, "message": message }))).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        resp
    }
}
