use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde::Serialize;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("conflict")]
    Conflict,
    #[error("internal error")]
    Internal(#[source] anyhow::Error),
}
impl From<sqlx::Error> for AppError { fn from(e: sqlx::Error) -> Self { error!(error=%e,"database error"); Self::Internal(e.into()) } }
impl From<std::io::Error> for AppError { fn from(e: std::io::Error) -> Self { error!(error=%e,"io error"); Self::Internal(e.into()) } }
impl From<veyra_core::SecureDropError> for AppError { fn from(e: veyra_core::SecureDropError) -> Self { error!(error=%e,"crypto error"); Self::Internal(e.into()) } }
impl From<anyhow::Error> for AppError { fn from(e: anyhow::Error) -> Self { error!(error=%e,"application error"); Self::Internal(e) } }
#[derive(Serialize)] struct Body { error: &'static str, message: &'static str }
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, msg) = match self { Self::Unauthorized => (StatusCode::UNAUTHORIZED,"unauthorized","Authentication required"), Self::Forbidden => (StatusCode::FORBIDDEN,"forbidden","Access denied"), Self::NotFound => (StatusCode::NOT_FOUND,"not_found","Resource not found"), Self::BadRequest(_) => (StatusCode::BAD_REQUEST,"bad_request","The request could not be processed"), Self::Conflict => (StatusCode::CONFLICT,"conflict","The requested resource already exists"), Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR,"internal_error","We couldn't complete this request") };
        (status, Json(Body { error: code, message: msg })).into_response()
    }
}
