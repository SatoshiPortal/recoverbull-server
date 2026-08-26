//! HTTP error response construction and retry metadata.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

pub(crate) fn error_body(error: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "error": error.into() })
}

pub(crate) fn retry_after_response(
    status: StatusCode,
    retry_after_secs: u64,
    error: impl Into<String>,
) -> Response {
    let mut response = (status, Json(error_body(error))).into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after_secs.to_string())
            .expect("a stringified non-negative integer is a valid header value"),
    );
    response
}
