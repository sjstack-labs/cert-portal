//! API 오류 형식입니다. 내부 원인은 로그에만 남기고 응답에는 고정 문구만 보냅니다.

use axum::http::StatusCode;

pub(crate) type ApiError = (StatusCode, String);

pub(crate) const INTERNAL_ERROR_MESSAGE: &str = "내부 오류가 발생했습니다";

/// 내부 오류를 `context`와 함께 로그에 남기고, 응답에는 고정 문구를 돌려줍니다.
pub(crate) fn internal_error<E: std::fmt::Display>(
    context: &'static str,
) -> impl FnOnce(E) -> ApiError {
    move |error| {
        tracing::error!(context, error = %error, "internal_error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            INTERNAL_ERROR_MESSAGE.to_string(),
        )
    }
}

/// 서버 오류 응답에 요청 ID를 붙여, 사용자가 알려준 ID로 로그를 찾을 수 있게 합니다.
pub(crate) fn with_request_id((status, message): ApiError, request_id: &str) -> ApiError {
    if status.is_server_error() {
        (status, format!("{message} (요청 ID: {request_id})"))
    } else {
        (status, message)
    }
}
