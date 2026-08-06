use axum::http::StatusCode;

pub(crate) type ApiError = (StatusCode, String);

pub(crate) fn internal_error<E: std::fmt::Display>(
    context: &'static str,
) -> impl FnOnce(E) -> ApiError {
    move |error| {
        tracing::error!(context, error = %error, "internal_error");
        (StatusCode::INTERNAL_SERVER_ERROR, context.to_string())
    }
}
