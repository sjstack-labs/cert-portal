use crate::{auth::AuthenticatedUser, state::AppState};
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, Response, StatusCode, header},
    middleware::Next,
    response::IntoResponse,
};
use std::{net::SocketAddr, sync::Arc};

pub(crate) async fn require_access_jwt(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let request_method = request.method().clone();
    let request_path = request.uri().path().to_owned();

    if let Some(allow_non_loopback) = state.authentication.local_allow_non_loopback() {
        let is_loopback = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|peer| peer.0.ip().is_loopback());
        if !allow_non_loopback && !is_loopback {
            tracing::warn!(
                audit = true,
                method = %request_method,
                path = %request_path,
                "non_loopback_development_request_rejected"
            );
            return unauthorized_response();
        }
        request.extensions_mut().insert(AuthenticatedUser {
            email: "local-development@localhost".to_string(),
            subject: "local-development".to_string(),
        });
        return next.run(request).await;
    }

    let token = request
        .headers()
        .get("cf-access-jwt-assertion")
        .and_then(|value| value.to_str().ok());
    let Some(token) = token else {
        tracing::warn!(
            audit = true,
            method = %request_method,
            path = %request_path,
            "access_jwt_missing"
        );
        return unauthorized_response();
    };

    match state.authentication.authenticate(token).await {
        Ok(user) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(reason) => {
            tracing::warn!(
                audit = true,
                method = %request_method,
                path = %request_path,
                reason,
                "access_jwt_rejected"
            );
            unauthorized_response()
        }
    }
}

fn unauthorized_response() -> Response<Body> {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        "Cloudflare Access 인증이 필요합니다",
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}
