use crate::{
    access_middleware::require_access_jwt,
    auth::AuthenticatedUser,
    certificate::{CertRequest, CertificateProfile, issue_certificate},
    error::{ApiError, internal_error},
    state::AppState,
};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Response, StatusCode, header},
    middleware,
    routing::{get, post},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
use tower_http::services::ServeDir;

pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/request-cert", post(request_and_download_cert))
        .route("/api/vpn/ca-certificate", get(download_vpn_ca_certificate))
        .route("/api/vpn/request-cert", post(request_and_download_vpn_cert))
        .fallback_service(ServeDir::new("static"))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_access_jwt,
        ))
        .with_state(state)
}

async fn download_vpn_ca_certificate(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let started = Instant::now();
    let request_id = state.request_sequence.fetch_add(1, Ordering::Relaxed);
    let client_ip = client_ip(&headers, peer.ip(), state.config.trust_forwarded_for);

    tracing::info!(
        audit = true,
        request_id,
        client_ip = %client_ip,
        peer_ip = %peer.ip(),
        authenticated_email = %user.email,
        authenticated_subject = %user.subject,
        "vpn_ca_download_requested"
    );

    let certificate = match tokio::fs::read(&state.config.vpn_ca.root).await {
        Ok(certificate) => certificate,
        Err(error) => {
            tracing::error!(
                audit = true,
                request_id,
                client_ip = %client_ip,
                authenticated_email = %user.email,
                status = 500,
                error = %error,
                duration_ms = started.elapsed().as_millis() as u64,
                "vpn_ca_download_failed"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "CA certificate read failed".to_string(),
            ));
        }
    };

    let certificate_size = certificate.len();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-pem-file")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=vpn-ca-certificate.crt",
        )
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(certificate))
        .map_err(internal_error("Response creation failed"));

    if response.is_ok() {
        tracing::info!(
            audit = true,
            request_id,
            client_ip = %client_ip,
            authenticated_email = %user.email,
            status = 200,
            certificate_size,
            duration_ms = started.elapsed().as_millis() as u64,
            "vpn_ca_download_succeeded"
        );
    }

    response
}

async fn request_and_download_cert(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CertRequest>,
) -> Result<Response<Body>, ApiError> {
    request_certificate(
        state,
        user,
        peer,
        headers,
        payload,
        CertificateProfile::Wpa3,
    )
    .await
}

async fn request_and_download_vpn_cert(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CertRequest>,
) -> Result<Response<Body>, ApiError> {
    request_certificate(state, user, peer, headers, payload, CertificateProfile::Vpn).await
}

async fn request_certificate(
    state: Arc<AppState>,
    user: AuthenticatedUser,
    peer: SocketAddr,
    headers: HeaderMap,
    payload: CertRequest,
    profile: CertificateProfile,
) -> Result<Response<Body>, ApiError> {
    let started = Instant::now();
    let request_id = state.request_sequence.fetch_add(1, Ordering::Relaxed);
    let client_ip = client_ip(&headers, peer.ip(), state.config.trust_forwarded_for);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    let requested_common_name = payload.common_name.trim().to_owned();

    tracing::info!(
        audit = true,
        request_id,
        client_ip = %client_ip,
        peer_ip = %peer.ip(),
        user_agent,
        common_name = %requested_common_name,
        authenticated_email = %user.email,
        authenticated_subject = %user.subject,
        certificate_profile = profile.audit_name(),
        "certificate_request_received"
    );

    let result = issue_certificate(&state.config, payload, profile).await;
    match &result {
        Ok(_) => tracing::info!(
            audit = true,
            request_id,
            client_ip = %client_ip,
            common_name = %requested_common_name,
            authenticated_email = %user.email,
            authenticated_subject = %user.subject,
            certificate_profile = profile.audit_name(),
            status = 200,
            duration_ms = started.elapsed().as_millis() as u64,
            "certificate_issued"
        ),
        Err((status, message)) => tracing::warn!(
            audit = true,
            request_id,
            client_ip = %client_ip,
            common_name = %requested_common_name,
            authenticated_email = %user.email,
            authenticated_subject = %user.subject,
            certificate_profile = profile.audit_name(),
            status = status.as_u16(),
            error = message,
            duration_ms = started.elapsed().as_millis() as u64,
            "certificate_request_failed"
        ),
    }
    result
}

fn client_ip(headers: &HeaderMap, peer_ip: IpAddr, trust_forwarded_for: bool) -> IpAddr {
    if !trust_forwarded_for {
        return peer_ip;
    }

    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(peer_ip)
}
