//! HTTP 라우터와 핸들러. 모든 경로는 인증 미들웨어 뒤에 있고, 발급과 다운로드는 감사
//! 로그(`audit = true`)에 남습니다.

use crate::{
    access_middleware::require_access_jwt,
    auth::AuthenticatedUser,
    certificate::{CertRequest, CertificateProfile, issue_certificate},
    error::{ApiError, INTERNAL_ERROR_MESSAGE, internal_error, with_request_id},
    state::AppState,
};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, header},
    middleware,
    routing::{get, post},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};
use tower_http::{services::ServeDir, set_header::SetResponseHeaderLayer};

/// 발급 요청 본문은 기기 이름과 비밀번호뿐이므로 작게 제한합니다.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024;
/// 감사 로그에 남기는 사용자 입력의 최대 길이입니다.
const MAX_LOGGED_INPUT_CHARS: usize = 253;

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
    form-action 'self'";

pub(crate) fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/request-cert", post(request_and_download_cert))
        .route("/api/vpn/ca-certificate", get(download_vpn_ca_certificate))
        .route("/api/vpn/request-cert", post(request_and_download_vpn_cert))
        .fallback_service(ServeDir::new("static"))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_access_jwt,
        ))
        // 인증 실패 응답을 포함한 모든 응답에 붙도록 가장 바깥에 둡니다.
        .layer(security_header(
            header::CONTENT_SECURITY_POLICY,
            CONTENT_SECURITY_POLICY,
        ))
        .layer(security_header(header::X_FRAME_OPTIONS, "DENY"))
        .layer(security_header(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(security_header(header::REFERRER_POLICY, "no-referrer"))
        .with_state(state)
}

fn security_header(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
}

/// 감사 로그에 공통으로 남기는 요청 정보입니다.
struct RequestContext {
    request_id: String,
    client_ip: IpAddr,
    peer_ip: IpAddr,
    user_agent: String,
    user: AuthenticatedUser,
    started: Instant,
}

impl RequestContext {
    fn new(
        state: &AppState,
        user: AuthenticatedUser,
        peer: SocketAddr,
        headers: &HeaderMap,
    ) -> Self {
        let user_agent = headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map_or_else(|| "unknown".to_string(), truncate_for_log);
        Self {
            request_id: state.next_request_id(),
            client_ip: client_ip(headers, peer.ip(), state.config.trust_forwarded_for),
            peer_ip: peer.ip(),
            user_agent,
            user,
            started: Instant::now(),
        }
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

async fn download_vpn_ca_certificate(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response<Body>, ApiError> {
    let context = RequestContext::new(&state, user, peer, &headers);
    tracing::info!(
        audit = true,
        request_id = %context.request_id,
        client_ip = %context.client_ip,
        peer_ip = %context.peer_ip,
        user_agent = %context.user_agent,
        authenticated_email = %context.user.email,
        authenticated_subject = %context.user.subject,
        "vpn_ca_download_requested"
    );

    let result = match tokio::fs::read(&state.config.vpn_ca.root).await {
        Ok(certificate) => {
            let size = certificate.len();
            attachment(
                "application/x-pem-file",
                "vpn-ca-certificate.crt",
                certificate,
            )
            .map(|response| (response, size))
        }
        Err(error) => {
            tracing::error!(request_id = %context.request_id, error = %error, "vpn_ca_read_failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR_MESSAGE.to_string(),
            ))
        }
    };

    match result {
        Ok((response, certificate_size)) => {
            tracing::info!(
                audit = true,
                request_id = %context.request_id,
                client_ip = %context.client_ip,
                authenticated_email = %context.user.email,
                authenticated_subject = %context.user.subject,
                status = 200,
                certificate_size,
                duration_ms = context.elapsed_ms(),
                "vpn_ca_download_succeeded"
            );
            Ok(response)
        }
        Err(error) => {
            let (status, message) = with_request_id(error, &context.request_id);
            tracing::warn!(
                audit = true,
                request_id = %context.request_id,
                client_ip = %context.client_ip,
                authenticated_email = %context.user.email,
                authenticated_subject = %context.user.subject,
                status = status.as_u16(),
                duration_ms = context.elapsed_ms(),
                "vpn_ca_download_failed"
            );
            Err((status, message))
        }
    }
}

async fn request_and_download_cert(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<CertRequest>, JsonRejection>,
) -> Result<Response<Body>, ApiError> {
    let context = RequestContext::new(&state, user, peer, &headers);
    request_certificate(&state, context, payload, CertificateProfile::Wpa3).await
}

async fn request_and_download_vpn_cert(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    payload: Result<Json<CertRequest>, JsonRejection>,
) -> Result<Response<Body>, ApiError> {
    let context = RequestContext::new(&state, user, peer, &headers);
    request_certificate(&state, context, payload, CertificateProfile::Vpn).await
}

async fn request_certificate(
    state: &AppState,
    context: RequestContext,
    payload: Result<Json<CertRequest>, JsonRejection>,
    profile: CertificateProfile,
) -> Result<Response<Body>, ApiError> {
    let requested_common_name = payload
        .as_ref()
        .map(|Json(request)| truncate_for_log(request.common_name.trim()))
        .unwrap_or_default();

    tracing::info!(
        audit = true,
        request_id = %context.request_id,
        client_ip = %context.client_ip,
        peer_ip = %context.peer_ip,
        user_agent = %context.user_agent,
        common_name = %requested_common_name,
        authenticated_email = %context.user.email,
        authenticated_subject = %context.user.subject,
        certificate_profile = profile.audit_name(),
        "certificate_request_received"
    );

    let result = issue(state, &context, payload, profile).await;
    match &result {
        Ok(_) => tracing::info!(
            audit = true,
            request_id = %context.request_id,
            client_ip = %context.client_ip,
            common_name = %requested_common_name,
            authenticated_email = %context.user.email,
            authenticated_subject = %context.user.subject,
            certificate_profile = profile.audit_name(),
            status = 200,
            duration_ms = context.elapsed_ms(),
            "certificate_issued"
        ),
        Err((status, message)) => tracing::warn!(
            audit = true,
            request_id = %context.request_id,
            client_ip = %context.client_ip,
            common_name = %requested_common_name,
            authenticated_email = %context.user.email,
            authenticated_subject = %context.user.subject,
            certificate_profile = profile.audit_name(),
            status = status.as_u16(),
            error = %message,
            duration_ms = context.elapsed_ms(),
            "certificate_request_failed"
        ),
    }
    result
}

async fn issue(
    state: &AppState,
    context: &RequestContext,
    payload: Result<Json<CertRequest>, JsonRejection>,
    profile: CertificateProfile,
) -> Result<Response<Body>, ApiError> {
    let Json(payload) = payload.map_err(|rejection| {
        tracing::debug!(request_id = %context.request_id, error = %rejection, "invalid_request_body");
        (
            StatusCode::BAD_REQUEST,
            "요청 형식이 올바르지 않습니다".to_string(),
        )
    })?;

    // 슬롯이 없으면 기다리지 않고 바로 거절합니다. 슬롯은 응답이 만들어질 때까지 유지됩니다.
    let Ok(_slot) = state.issuance_slots.clone().try_acquire_owned() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "다른 발급 요청이 처리 중입니다. 잠시 후 다시 시도하세요".to_string(),
        ));
    };

    let issued = issue_certificate(&state.config, payload, profile)
        .await
        .map_err(|error| with_request_id(error, &context.request_id))?;
    attachment("application/x-pkcs12", &issued.filename, issued.pkcs12)
        .map_err(|error| with_request_id(error, &context.request_id))
}

/// 캐시하지 않는 첨부 파일 응답을 만듭니다. `filename`은 검증된 ASCII 값이어야 합니다.
fn attachment(
    content_type: &'static str,
    filename: &str,
    body: Vec<u8>,
) -> Result<Response<Body>, ApiError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .map_err(internal_error("Response creation failed"))
}

fn truncate_for_log(value: &str) -> String {
    value.chars().take(MAX_LOGGED_INPUT_CHARS).collect()
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
