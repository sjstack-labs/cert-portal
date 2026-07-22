use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, Response, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
    routing::post,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, Ia5String, KeyPair, KeyUsagePurpose};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tempfile::tempdir;
use tokio::{
    net::TcpListener,
    process::Command,
    sync::{Mutex, RwLock},
};
use tower_http::services::ServeDir;

struct AppState {
    authentication: Authentication,
    step_binary: String,
    step_ca_url: String,
    step_ca_root: PathBuf,
    step_ca_provisioner: String,
    step_ca_provisioner_password_file: PathBuf,
    trust_forwarded_for: bool,
    request_sequence: AtomicU64,
}

impl AppState {
    async fn from_env(environment: AppEnvironment) -> Result<Self, String> {
        let step_ca_root = required_env_path("STEP_CA_ROOT")?;
        let step_ca_provisioner_password_file =
            required_env_path("STEP_CA_PROVISIONER_PASSWORD_FILE")?;
        std::fs::metadata(&step_ca_root)
            .map_err(|e| format!("STEP_CA_ROOT 파일을 읽을 수 없습니다: {e}"))?;

        // 시작할 때 비밀번호 파일의 존재 여부만 검사합니다. 내용은 step CLI만 읽습니다.
        std::fs::metadata(&step_ca_provisioner_password_file)
            .map_err(|e| format!("STEP_CA_PROVISIONER_PASSWORD_FILE을 읽을 수 없습니다: {e}"))?;

        Ok(Self {
            authentication: match environment {
                AppEnvironment::Production => {
                    Authentication::Cloudflare(Box::new(AccessJwtValidator::from_env().await?))
                }
                AppEnvironment::Development => Authentication::LocalDevelopment,
            },
            step_binary: std::env::var("STEP_BINARY").unwrap_or_else(|_| "step".to_string()),
            step_ca_url: required_env("STEP_CA_URL")?,
            step_ca_root,
            step_ca_provisioner: required_env("STEP_CA_PROVISIONER")?,
            step_ca_provisioner_password_file,
            trust_forwarded_for: env_flag("TRUST_FORWARDED_FOR"),
            request_sequence: AtomicU64::new(1),
        })
    }
}

#[derive(Clone, Copy, PartialEq)]
enum AppEnvironment {
    Development,
    Production,
}

impl AppEnvironment {
    fn from_env() -> Result<Self, String> {
        match required_env("APP_ENV")?.as_str() {
            "development" => Ok(Self::Development),
            "production" => Ok(Self::Production),
            value => Err(format!(
                "APP_ENV는 development 또는 production이어야 합니다: {value}"
            )),
        }
    }

    fn default_bind_address(self) -> &'static str {
        match self {
            Self::Development => "127.0.0.1:3000",
            Self::Production => "0.0.0.0:3000",
        }
    }
}

enum Authentication {
    Cloudflare(Box<AccessJwtValidator>),
    LocalDevelopment,
}

struct AccessJwtValidator {
    issuer: String,
    audience: String,
    certs_url: String,
    client: reqwest::Client,
    jwks: RwLock<JwkSet>,
    last_refresh: Mutex<tokio::time::Instant>,
}

#[derive(Clone)]
struct AuthenticatedUser {
    email: String,
    subject: String,
}

#[derive(Deserialize)]
struct AccessClaims {
    email: String,
    sub: String,
    exp: u64,
}

impl AccessJwtValidator {
    async fn from_env() -> Result<Self, String> {
        let issuer = required_env("CF_ACCESS_ISSUER")?
            .trim_end_matches('/')
            .to_string();
        if !issuer.starts_with("https://") {
            return Err("CF_ACCESS_ISSUER는 https:// URL이어야 합니다".to_string());
        }
        let audience = required_env("CF_ACCESS_AUDIENCE")?;
        let certs_url = format!("{issuer}/cdn-cgi/access/certs");
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Cloudflare Access HTTP client 생성 실패: {e}"))?;
        let jwks = fetch_jwks(&client, &certs_url).await?;

        Ok(Self {
            issuer,
            audience,
            certs_url,
            client,
            jwks: RwLock::new(jwks),
            last_refresh: Mutex::new(
                tokio::time::Instant::now() - std::time::Duration::from_secs(60),
            ),
        })
    }

    async fn authenticate(&self, token: &str) -> Result<AuthenticatedUser, &'static str> {
        let header = decode_header(token).map_err(|_| "invalid JWT header")?;
        if header.alg != Algorithm::RS256 {
            return Err("unsupported JWT algorithm");
        }
        let kid = header.kid.ok_or("JWT has no key ID")?;

        let mut key = self.decoding_key(&kid).await;
        if key.is_none() {
            // Cloudflare가 서명 키를 교체했을 수 있으므로 모르는 kid일 때 갱신합니다.
            // 임의 kid를 사용한 요청이 JWKS endpoint를 과도하게 호출하지 않도록 제한합니다.
            let mut last_refresh = self.last_refresh.lock().await;
            if self.decoding_key(&kid).await.is_none()
                && last_refresh.elapsed() >= std::time::Duration::from_secs(60)
            {
                *last_refresh = tokio::time::Instant::now();
                let refreshed = fetch_jwks(&self.client, &self.certs_url)
                    .await
                    .map_err(|_| "unable to refresh signing keys")?;
                *self.jwks.write().await = refreshed;
            }
            key = self.decoding_key(&kid).await;
        }
        let key = key.ok_or("unknown JWT key ID")?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = decode::<AccessClaims>(token, &key, &validation)
            .map_err(|_| "JWT validation failed")?
            .claims;
        if claims.email.trim().is_empty() || claims.sub.trim().is_empty() || claims.exp == 0 {
            return Err("JWT identity claims are missing");
        }

        Ok(AuthenticatedUser {
            email: claims.email,
            subject: claims.sub,
        })
    }

    async fn decoding_key(&self, kid: &str) -> Option<DecodingKey> {
        let jwks = self.jwks.read().await;
        jwks.find(kid)
            .and_then(|jwk| DecodingKey::from_jwk(jwk).ok())
    }
}

async fn fetch_jwks(client: &reqwest::Client, url: &str) -> Result<JwkSet, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Cloudflare Access 공개 키 조회 실패: {e}"))?
        .error_for_status()
        .map_err(|e| format!("Cloudflare Access 공개 키 응답 오류: {e}"))?;
    let jwks = response
        .json::<JwkSet>()
        .await
        .map_err(|e| format!("Cloudflare Access 공개 키 형식 오류: {e}"))?;
    if jwks.keys.is_empty() {
        return Err("Cloudflare Access 공개 키 목록이 비어 있습니다".to_string());
    }
    Ok(jwks)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("필수 환경 변수 {name}가 설정되지 않았습니다"))
}

fn required_env_path(name: &str) -> Result<PathBuf, String> {
    required_env(name).map(PathBuf::from)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "eap_tls_cert_portal=info".into()),
        )
        .with_current_span(false)
        .init();

    let environment = AppEnvironment::from_env().unwrap_or_else(|e| {
        tracing::error!(error = %e, "configuration_error");
        std::process::exit(1);
    });
    if environment == AppEnvironment::Development {
        tracing::warn!(audit = true, "local_development_authentication_enabled");
    }
    let state = Arc::new(AppState::from_env(environment).await.unwrap_or_else(|e| {
        tracing::error!(error = %e, "configuration_error");
        std::process::exit(1);
    }));

    let app = Router::new()
        .route("/api/request-cert", post(request_and_download_cert))
        .fallback_service(ServeDir::new("static"))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_access_jwt,
        ))
        .with_state(state);

    let addr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| environment.default_bind_address().to_string())
        .parse::<SocketAddr>()
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "invalid_bind_address");
            std::process::exit(1);
        });
    if environment == AppEnvironment::Development && !addr.ip().is_loopback() {
        tracing::error!(address = %addr, "development_mode_requires_loopback_bind_address");
        std::process::exit(1);
    }
    let listener = TcpListener::bind(addr).await.unwrap();
    tracing::info!(address = %listener.local_addr().unwrap(), "server_started");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

async fn require_access_jwt(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response<Body> {
    if matches!(state.authentication, Authentication::LocalDevelopment) {
        let is_loopback = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|peer| peer.0.ip().is_loopback());
        if !is_loopback {
            tracing::warn!(audit = true, "non_loopback_development_request_rejected");
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
        tracing::warn!(audit = true, "access_jwt_missing");
        return unauthorized_response();
    };

    let Authentication::Cloudflare(access_jwt) = &state.authentication else {
        unreachable!("development authentication returned above")
    };
    match access_jwt.authenticate(token).await {
        Ok(user) => {
            request.extensions_mut().insert(user);
            next.run(request).await
        }
        Err(reason) => {
            tracing::warn!(audit = true, reason, "access_jwt_rejected");
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

#[derive(Deserialize)]
struct CertRequest {
    common_name: String,
    p12_password: String,
}

async fn request_and_download_cert(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CertRequest>,
) -> Result<Response<Body>, (StatusCode, String)> {
    let started = Instant::now();
    let request_id = state.request_sequence.fetch_add(1, Ordering::Relaxed);
    let client_ip = client_ip(&headers, peer.ip(), state.trust_forwarded_for);
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
        "certificate_request_received"
    );

    let result = issue_certificate(&state, payload).await;
    match &result {
        Ok(_) => tracing::info!(
            audit = true,
            request_id,
            client_ip = %client_ip,
            common_name = %requested_common_name,
            authenticated_email = %user.email,
            authenticated_subject = %user.subject,
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
            status = status.as_u16(),
            error = message,
            duration_ms = started.elapsed().as_millis() as u64,
            "certificate_request_failed"
        ),
    }
    result
}

async fn issue_certificate(
    state: &AppState,
    payload: CertRequest,
) -> Result<Response<Body>, (StatusCode, String)> {
    let common_name = validate_common_name(&payload.common_name)?;
    let p12_password = validate_p12_password(&payload.p12_password)?;

    // 이 서비스는 리프 개인키와 CSR만 생성합니다. CA 키를 보유하거나 서명하지 않습니다.
    let client_key_pair =
        KeyPair::generate().map_err(internal_error("Client key generation failed"))?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let san_name = Ia5String::try_from(common_name.to_string()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("유효하지 않은 기기 이름: {e}"),
        )
    })?;
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName(san_name));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let csr_pem = params
        .serialize_request(&client_key_pair)
        .map_err(internal_error("CSR generation failed"))?
        .pem()
        .map_err(internal_error("CSR encoding failed"))?;

    let work_dir = tempdir().map_err(internal_error("Temporary directory creation failed"))?;
    let csr_path = work_dir.path().join("client.csr");
    let cert_path = work_dir.path().join("client.crt");
    let key_path = work_dir.path().join("client.key");
    let password_path = work_dir.path().join("p12-password");
    let p12_path = work_dir.path().join("client.p12");
    tokio::fs::write(&csr_path, csr_pem)
        .await
        .map_err(internal_error("CSR write failed"))?;
    tokio::fs::write(&key_path, client_key_pair.serialize_pem())
        .await
        .map_err(internal_error("Client key write failed"))?;
    tokio::fs::write(&password_path, p12_password)
        .await
        .map_err(internal_error("PKCS#12 password write failed"))?;

    // step CLI가 전용 JWK Provisioner로 OTT를 내부 생성하고 step-ca에 CSR을 전송합니다.
    let output = Command::new(&state.step_binary)
        .arg("ca")
        .arg("sign")
        .arg(&csr_path)
        .arg(&cert_path)
        .arg("--ca-url")
        .arg(&state.step_ca_url)
        .arg("--root")
        .arg(&state.step_ca_root)
        .arg("--provisioner")
        .arg(&state.step_ca_provisioner)
        .arg("--provisioner-password-file")
        .arg(&state.step_ca_provisioner_password_file)
        .output()
        .await
        .map_err(internal_error("step CLI execution failed"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(error = %stderr.trim(), "step_ca_signing_failed");
        return Err((
            StatusCode::BAD_GATEWAY,
            "step-ca가 인증서 발급을 거부했거나 응답하지 않았습니다".to_string(),
        ));
    }

    // Windows와 Android에서 바로 가져올 수 있도록 개인키, 클라이언트 인증서 체인,
    // Root CA를 사용자가 지정한 비밀번호로 암호화한 PKCS#12로 패키징합니다.
    let p12_output = Command::new(&state.step_binary)
        .arg("certificate")
        .arg("p12")
        .arg(&p12_path)
        .arg(&cert_path)
        .arg(&key_path)
        .arg("--ca")
        .arg(&state.step_ca_root)
        .arg("--password-file")
        .arg(&password_path)
        // 구형 Windows에서도 가져올 수 있는 PKCS#12 암호화 방식을 사용합니다.
        .arg("--legacy")
        .output()
        .await
        .map_err(internal_error("step PKCS#12 execution failed"))?;

    if !p12_output.status.success() {
        let stderr = String::from_utf8_lossy(&p12_output.stderr);
        tracing::error!(error = %stderr.trim(), "pkcs12_packaging_failed");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "인증서 패키지 생성에 실패했습니다".to_string(),
        ));
    }

    let p12 = tokio::fs::read(&p12_path)
        .await
        .map_err(internal_error("PKCS#12 read failed"))?;
    // Windows에서 인증서 가져오기 마법사와 안정적으로 연결되는 확장자입니다.
    // PFX와 P12는 동일한 PKCS#12 컨테이너 형식입니다.
    let filename = format!("{}.pfx", common_name.replace(' ', "_"));

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-pkcs12")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(p12))
        .map_err(internal_error("Response creation failed"))
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

fn validate_p12_password(value: &str) -> Result<&str, (StatusCode, String)> {
    if value.len() < 8 || value.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            "PKCS#12 비밀번호는 8~128자여야 합니다".to_string(),
        ));
    }
    if value.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err((
            StatusCode::BAD_REQUEST,
            "PKCS#12 비밀번호에 줄바꿈이나 NUL 문자를 사용할 수 없습니다".to_string(),
        ));
    }
    Ok(value)
}

fn validate_common_name(value: &str) -> Result<&str, (StatusCode, String)> {
    let value = value.trim();
    if value.is_empty() || value.len() > 253 {
        return Err((
            StatusCode::BAD_REQUEST,
            "기기 이름은 1~253자여야 합니다".to_string(),
        ));
    }
    if !value
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "기기 이름에는 영문자, 숫자, 점, 하이픈만 사용할 수 있습니다".to_string(),
        ));
    }
    Ok(value)
}

fn internal_error<E: std::fmt::Display>(
    context: &'static str,
) -> impl FnOnce(E) -> (StatusCode, String) {
    move |e| {
        tracing::error!(context, error = %e, "internal_error");
        (StatusCode::INTERNAL_SERVER_ERROR, context.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_common_name, validate_p12_password};

    #[test]
    fn accepts_device_dns_names() {
        assert_eq!(
            validate_common_name("device-01.example").unwrap(),
            "device-01.example"
        );
    }

    #[test]
    fn rejects_header_and_path_characters() {
        assert!(validate_common_name("device\r\nname").is_err());
        assert!(validate_common_name("../device").is_err());
        assert!(validate_common_name("device_name").is_err());
    }

    #[test]
    fn validates_p12_passwords() {
        assert!(validate_p12_password("correct horse battery staple").is_ok());
        assert!(validate_p12_password("short").is_err());
        assert!(validate_p12_password("password\nnext-line").is_err());
    }
}
