//! 라우터 수준 테스트. `docs/security-model.md`의 불변식을 확인합니다.
//!
//! 실제 `step` 대신 `target/test-fixtures`에 만든 셸 스크립트를 실행합니다. 가짜 `step`은
//! 받은 인자를 결과 파일에 적으므로, 응답 본문을 보면 어떤 CA 설정이 쓰였는지 알 수 있습니다.

use crate::{
    auth::Authentication,
    config::{AppConfig, AppEnvironment, CaConfig},
    handlers::router,
    state::AppState,
};
use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use jsonwebtoken::jwk::JwkSet;
use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
use tower::ServiceExt;

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const REMOTE: [u8; 4] = [192, 0, 2, 10];
const ISSUE_BODY: &str = r#"{"common_name":"notebook-01","p12_password":"correct horse battery"}"#;

/// 인증 없이 확인할 경로 목록. 정적 파일과 없는 경로도 포함합니다.
const ALL_ROUTES: &[(Method, &str)] = &[
    (Method::GET, "/"),
    (Method::GET, "/index.html"),
    (Method::GET, "/app.js"),
    (Method::GET, "/does-not-exist"),
    (Method::GET, "/api/vpn/ca-certificate"),
    (Method::POST, "/api/request-cert"),
    (Method::POST, "/api/vpn/request-cert"),
];

struct Fixtures {
    dir: PathBuf,
}

impl Fixtures {
    fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }
}

/// 가짜 `step` 스크립트와 CA 파일을 한 번만 만듭니다. 테스트가 이 함수를 거친 뒤에만
/// 프로세스를 실행하므로, 실행 파일을 쓰는 도중 다른 스레드가 fork하는 일이 없습니다.
fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures");
        std::fs::create_dir_all(&dir).unwrap();

        let files = [
            ("wpa3-root.crt", "WPA3-ROOT-CERTIFICATE\n"),
            ("vpn-root.crt", "VPN-ROOT-CERTIFICATE\n"),
            ("wpa3-password", "unused\n"),
            ("vpn-password", "unused\n"),
        ];
        for (name, contents) in files {
            std::fs::write(dir.join(name), contents).unwrap();
        }

        let scripts = [
            (
                "recording-step",
                r#"#!/bin/sh
if [ "$1 $2" = "ca sign" ]; then
  printf 'SIGN %s\n' "$*" > "$4"
elif [ "$1 $2" = "certificate p12" ]; then
  cat "$4" > "$3"
  printf 'P12 %s\n' "$*" >> "$3"
else
  exit 64
fi
"#,
            ),
            (
                "slow-step",
                "#!/bin/sh\nsleep 2\nexec \"$(dirname \"$0\")/recording-step\" \"$@\"\n",
            ),
            (
                "failing-step",
                "#!/bin/sh\necho 'SECRET-STDERR-DETAIL from step' >&2\nexit 1\n",
            ),
        ];
        for (name, contents) in scripts {
            let path = dir.join(name);
            std::fs::write(&path, contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Fixtures { dir }
    })
}

fn config(step: &str, step_timeout: Duration, max_concurrent_issuances: usize) -> AppConfig {
    let fixtures = fixtures();
    AppConfig {
        environment: AppEnvironment::Development,
        containerized_development: false,
        step_binary: step.to_string(),
        wpa3_ca: CaConfig {
            url: "https://wpa3-ca.test".to_string(),
            root: fixtures.path("wpa3-root.crt").into(),
            provisioner: "wpa3-provisioner".to_string(),
            provisioner_password_file: fixtures.path("wpa3-password").into(),
        },
        vpn_ca: CaConfig {
            url: "https://vpn-ca.test".to_string(),
            root: fixtures.path("vpn-root.crt").into(),
            provisioner: "vpn-provisioner".to_string(),
            provisioner_password_file: fixtures.path("vpn-password").into(),
        },
        trust_forwarded_for: false,
        step_timeout,
        max_concurrent_issuances,
    }
}

fn development_app(step: &str) -> Router {
    development_app_with(step, Duration::from_secs(10), 4)
}

fn development_app_with(step: &str, timeout: Duration, max: usize) -> Router {
    let config = config(step, timeout, max);
    router(Arc::new(AppState::with_authentication(
        config,
        Authentication::local_development(false),
    )))
}

fn production_app() -> Router {
    let mut config = config(
        &fixtures().path("recording-step"),
        Duration::from_secs(10),
        4,
    );
    config.environment = AppEnvironment::Production;
    let authentication = Authentication::cloudflare_for_tests(
        "https://test.cloudflareaccess.com",
        "test-audience",
        JwkSet { keys: Vec::new() },
    );
    router(Arc::new(AppState::with_authentication(
        config,
        authentication,
    )))
}

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn send(
    app: &Router,
    method: Method,
    path: &str,
    peer: [u8; 4],
    extra_headers: &[(&str, &str)],
    body: Option<&str>,
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(path);
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    let mut request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from((peer, 50_000))));

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    TestResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn issue(app: &Router, path: &str) -> TestResponse {
    send(app, Method::POST, path, LOOPBACK, &[], Some(ISSUE_BODY)).await
}

fn hs256_token() -> String {
    #[derive(serde::Serialize)]
    struct Claims {
        sub: &'static str,
        email: &'static str,
        exp: u64,
    }
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &Claims {
            sub: "attacker",
            email: "attacker@example.com",
            exp: 4_102_444_800,
        },
        &jsonwebtoken::EncodingKey::from_secret(b"guessable"),
    )
    .unwrap()
}

// 불변식 3: 모든 경로는 인증 미들웨어 뒤에 있습니다.
#[tokio::test]
async fn production_rejects_unauthenticated_requests_on_every_route() {
    let app = production_app();
    // RS256 헤더에 알 수 없는 kid를 넣은 토큰입니다. 서명은 의미 없는 값입니다.
    let unknown_kid = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVua25vd24tdGVzdC1raWQifQ.eyJzdWIiOiJ4In0.c2ln";
    let hs256 = hs256_token();
    let tokens: [Option<&str>; 4] = [None, Some("not-a-jwt"), Some(&hs256), Some(unknown_kid)];

    for (method, path) in ALL_ROUTES {
        for token in tokens {
            let headers: Vec<(&str, &str)> = token
                .map(|token| vec![("cf-access-jwt-assertion", token)])
                .unwrap_or_default();
            let body = (*method == Method::POST).then_some(ISSUE_BODY);
            let response = send(&app, method.clone(), path, LOOPBACK, &headers, body).await;
            assert_eq!(
                response.status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} with token {token:?}"
            );
            assert!(
                !response.body.contains("SIGN"),
                "step must not run for {method} {path}"
            );
        }
    }
}

// 불변식 4: 개발 모드의 인증 우회는 loopback에서만 동작합니다.
#[tokio::test]
async fn development_mode_rejects_non_loopback_peers() {
    let app = development_app(&fixtures().path("recording-step"));
    for (method, path) in ALL_ROUTES {
        let body = (*method == Method::POST).then_some(ISSUE_BODY);
        let response = send(&app, method.clone(), path, REMOTE, &[], body).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }

    let local = send(&app, Method::GET, "/", LOOPBACK, &[], None).await;
    assert_eq!(local.status, StatusCode::OK);
}

// 불변식 2: WPA3와 VPN은 각자의 CA 설정만 사용합니다.
#[tokio::test]
async fn wpa3_and_vpn_use_only_their_own_ca_settings() {
    let app = development_app(&fixtures().path("recording-step"));

    let wpa3 = issue(&app, "/api/request-cert").await;
    assert_eq!(wpa3.status, StatusCode::OK, "{}", wpa3.body);
    for expected in [
        "https://wpa3-ca.test",
        "wpa3-root.crt",
        "wpa3-provisioner",
        "wpa3-password",
    ] {
        assert!(wpa3.body.contains(expected), "WPA3 missing {expected}");
    }
    assert!(!wpa3.body.contains("vpn"), "WPA3 used VPN settings");
    assert_eq!(
        wpa3.headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"notebook-01.pfx\""
    );

    let vpn = issue(&app, "/api/vpn/request-cert").await;
    assert_eq!(vpn.status, StatusCode::OK, "{}", vpn.body);
    for expected in [
        "https://vpn-ca.test",
        "vpn-root.crt",
        "vpn-provisioner",
        "vpn-password",
    ] {
        assert!(vpn.body.contains(expected), "VPN missing {expected}");
    }
    assert!(!vpn.body.contains("wpa3"), "VPN used WPA3 settings");
    assert_eq!(
        vpn.headers[header::CONTENT_DISPOSITION],
        "attachment; filename=\"vpn-notebook-01.pfx\""
    );
    assert_eq!(vpn.headers[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn vpn_ca_download_serves_the_vpn_root() {
    let app = development_app(&fixtures().path("recording-step"));
    let response = send(
        &app,
        Method::GET,
        "/api/vpn/ca-certificate",
        LOOPBACK,
        &[],
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "VPN-ROOT-CERTIFICATE\n");
}

// 불변식 6: step이 제한 시간을 넘기면 종료하고 504를 돌려줍니다.
#[tokio::test]
async fn slow_step_is_stopped_after_the_timeout() {
    let app = development_app_with(&fixtures().path("slow-step"), Duration::from_millis(300), 4);
    let started = Instant::now();
    let response = issue(&app, "/api/request-cert").await;
    assert_eq!(response.status, StatusCode::GATEWAY_TIMEOUT);
    assert!(started.elapsed() < Duration::from_millis(1_500));
    assert!(response.body.contains("요청 ID"));
}

// 불변식 6: 동시 발급 수를 넘는 요청은 기다리지 않고 503을 받습니다.
#[tokio::test]
async fn concurrent_issuance_is_limited() {
    let app = development_app_with(&fixtures().path("slow-step"), Duration::from_secs(10), 1);

    let first = tokio::spawn({
        let app = app.clone();
        async move { issue(&app, "/api/request-cert").await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let second = issue(&app, "/api/vpn/request-cert").await;
    assert_eq!(second.status, StatusCode::SERVICE_UNAVAILABLE);

    let first = first.await.unwrap();
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
}

// 불변식 5: 내부 원인은 응답에 드러나지 않습니다.
#[tokio::test]
async fn step_failures_do_not_leak_details() {
    let app = development_app(&fixtures().path("failing-step"));
    let response = issue(&app, "/api/request-cert").await;
    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    assert!(!response.body.contains("SECRET-STDERR-DETAIL"));
    assert!(!response.body.contains("wpa3-ca.test"));
    assert!(response.body.contains("요청 ID"));

    let missing = development_app(&fixtures().path("no-such-step-binary"));
    let response = issue(&missing, "/api/request-cert").await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!response.body.contains("no-such-step-binary"));
    assert!(response.body.starts_with("내부 오류가 발생했습니다"));
}

#[tokio::test]
async fn malformed_requests_get_fixed_messages() {
    let app = development_app(&fixtures().path("recording-step"));
    for body in [
        "{not json",
        r#"{"common_name":"a"}"#,
        r#"{"common_name":1,"p12_password":"x"}"#,
    ] {
        let response = send(
            &app,
            Method::POST,
            "/api/request-cert",
            LOOPBACK,
            &[],
            Some(body),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(response.body, "요청 형식이 올바르지 않습니다");
    }

    let oversized = format!(
        r#"{{"common_name":"{}","p12_password":"correct horse"}}"#,
        "a".repeat(20_000)
    );
    let response = send(
        &app,
        Method::POST,
        "/api/request-cert",
        LOOPBACK,
        &[],
        Some(&oversized),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn security_headers_are_set_on_every_response() {
    let development = development_app(&fixtures().path("recording-step"));
    let production = production_app();
    let responses = [
        send(&development, Method::GET, "/", LOOPBACK, &[], None).await,
        send(&development, Method::GET, "/", REMOTE, &[], None).await,
        send(&production, Method::GET, "/", LOOPBACK, &[], None).await,
        issue(&development, "/api/request-cert").await,
    ];
    for response in responses {
        let csp = response.headers[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap();
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("script-src 'self'"));
        assert_eq!(response.headers[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(response.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(response.headers[header::REFERRER_POLICY], "no-referrer");
    }
}
