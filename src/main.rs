//! EAP-TLS Certificate Portal: WPA3와 VPN 클라이언트 인증서를 `step-ca`로 발급해 PFX로
//! 내려주는 서버입니다. 보안 불변식은 `docs/security-model.md`를 참고하세요.

mod access_middleware;
mod auth;
mod certificate;
mod config;
mod error;
mod handlers;
#[cfg(test)]
mod router_tests;
mod state;

use crate::{
    config::{AppConfig, AppEnvironment},
    state::AppState,
};
use std::sync::Arc;
use tokio::net::TcpListener;

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

    let config = AppConfig::from_env().unwrap_or_else(|error| configuration_error(error));
    if config.environment == AppEnvironment::Development {
        tracing::warn!(audit = true, "local_development_authentication_enabled");
    }
    if config.containerized_development {
        tracing::warn!(
            audit = true,
            "containerized_development_authentication_enabled"
        );
    }

    let address = config.bind_address().unwrap_or_else(|error| {
        tracing::error!(error = %error, "invalid_bind_address");
        std::process::exit(1);
    });
    if config.environment == AppEnvironment::Development
        && !config.containerized_development
        && !address.ip().is_loopback()
    {
        tracing::error!(address = %address, "development_mode_requires_loopback_bind_address");
        std::process::exit(1);
    }

    let state = Arc::new(
        AppState::new(config)
            .await
            .unwrap_or_else(|error| configuration_error(error)),
    );
    let app = handlers::router(state);

    let listener = TcpListener::bind(address).await.unwrap_or_else(|error| {
        tracing::error!(error = %error, address = %address, "server_bind_failed");
        std::process::exit(1);
    });
    let local_address = listener.local_addr().unwrap_or(address);
    tracing::info!(address = %local_address, "server_started");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap_or_else(|error| {
        tracing::error!(error = %error, "server_failed");
        std::process::exit(1);
    });
}

/// SIGINT 또는 SIGTERM을 받으면 새 연결을 받지 않고 진행 중인 요청이 끝나기를 기다립니다.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %error, "interrupt_signal_handler_failed");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(error = %error, "terminate_signal_handler_failed");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!("shutdown_started");
}

fn configuration_error(error: String) -> ! {
    tracing::error!(error = %error, "configuration_error");
    std::process::exit(1);
}
