mod access_middleware;
mod auth;
mod certificate;
mod config;
mod error;
mod handlers;
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
    .await
    .unwrap_or_else(|error| {
        tracing::error!(error = %error, "server_failed");
        std::process::exit(1);
    });
}

fn configuration_error(error: String) -> ! {
    tracing::error!(error = %error, "configuration_error");
    std::process::exit(1);
}
