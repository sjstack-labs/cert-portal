use crate::{
    auth::Authentication,
    config::{AppConfig, AppEnvironment},
};
use std::sync::atomic::AtomicU64;

pub(crate) struct AppState {
    pub(crate) authentication: Authentication,
    pub(crate) config: AppConfig,
    pub(crate) request_sequence: AtomicU64,
}

impl AppState {
    pub(crate) async fn new(config: AppConfig) -> Result<Self, String> {
        let authentication = match config.environment {
            AppEnvironment::Production => Authentication::cloudflare_from_env().await?,
            AppEnvironment::Development => {
                Authentication::local_development(config.containerized_development)
            }
        };

        Ok(Self {
            authentication,
            config,
            request_sequence: AtomicU64::new(1),
        })
    }
}
