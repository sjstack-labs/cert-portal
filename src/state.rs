//! 요청 사이에 공유하는 애플리케이션 상태입니다.

use crate::{
    auth::Authentication,
    config::{AppConfig, AppEnvironment},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

pub(crate) struct AppState {
    pub(crate) authentication: Authentication,
    pub(crate) config: AppConfig,
    /// 동시에 진행할 수 있는 발급 요청 슬롯입니다.
    pub(crate) issuance_slots: Arc<Semaphore>,
    /// 재시작 후에도 요청 ID가 겹치지 않도록 프로세스 시작 시각을 접두어로 씁니다.
    boot_id: String,
    request_sequence: AtomicU64,
}

impl AppState {
    pub(crate) async fn new(config: AppConfig) -> Result<Self, String> {
        let authentication = match config.environment {
            AppEnvironment::Production => Authentication::cloudflare_from_env().await?,
            AppEnvironment::Development => {
                Authentication::local_development(config.containerized_development)
            }
        };
        Ok(Self::with_authentication(config, authentication))
    }

    pub(crate) fn with_authentication(config: AppConfig, authentication: Authentication) -> Self {
        let boot_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default();
        Self {
            authentication,
            issuance_slots: Arc::new(Semaphore::new(config.max_concurrent_issuances)),
            config,
            boot_id: format!("{boot_seconds:x}"),
            request_sequence: AtomicU64::new(1),
        }
    }

    pub(crate) fn next_request_id(&self) -> String {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed);
        format!("{}-{sequence}", self.boot_id)
    }
}
