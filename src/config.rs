//! 환경 변수에서 실행 설정을 읽고 시작 시점에 검증합니다.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

const DEFAULT_STEP_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_CONCURRENT_ISSUANCES: usize = 4;

#[derive(Clone)]
pub(crate) struct CaConfig {
    pub(crate) url: String,
    pub(crate) root: PathBuf,
    pub(crate) provisioner: String,
    pub(crate) provisioner_password_file: PathBuf,
}

pub(crate) struct AppConfig {
    pub(crate) environment: AppEnvironment,
    pub(crate) containerized_development: bool,
    pub(crate) step_binary: String,
    pub(crate) wpa3_ca: CaConfig,
    pub(crate) vpn_ca: CaConfig,
    pub(crate) trust_forwarded_for: bool,
    /// `step` 명령 하나가 끝나야 하는 시간입니다. 넘기면 프로세스를 종료합니다.
    pub(crate) step_timeout: Duration,
    /// 동시에 진행할 수 있는 발급 요청 수입니다. 넘치는 요청은 `503`을 받습니다.
    pub(crate) max_concurrent_issuances: usize,
}

impl AppConfig {
    pub(crate) fn from_env() -> Result<Self, String> {
        let environment = AppEnvironment::from_env()?;
        let containerized_development =
            environment == AppEnvironment::Development && env_flag("CONTAINERIZED_DEVELOPMENT");

        let wpa3_ca = CaConfig::from_env("STEP_CA")?;
        let vpn_ca = CaConfig::from_env("VPN_STEP_CA")?;

        Ok(Self {
            environment,
            containerized_development,
            step_binary: std::env::var("STEP_BINARY").unwrap_or_else(|_| "step".to_string()),
            wpa3_ca,
            vpn_ca,
            trust_forwarded_for: env_flag("TRUST_FORWARDED_FOR"),
            step_timeout: Duration::from_secs(env_number(
                "STEP_TIMEOUT_SECS",
                DEFAULT_STEP_TIMEOUT_SECS,
                1..=300,
            )?),
            max_concurrent_issuances: env_number(
                "MAX_CONCURRENT_ISSUANCES",
                DEFAULT_MAX_CONCURRENT_ISSUANCES,
                1..=64,
            )?,
        })
    }

    pub(crate) fn bind_address(&self) -> Result<SocketAddr, String> {
        std::env::var("BIND_ADDR")
            .unwrap_or_else(|_| self.environment.default_bind_address().to_string())
            .parse::<SocketAddr>()
            .map_err(|error| format!("유효하지 않은 BIND_ADDR입니다: {error}"))
    }
}

impl CaConfig {
    fn from_env(prefix: &str) -> Result<Self, String> {
        let root_name = format!("{prefix}_ROOT");
        let password_file_name = format!("{prefix}_PROVISIONER_PASSWORD_FILE");
        let root = required_env_path(&root_name)?;
        let provisioner_password_file = required_env_path(&password_file_name)?;

        std::fs::metadata(&root)
            .map_err(|error| format!("{root_name} 파일을 읽을 수 없습니다: {error}"))?;
        // 시작할 때 비밀번호 파일의 존재 여부만 검사합니다. 내용은 step CLI만 읽습니다.
        std::fs::metadata(&provisioner_password_file)
            .map_err(|error| format!("{password_file_name}을 읽을 수 없습니다: {error}"))?;

        Ok(Self {
            url: required_env(&format!("{prefix}_URL"))?,
            root,
            provisioner: required_env(&format!("{prefix}_PROVISIONER"))?,
            provisioner_password_file,
        })
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum AppEnvironment {
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

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn env_number<T>(name: &str, default: T, range: std::ops::RangeInclusive<T>) -> Result<T, String>
where
    T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
{
    let Ok(raw) = std::env::var(name) else {
        return Ok(default);
    };
    let value = raw
        .trim()
        .parse::<T>()
        .map_err(|_| format!("{name}는 숫자여야 합니다: {raw}"))?;
    if !range.contains(&value) {
        return Err(format!(
            "{name}는 {}~{} 범위여야 합니다: {value}",
            range.start(),
            range.end()
        ));
    }
    Ok(value)
}

pub(crate) fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("필수 환경 변수 {name}가 설정되지 않았습니다"))
}

fn required_env_path(name: &str) -> Result<PathBuf, String> {
    required_env(name).map(PathBuf::from)
}
