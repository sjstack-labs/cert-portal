//! 클라이언트 인증서 발급: 입력 검증, 리프 키와 CSR 생성, `step-ca` 서명 요청,
//! PKCS#12 패키징. CA 개인키는 다루지 않습니다.

use crate::{
    config::{AppConfig, CaConfig},
    error::{ApiError, INTERNAL_ERROR_MESSAGE, internal_error},
};
use axum::http::StatusCode;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, Ia5String, KeyPair, KeyUsagePurpose};
use serde::Deserialize;
use std::{path::Path, process::Stdio};
use tempfile::tempdir;
use tokio::process::Command;

const MAX_COMMON_NAME_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;
const PKCS12_PASSWORD_LENGTH: std::ops::RangeInclusive<usize> = 8..=128;

#[derive(Deserialize)]
pub(crate) struct CertRequest {
    pub(crate) common_name: String,
    pub(crate) p12_password: String,
}

#[derive(Clone, Copy)]
pub(crate) enum CertificateProfile {
    Wpa3,
    Vpn,
}

impl CertificateProfile {
    pub(crate) fn audit_name(self) -> &'static str {
        match self {
            Self::Wpa3 => "wpa3",
            Self::Vpn => "vpn",
        }
    }

    fn ca_config(self, config: &AppConfig) -> &CaConfig {
        match self {
            Self::Wpa3 => &config.wpa3_ca,
            Self::Vpn => &config.vpn_ca,
        }
    }

    /// 다운로드 파일명. 기기 이름은 검증을 통과한 값만 들어오므로 헤더에 그대로 쓸 수 있습니다.
    fn filename(self, common_name: &str) -> String {
        match self {
            Self::Wpa3 => format!("{common_name}.pfx"),
            Self::Vpn => format!("vpn-{common_name}.pfx"),
        }
    }
}

pub(crate) struct IssuedCertificate {
    pub(crate) filename: String,
    pub(crate) pkcs12: Vec<u8>,
}

pub(crate) async fn issue_certificate(
    config: &AppConfig,
    payload: CertRequest,
    profile: CertificateProfile,
) -> Result<IssuedCertificate, ApiError> {
    let common_name = validate_common_name(&payload.common_name)?;
    let p12_password = validate_p12_password(&payload.p12_password)?;
    let ca = profile.ca_config(config);

    let (client_key_pair, csr_pem) = build_csr(common_name)?;

    // tempdir는 0700 권한으로 만들어지고, 반환될 때 안의 키와 비밀번호 파일과 함께 삭제됩니다.
    let work_dir = tempdir().map_err(internal_error("Temporary directory creation failed"))?;
    let csr_path = work_dir.path().join("client.csr");
    let cert_path = work_dir.path().join("client.crt");
    let key_path = work_dir.path().join("client.key");
    let password_path = work_dir.path().join("p12-password");
    let p12_path = work_dir.path().join("client.p12");
    write_file(&csr_path, csr_pem.as_bytes(), "CSR write failed").await?;
    write_file(
        &key_path,
        client_key_pair.serialize_pem().as_bytes(),
        "Client key write failed",
    )
    .await?;
    write_file(
        &password_path,
        p12_password.as_bytes(),
        "PKCS#12 password write failed",
    )
    .await?;

    // step CLI가 전용 JWK provisioner로 OTT를 만들어 step-ca에 CSR 서명을 요청합니다.
    let mut sign = Command::new(&config.step_binary);
    sign.arg("ca")
        .arg("sign")
        .arg(&csr_path)
        .arg(&cert_path)
        .arg("--ca-url")
        .arg(&ca.url)
        .arg("--root")
        .arg(&ca.root)
        .arg("--provisioner")
        .arg(&ca.provisioner)
        .arg("--provisioner-password-file")
        .arg(&ca.provisioner_password_file);
    run_step(config, sign, "step_ca_sign")
        .await
        .map_err(|failure| match failure {
            StepFailure::TimedOut => (
                StatusCode::GATEWAY_TIMEOUT,
                "step-ca 응답 시간이 초과되었습니다".to_string(),
            ),
            StepFailure::Exited => (
                StatusCode::BAD_GATEWAY,
                "step-ca가 인증서 발급을 거부했거나 응답하지 않았습니다".to_string(),
            ),
            StepFailure::NotStarted => (
                StatusCode::INTERNAL_SERVER_ERROR,
                INTERNAL_ERROR_MESSAGE.to_string(),
            ),
        })?;

    // Windows와 Android에서 바로 가져올 수 있도록 개인키, 클라이언트 인증서,
    // Root CA를 사용자가 지정한 비밀번호로 암호화한 PKCS#12로 묶습니다.
    let mut package = Command::new(&config.step_binary);
    package
        .arg("certificate")
        .arg("p12")
        .arg(&p12_path)
        .arg(&cert_path)
        .arg(&key_path)
        .arg("--ca")
        .arg(&ca.root)
        .arg("--password-file")
        .arg(&password_path);
    run_step(config, package, "step_certificate_p12")
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "인증서 패키지 생성에 실패했습니다".to_string(),
            )
        })?;

    let pkcs12 = tokio::fs::read(&p12_path)
        .await
        .map_err(internal_error("PKCS#12 read failed"))?;

    Ok(IssuedCertificate {
        filename: profile.filename(common_name),
        pkcs12,
    })
}

fn build_csr(common_name: &str) -> Result<(KeyPair, String), ApiError> {
    let key_pair = KeyPair::generate().map_err(internal_error("Client key generation failed"))?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let san_name = Ia5String::try_from(common_name.to_string()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "유효하지 않은 기기 이름입니다".to_string(),
        )
    })?;
    params
        .subject_alt_names
        .push(rcgen::SanType::DnsName(san_name));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let csr_pem = params
        .serialize_request(&key_pair)
        .map_err(internal_error("CSR generation failed"))?
        .pem()
        .map_err(internal_error("CSR encoding failed"))?;
    Ok((key_pair, csr_pem))
}

async fn write_file(path: &Path, contents: &[u8], context: &'static str) -> Result<(), ApiError> {
    tokio::fs::write(path, contents)
        .await
        .map_err(internal_error(context))
}

enum StepFailure {
    /// 실행 파일을 찾지 못했거나 시작할 수 없었습니다.
    NotStarted,
    /// 제한 시간 안에 끝나지 않아 종료했습니다.
    TimedOut,
    /// 0이 아닌 종료 코드로 끝났습니다.
    Exited,
}

/// `step`을 실행하고 제한 시간을 넘기면 프로세스를 종료합니다. 상세 원인은 로그에만 남깁니다.
async fn run_step(
    config: &AppConfig,
    mut command: Command,
    operation: &'static str,
) -> Result<(), StepFailure> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // 시간 초과로 future가 버려지면 자식 프로세스도 함께 종료됩니다.
        .kill_on_drop(true);

    let output = match tokio::time::timeout(config.step_timeout, command.output()).await {
        Err(_) => {
            tracing::error!(
                operation,
                timeout_secs = config.step_timeout.as_secs_f64(),
                "step_timed_out"
            );
            return Err(StepFailure::TimedOut);
        }
        Ok(Err(error)) => {
            tracing::error!(operation, error = %error, "step_start_failed");
            return Err(StepFailure::NotStarted);
        }
        Ok(Ok(output)) => output,
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(
            operation,
            exit_code = output.status.code(),
            error = %stderr.trim(),
            "step_failed"
        );
        return Err(StepFailure::Exited);
    }
    Ok(())
}

fn validate_p12_password(value: &str) -> Result<&str, ApiError> {
    if !PKCS12_PASSWORD_LENGTH.contains(&value.chars().count()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "PKCS#12 비밀번호는 8~128자여야 합니다".to_string(),
        ));
    }
    if value
        .chars()
        .any(|character| matches!(character, '\r' | '\n' | '\0'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "PKCS#12 비밀번호에 줄바꿈이나 NUL 문자를 사용할 수 없습니다".to_string(),
        ));
    }
    Ok(value)
}

/// 기기 이름은 DNS 이름 규칙을 따릅니다. 점으로 나뉜 각 부분은 1~63자이고,
/// 하이픈으로 시작하거나 끝날 수 없습니다.
fn validate_common_name(value: &str) -> Result<&str, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_COMMON_NAME_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            "기기 이름은 1~253자여야 합니다".to_string(),
        ));
    }
    if !value
        .bytes()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, b'.' | b'-'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "기기 이름에는 영문자, 숫자, 점, 하이픈만 사용할 수 있습니다".to_string(),
        ));
    }
    let labels_are_valid = value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LENGTH
            && !label.starts_with('-')
            && !label.ends_with('-')
    });
    if !labels_are_valid {
        return Err((
            StatusCode::BAD_REQUEST,
            "기기 이름은 점으로 시작하거나 끝날 수 없고, 점 사이는 1~63자이며 하이픈으로 시작하거나 끝날 수 없습니다"
                .to_string(),
        ));
    }
    Ok(value)
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
        assert_eq!(
            validate_common_name("  notebook-01  ").unwrap(),
            "notebook-01"
        );
    }

    #[test]
    fn rejects_header_and_path_characters() {
        assert!(validate_common_name("device\r\nname").is_err());
        assert!(validate_common_name("../device").is_err());
        assert!(validate_common_name("device_name").is_err());
        assert!(validate_common_name("device name").is_err());
    }

    #[test]
    fn rejects_malformed_dns_labels() {
        assert!(validate_common_name(".device").is_err());
        assert!(validate_common_name("device.").is_err());
        assert!(validate_common_name("device..example").is_err());
        assert!(validate_common_name("-device").is_err());
        assert!(validate_common_name("device-.example").is_err());
        assert!(validate_common_name(&"a".repeat(64)).is_err());
        assert!(validate_common_name(&"a".repeat(63)).is_ok());
        assert!(validate_common_name(&format!("{}.b", "a".repeat(252))).is_err());
    }

    #[test]
    fn validates_p12_passwords() {
        assert!(validate_p12_password("correct horse battery staple").is_ok());
        assert!(validate_p12_password("short").is_err());
        assert!(validate_p12_password("password\nnext-line").is_err());
    }

    #[test]
    fn counts_password_length_in_characters() {
        // 한글 8자는 24바이트지만 8자로 세어야 합니다.
        assert!(validate_p12_password("가나다라마바사아").is_ok());
        assert!(validate_p12_password(&"가".repeat(128)).is_ok());
        assert!(validate_p12_password(&"가".repeat(129)).is_err());
    }
}
