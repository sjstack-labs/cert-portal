use crate::{
    config::{AppConfig, CaConfig},
    error::{ApiError, internal_error},
};
use axum::{
    body::Body,
    http::{Response, StatusCode, header},
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, Ia5String, KeyPair, KeyUsagePurpose};
use serde::Deserialize;
use tempfile::tempdir;
use tokio::process::Command;

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

    fn filename(self, common_name: &str) -> String {
        match self {
            Self::Wpa3 => format!("{}.pfx", common_name.replace(' ', "_")),
            Self::Vpn => format!("vpn-{}.pfx", common_name.replace(' ', "_")),
        }
    }
}

pub(crate) async fn issue_certificate(
    config: &AppConfig,
    payload: CertRequest,
    profile: CertificateProfile,
) -> Result<Response<Body>, ApiError> {
    let common_name = validate_common_name(&payload.common_name)?;
    let p12_password = validate_p12_password(&payload.p12_password)?;

    // 이 서비스는 리프 개인키와 CSR만 생성합니다. CA 키를 보유하거나 서명하지 않습니다.
    let client_key_pair =
        KeyPair::generate().map_err(internal_error("Client key generation failed"))?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let san_name = Ia5String::try_from(common_name.to_string()).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("유효하지 않은 기기 이름: {error}"),
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

    let ca = profile.ca_config(config);
    // step CLI가 전용 JWK Provisioner로 OTT를 내부 생성하고 step-ca에 CSR을 전송합니다.
    let output = Command::new(&config.step_binary)
        .arg("ca")
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
        .arg(&ca.provisioner_password_file)
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
    let p12_output = Command::new(&config.step_binary)
        .arg("certificate")
        .arg("p12")
        .arg(&p12_path)
        .arg(&cert_path)
        .arg(&key_path)
        .arg("--ca")
        .arg(&ca.root)
        .arg("--password-file")
        .arg(&password_path)
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
    let filename = profile.filename(common_name);

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

fn validate_p12_password(value: &str) -> Result<&str, ApiError> {
    if value.len() < 8 || value.len() > 128 {
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

fn validate_common_name(value: &str) -> Result<&str, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 253 {
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
