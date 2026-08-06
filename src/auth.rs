use crate::config::required_env;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

pub(crate) struct Authentication {
    mode: AuthenticationMode,
}

enum AuthenticationMode {
    Cloudflare(Box<AccessJwtValidator>),
    LocalDevelopment { allow_non_loopback: bool },
}

impl Authentication {
    pub(crate) async fn cloudflare_from_env() -> Result<Self, String> {
        Ok(Self {
            mode: AuthenticationMode::Cloudflare(Box::new(AccessJwtValidator::from_env().await?)),
        })
    }

    pub(crate) fn local_development(allow_non_loopback: bool) -> Self {
        Self {
            mode: AuthenticationMode::LocalDevelopment { allow_non_loopback },
        }
    }

    pub(crate) fn local_allow_non_loopback(&self) -> Option<bool> {
        match self.mode {
            AuthenticationMode::LocalDevelopment { allow_non_loopback } => Some(allow_non_loopback),
            AuthenticationMode::Cloudflare(_) => None,
        }
    }

    pub(crate) async fn authenticate(
        &self,
        token: &str,
    ) -> Result<AuthenticatedUser, &'static str> {
        match &self.mode {
            AuthenticationMode::Cloudflare(validator) => validator.authenticate(token).await,
            AuthenticationMode::LocalDevelopment { .. } => {
                Err("Cloudflare authentication is disabled in development")
            }
        }
    }
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
pub(crate) struct AuthenticatedUser {
    pub(crate) email: String,
    pub(crate) subject: String,
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
            .map_err(|error| format!("Cloudflare Access HTTP client 생성 실패: {error}"))?;
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
        .map_err(|error| format!("Cloudflare Access 공개 키 조회 실패: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Cloudflare Access 공개 키 응답 오류: {error}"))?;
    let jwks = response
        .json::<JwkSet>()
        .await
        .map_err(|error| format!("Cloudflare Access 공개 키 형식 오류: {error}"))?;
    if jwks.keys.is_empty() {
        return Err("Cloudflare Access 공개 키 목록이 비어 있습니다".to_string());
    }
    Ok(jwks)
}
