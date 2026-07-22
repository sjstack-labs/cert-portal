# EAP-TLS Certificate Portal

이 서비스는 클라이언트 키와 CSR만 생성하며 인증서를 직접 서명하지 않습니다.
최종 클라이언트 인증서는 OpenWrt One Root CA가 서명한 intermediate CA인
`step-ca`가 발급합니다.

## step-ca 설정

Axum 전용 JWK Provisioner를 만들고 EAP-TLS 클라이언트 인증서 템플릿을 적용합니다.
다음 명령은 `step-ca` 서버의 설정 환경에서 실행합니다.

```sh
step ca provisioner add axum-eap --type JWK --create
step ca provisioner update axum-eap \
  --x509-template ./step-ca/eap-client.tpl \
  --x509-default-dur 24h \
  --x509-max-dur 168h
```

원격 provisioner 관리가 비활성화되어 있다면 설정 변경 후 `step-ca`를 재시작하거나
SIGHUP으로 설정을 다시 불러와야 합니다. 생성된 JWK Provisioner 비밀번호는 Axum
프로세스만 읽을 수 있는 파일에 저장합니다.

## Axum 실행 설정

서버에 `step` CLI를 설치하고 다음 환경 변수를 설정합니다.

```sh
export STEP_CA_URL=https://step-ca.example.internal
export STEP_CA_ROOT=/etc/axum/root_ca.crt
export STEP_CA_PROVISIONER=axum-eap
export STEP_CA_PROVISIONER_PASSWORD_FILE=/etc/axum/axum-eap-password
# step 실행 파일이 PATH에 없다면 지정
export STEP_BINARY=/usr/local/bin/step
export APP_ENV=production

# Cloudflare Zero Trust의 team domain과 Access Application AUD tag
export CF_ACCESS_ISSUER=https://your-team.cloudflareaccess.com
export CF_ACCESS_AUDIENCE=0123456789abcdef0123456789abcdef

cargo run
```

## 개발 환경과 서비스 환경

`APP_ENV`는 반드시 명시해야 합니다.

- `development`: Cloudflare JWT 대신 고정된 로컬 개발 신원을 사용합니다. 안전을 위해
  `BIND_ADDR`가 loopback 주소여야 하며 loopback이 아닌 요청도 거부합니다.
- `production`: `Cf-Access-Jwt-Assertion` 검증이 항상 활성화됩니다. Cloudflare 설정이나
  공개 키 조회에 실패하면 서버가 시작되지 않습니다.

로컬에서 개발할 때 예제 파일을 복사한 후 실제 step-ca 경로를 입력합니다.

```sh
cp .env.development.example .env.development
set -a
. ./.env.development
set +a
cargo run
```

`.env.development`와 `.env.production`은 Git에서 제외됩니다. 개발 모드는 인증을 완전히
제거하는 용도가 아니며 `127.0.0.1` 밖으로 노출해서는 안 됩니다.

## Debian 컨테이너 배포

이미지는 Rust builder와 Debian Bookworm slim runtime을 사용하는 멀티스테이지 빌드입니다.
runtime에는 애플리케이션, CA 인증서 검증용 패키지와 `step` CLI만 포함되며 UID 10001의
비특권 사용자로 실행됩니다.

```sh
cp .env.production.example .env.production
# .env.production의 Cloudflare/step-ca 값과 호스트 파일 경로를 수정
docker compose --env-file .env.production config
docker compose --env-file .env.production up -d --build
```

Compose는 컨테이너 root filesystem을 read-only로 두고 모든 Linux capability를 제거합니다.
Root CA는 read-only bind mount, provisioner 비밀번호는 Compose secret으로 `/run/secrets`에
전달합니다. 임시 CSR과 PKCS#12 작업에는 메모리 기반 `/tmp`만 사용합니다. 호스트에는
`127.0.0.1:3000`으로만 publish하므로 같은 호스트의 `cloudflared`가
`http://localhost:3000`으로 연결하도록 구성할 수 있습니다. `cloudflared`도 나중에 같은
Compose project에 넣는다면 host port를 제거하고 내부 service 이름 `http://portal:3000`을
사용하는 편이 좋습니다.

서버는 시작 시 `${CF_ACCESS_ISSUER}/cdn-cgi/access/certs`에서 공개 키를 가져오며,
모든 정적 페이지와 API 요청의 `Cf-Access-Jwt-Assertion`을 검증합니다. 서명 알고리즘은
RS256으로 제한하고 `iss`, `aud`, `exp`, `sub`를 확인합니다. 토큰이 없거나 유효하지
않으면 요청은 `401 Unauthorized`로 거부되며 CA 명령은 실행되지 않습니다. 서명 키의
`kid`가 변경되면 공개 키 목록을 한 번 갱신합니다.

Cloudflare 대시보드의 Access Application에서 표시되는 **Application Audience (AUD) Tag**를
`CF_ACCESS_AUDIENCE`에 정확히 입력하십시오. `CF_ACCESS_ISSUER`에는 Access의 team domain만
입력하고 경로는 추가하지 않습니다. 이 검증은 tunnel 자체의 접근 통제를 대체하지 않으며,
origin 방화벽도 cloudflared 또는 로컬 reverse proxy에서만 이 포트에 접근하도록 제한해야 합니다.

## 운영 감사 로그

포털은 인증서 요청마다 JSON 감사 로그를 표준 출력에 기록합니다. 요청 ID, 접속 IP,
User-Agent, 검증된 Access 이메일/subject, 인증서 CN, 성공/실패, HTTP 상태와 처리 시간이 포함됩니다. PKCS#12
비밀번호, 개인키, CSR 및 인증서 파일 내용은 기록하지 않습니다. `systemd`로 실행한다면
`journalctl -u <서비스명>`에서 조회하고 보존 기간은 journald 정책으로 관리합니다.

리버스 프록시 바로 뒤에서 운영하며 프록시가 외부의 `X-Forwarded-For` 헤더를 제거하고
새로 설정하도록 구성된 경우에만 다음 값을 사용하십시오.

```sh
export TRUST_FORWARDED_FOR=true
export RUST_LOG=eap_tls_cert_portal=info
```

이 설정이 없으면 위조 가능한 전달 헤더를 무시하고 TCP 연결 상대의 IP를 기록합니다.
IP와 User-Agent는 기기 식별의 보조 정보이며 인증된 기기 신원을 보장하지 않습니다.

`STEP_CA_ROOT`는 OpenWrt One Root CA 인증서이고 개인키가 아닙니다. 이 서비스에는
Root CA 및 intermediate CA 개인키를 복사하지 마십시오.

포털에서 입력한 가져오기 비밀번호로 암호화된 PKCS#12(`.pfx`) 파일이 다운로드됩니다.
이 파일에는 클라이언트 개인키, 클라이언트 인증서 체인, Root CA 인증서가 포함되어
Windows와 Android의 인증서 가져오기 화면에서 바로 설치할 수 있습니다. 비밀번호는
패키징 중 임시 파일로만 사용되며 응답이나 로그에 기록하지 않습니다.

`.pfx`와 `.p12`는 동일한 PKCS#12 형식입니다. 포털은 구형 Windows와의 호환성을
위해 `step certificate p12 --legacy` 인코딩을 사용합니다.

개인키가 네트워크로 전달되므로 운영 환경에서는 이 API를 HTTPS로 보호하고 별도의
사용자 또는 기기 인증과 발급 제한을 적용해야 합니다. PKCS#12 비밀번호도 인증서
다운로드와 다른 안전한 경로로 관리하는 것을 권장합니다.

## 추후 개선 과제

현재 구성은 관리자가 발급과 기기 등록을 통제하는 소규모 환경에서 운영할 수 있다.
규모 확대 또는 인증서별 즉시 차단이 필요해지면 다음 항목을 우선 검토한다.

- step-ca의 클라이언트 전용 provisioner를 분리하고 `clientAuth` 전용 템플릿과 의도한
  유효기간이 실제 발급 인증서에 적용되는지 검증한다.
- 인증서 serial, 사용자, 기기명, 발급일과 만료일을 기록하고 만료·교체 절차를 마련한다.
- `eap_user`의 EAP Identity는 인증서 allowlist가 아니므로, 강한 장치별 통제가 필요하면
  FreeRADIUS 등에서 인증서 serial 또는 SAN을 승인 DB와 연동하고 폐기 상태를 검사한다.
- 가능하면 개인키와 CSR을 클라이언트 기기에서 생성하고 Windows TPM이나 MDM/SCEP 등
  내보내기 어려운 키 저장 방식을 사용한다.
- step-ca 이미지 버전을 고정하고 CA 설정·DB를 정기적으로 백업하며 복구 및 신규 PFX의
  EKU·유효기간·실제 Wi-Fi 연결을 주기적으로 시험한다.
