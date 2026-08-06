# EAP-TLS Certificate Portal

## 개요

EAP-TLS Certificate Portal은 WPA3-Enterprise와 VPN 접속에 필요한 클라이언트 인증서를
웹에서 발급하고, 기기에 설치할 수 있는 PKCS#12(`.pfx`) 파일로 제공하는 Axum 기반
서비스입니다. 사용자는 용도에 맞는 인증서 이름과 가져오기 비밀번호를 입력해 PFX를
다운로드할 수 있습니다.

포털은 클라이언트 개인키와 CSR을 생성하지만 인증서를 직접 서명하지는 않습니다. 서명은
외부 `step-ca`에 요청하며, 발급된 인증서와 개인키 및 CA 인증서를 사용자가 지정한
비밀번호로 암호화해 하나의 PFX 파일로 묶습니다. CA 개인키는 포털에 저장하거나 전달하지
않습니다.

WPA3와 VPN 발급은 서로 분리된 CA 설정과 provisioner를 사용합니다. 두 CA가 같은 서버에
있더라도 provisioner와 발급 정책은 공유하지 않습니다. 운영 환경에서는 Cloudflare
Access로 모든 화면과 API 요청을 인증하고, 인증서 발급 결과를 JSON 감사 로그로 기록합니다.

## 만든 배경

개인 홈랩에서 WPA3-Enterprise와 VPN을 운영하면서 기기마다 `step` CLI로 인증서를 발급하고
PFX로 변환하는 작업을 반복해야 했습니다. 이 과정을 단순화하기 위해, 인증된 사용자가
웹에서 용도에 맞는 클라이언트 인증서를 직접 발급받을 수 있는 작은 포털을 만들었습니다.

이 프로젝트는 새로운 CA를 구현하거나 모든 인증서 수명주기를 관리하기 위한 시스템이
아닙니다. 기존 `step-ca`의 발급 정책을 그대로 사용하면서, 소수의 기기에 인증서를
배포하는 과정을 편리하게 만드는 데 목적이 있습니다.

## 대상 및 범위

다음과 같은 환경에서 활용하거나 참고할 수 있습니다.

- `step-ca`를 사용하는 개인 홈랩 또는 관리자가 직접 통제하는 소규모 네트워크
- WPA3-Enterprise나 VPN용 클라이언트 인증서를 수동으로 발급·배포하고 있는 환경
- Rust/Axum에서 외부 CA 및 CLI를 연동하는 self-hosted 애플리케이션 예제가 필요한 경우
- Cloudflare Access로 내부 관리 도구를 보호하는 구성을 참고하려는 경우

범용 PKI 관리 시스템, MDM/SCEP 대체재 또는 대규모 조직용 인증서 수명주기 관리 도구를
목표로 하지는 않습니다. 고가용성, 자동 갱신, 인증서별 폐기, 기기 인벤토리와 하드웨어 기반
키 보호가 필요하다면 별도의 PKI·MDM 구성을 함께 검토해야 합니다.

## 주요 기능과 API

- `POST /api/request-cert`: WPA3 전용 PFX를 발급하며 `STEP_CA_*` 설정만 사용합니다.
- `GET /api/vpn/ca-certificate`: `VPN_STEP_CA_ROOT`에 지정한 VPN 공개 CA 인증서를
  다운로드합니다.
- `POST /api/vpn/request-cert`: VPN 전용 PFX를 발급하며 `VPN_STEP_CA_*` 설정만 사용합니다.

화면에서도 WPA3와 VPN 발급 기능을 독립된 카드로 제공합니다. VPN 카드에서 VPN CA
다운로드와 VPN PFX 발급을 수행합니다. 운영 환경에서는 모든 화면과 API 요청에
Cloudflare Access 인증을 적용하며, 인증서 응답은 캐시하지 않습니다.

## 인증서 발급 흐름

WPA3와 VPN은 같은 절차로 인증서를 발급하며, 사용하는 CA 설정과 provisioner만 다릅니다.

1. 포털이 임시 작업 디렉터리에서 클라이언트 개인키와 `clientAuth` CSR을 생성합니다.
2. WPA3 요청에는 `STEP_CA_*`, VPN 요청에는 `VPN_STEP_CA_*` 설정을 사용해 해당
   `step-ca`에 CSR 서명을 요청합니다. VPN 요청은 다음 명령과 같은 방식으로 처리됩니다.

   ```sh
   step ca sign client.csr client.crt \
     --ca-url "$VPN_STEP_CA_URL" \
     --root "$VPN_STEP_CA_ROOT" \
     --provisioner "$VPN_STEP_CA_PROVISIONER" \
     --provisioner-password-file "$VPN_STEP_CA_PROVISIONER_PASSWORD_FILE"
   ```

3. `step-ca`가 해당 provisioner와 클라이언트 인증서 정책을 검사한 후 인증서에
   서명합니다. 발급 거부 또는 통신 실패 시 포털은 `502 Bad Gateway`를 반환합니다.
4. 포털이 서명된 인증서, 클라이언트 개인키와 해당 CA 인증서를 사용자가 입력한
   비밀번호로 암호화한 PFX로 묶어 내려줍니다. 임시 작업 파일은 요청 처리 후 삭제됩니다.

## 사전 준비 사항

- WPA3와 VPN에 사용할 `step-ca` 및 각각의 JWK provisioner
- 포털 호스트에서 각 `step-ca`로 연결할 수 있는 네트워크 경로
- 각 CA의 공개 Root CA 인증서와 provisioner 비밀번호 파일
- 운영 환경에서 사용할 Cloudflare Access Application의 팀 도메인과 Audience Tag
- 네이티브 실행 시 Rust 툴체인과 `step` CLI, 컨테이너 실행 시 Docker와 Compose

`STEP_CA_ROOT`와 `VPN_STEP_CA_ROOT`에는 CA 개인키가 아닌 공개 Root CA 인증서를
지정해야 합니다. provisioner 비밀번호 파일은 포털 프로세스만 읽을 수 있도록 권한을
제한합니다.

## step-ca 설정

WPA3와 VPN용 JWK provisioner를 각각 만들고 용도별 클라이언트 인증서 템플릿을 적용합니다.
다음 명령은 해당 `step-ca` 서버의 설정 환경에서 실행합니다.

WPA3용 템플릿을 `eap-client.tpl`로 저장합니다.

```json
{
  "subject": {
    "commonName": {{ toJson .Subject.CommonName }}
  },
  "sans": {{ toJson .SANs }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"]
}
```

VPN용 템플릿을 `vpn-client.tpl`로 저장합니다.

현재 두 템플릿의 내용은 같지만, 용도별 정책을 독립적으로 변경할 수 있도록 별도 파일로
관리합니다.

```json
{
  "subject": {
    "commonName": {{ toJson .Subject.CommonName }}
  },
  "sans": {{ toJson .SANs }},
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"]
}
```

```sh
step ca provisioner add axum-eap --type JWK --create
step ca provisioner update axum-eap \
  --x509-template ./eap-client.tpl \
  --x509-default-dur 24h \
  --x509-max-dur 168h

step ca provisioner add axum-vpn --type JWK --create
step ca provisioner update axum-vpn \
  --x509-template ./vpn-client.tpl \
  --x509-default-dur 24h \
  --x509-max-dur 168h
```

원격 provisioner 관리가 비활성화되어 있다면 설정 변경 후 `step-ca`를 재시작하거나
SIGHUP으로 설정을 다시 불러와야 합니다. 생성된 JWK provisioner 비밀번호는 포털
프로세스만 읽을 수 있는 파일에 저장합니다. 템플릿을 변경한 경우에도 파일을 저장한 뒤
`step ca provisioner update`를 다시 실행해야 운영 설정에 반영됩니다.

## 실행 모드

`APP_ENV`는 반드시 명시해야 합니다.

- `development`: Cloudflare JWT 대신 고정된 로컬 개발 신원을 사용합니다. 안전을 위해
  기본적으로 `BIND_ADDR`가 루프백(loopback) 주소여야 하며 루프백이 아닌 요청도 거부합니다.
  Docker 개발 환경에서는 명시적인 컨테이너 개발 모드와 호스트 루프백 포트 게시를
  함께 사용합니다.
- `production`: `Cf-Access-Jwt-Assertion` 검증이 항상 활성화됩니다. Cloudflare 설정이나
  공개 키 조회에 실패하면 서버가 시작되지 않습니다.

개발 모드는 인증을 완전히 제거하는 용도가 아니며 `127.0.0.1` 밖으로 노출해서는 안
됩니다. `.env.development`와 `.env.production`은 Git에서 제외됩니다.

## 네이티브 실행

네이티브로 실행하려면 호스트에 Rust 툴체인과 `step` CLI가 설치되어 있어야 합니다.

로컬 개발 환경에서는 예제 파일을 복사한 후 실제 `step-ca` 경로를 입력합니다.

```sh
cp .env.development.example .env.development
set -a
. ./.env.development
set +a
cargo run
```

네이티브 운영 환경에서는 다음과 같이 CA와 Cloudflare Access 설정을 지정합니다.

```sh
export STEP_CA_URL=https://step-ca.example.internal
export STEP_CA_ROOT=/etc/axum/root_ca.crt
export STEP_CA_PROVISIONER=axum-eap
export STEP_CA_PROVISIONER_PASSWORD_FILE=/etc/axum/axum-eap-password

export VPN_STEP_CA_URL=https://vpn-step-ca.example.internal
export VPN_STEP_CA_ROOT=/etc/axum/vpn_root_ca.crt
export VPN_STEP_CA_PROVISIONER=axum-vpn
export VPN_STEP_CA_PROVISIONER_PASSWORD_FILE=/etc/axum/axum-vpn-password

# step 실행 파일이 PATH에 없다면 지정합니다.
export STEP_BINARY=/usr/local/bin/step
export APP_ENV=production

# Cloudflare Zero Trust의 팀 도메인과 Access Application Audience Tag입니다.
export CF_ACCESS_ISSUER=https://your-team.cloudflareaccess.com
export CF_ACCESS_AUDIENCE=0123456789abcdef0123456789abcdef

cargo run --release
```

## Docker 개발 환경

`.env.development`의 `*_HOST_PATH` 값을 실제 호스트 파일 경로로 설정한 후 개발용
override 파일을 명시합니다.

```sh
docker compose \
  --env-file .env.development \
  -f compose.yaml \
  -f compose.development.yaml \
  config

docker compose \
  --env-file .env.development \
  -f compose.yaml \
  -f compose.development.yaml \
  up --build
```

컨테이너 내부 애플리케이션은 `0.0.0.0:3000`에서 요청을 받지만 호스트에는
`127.0.0.1:3000`으로만 게시됩니다. `CONTAINERIZED_DEVELOPMENT`는 개발용 override에서만
사용해야 하며 운영 환경에 설정하면 안 됩니다.

## Debian 컨테이너 배포

이미지는 Rust 빌더와 Debian Bookworm slim 런타임을 사용하는 멀티스테이지
빌드입니다. 런타임에는 애플리케이션, CA 인증서 검증용 패키지와 `step` CLI만 포함되며
UID 10001의 비특권 사용자로 실행됩니다.

```sh
cp .env.production.example .env.production
# .env.production의 Cloudflare/step-ca 값과 호스트 파일 경로를 수정합니다.
docker compose --env-file .env.production config
docker compose --env-file .env.production up -d --build
```

Compose는 컨테이너 루트 파일 시스템을 읽기 전용으로 두고 모든 Linux capability를
제거합니다. Root CA는 읽기 전용 바인드 마운트로, provisioner 비밀번호는 Compose secret을
통해 `/run/secrets`에 전달합니다. 임시 CSR과 PKCS#12 작업에는 메모리 기반 `/tmp`만
사용합니다.

호스트에는 `127.0.0.1:3000`으로만 게시하므로 같은 호스트의 `cloudflared`가
`http://localhost:3000`으로 연결하도록 구성할 수 있습니다. 추후 `cloudflared`를 같은
Compose 프로젝트에 포함한다면 호스트 포트를 제거하고 내부 서비스 주소
`http://portal:3000`을 사용하는 편이 좋습니다.

## 보안 모델

### Cloudflare Access 인증

운영 모드의 서버는 시작 시 `${CF_ACCESS_ISSUER}/cdn-cgi/access/certs`에서 공개 키를
가져오며, 모든 정적 페이지와 API 요청의 `Cf-Access-Jwt-Assertion`을 검증합니다. 서명
알고리즘은 RS256으로 제한하고 `iss`, `aud`, `exp`, `sub`를 확인합니다. 토큰이 없거나
유효하지 않으면 요청을 `401 Unauthorized`로 거부하며 CA 명령을 실행하지 않습니다. 서명
키의 `kid`가 변경되면 공개 키 목록을 한 번 갱신합니다.

Cloudflare 대시보드의 Access Application에 표시되는 **Application Audience (AUD) Tag**를
`CF_ACCESS_AUDIENCE`에 정확히 입력합니다. `CF_ACCESS_ISSUER`에는 Access의 팀 도메인만
입력하고 경로는 추가하지 않습니다.

이 JWT 검증은 터널 자체의 접근 통제를 대체하지 않습니다. 오리진 방화벽도
`cloudflared` 또는 로컬 리버스 프록시에서만 포털 포트에 접근할 수 있도록 제한해야
합니다.

### CA 및 개인키 처리

`STEP_CA_ROOT`와 `VPN_STEP_CA_ROOT`는 공개 CA 인증서이고 개인키가 아닙니다. 이 서비스에
Root CA 또는 intermediate CA 개인키를 복사하면 안 됩니다.

포털에서 입력한 가져오기 비밀번호로 암호화된 PKCS#12(`.pfx`) 파일이 다운로드됩니다.
이 파일에는 클라이언트 개인키, 클라이언트 인증서 체인과 Root CA 인증서가 포함되어 있어
Windows와 Android의 인증서 가져오기 화면에서 설치할 수 있습니다. 비밀번호는 패키징 중
임시 파일로만 사용되며 응답이나 로그에 기록하지 않습니다.

`.pfx`와 `.p12`는 동일한 PKCS#12 형식입니다. 포털은 `step certificate p12`의 기본
PKCS#12 인코딩을 사용합니다.

PFX에는 클라이언트 개인키가 포함되므로 HTTPS로만 제공하고, PFX 파일과 가져오기
비밀번호를 같은 경로로 공유하지 않는 것을 권장합니다. 필요한 경우 별도의 사용자 또는
기기 인증과 발급 제한도 적용해야 합니다.

## 운영 감사 로그

포털은 인증서 요청마다 JSON 감사 로그를 표준 출력에 기록합니다. 요청 ID, 접속 IP,
User-Agent, 검증된 Access 이메일과 subject, 인증서 CN, 성공 여부, HTTP 상태와 처리 시간이
포함됩니다. PKCS#12 비밀번호, 개인키, CSR 및 인증서 파일 내용은 기록하지 않습니다.
`systemd`로 실행한다면 `journalctl -u <서비스명>`에서 조회하고 보존 기간은 journald
정책으로 관리합니다.

리버스 프록시가 외부에서 받은 `X-Forwarded-For` 헤더를 제거하고 신뢰할 수 있는 값으로
새로 설정하는 경우에만 다음 값을 사용합니다.

```sh
export TRUST_FORWARDED_FOR=true
export RUST_LOG=eap_tls_cert_portal=info
```

이 설정이 없으면 위조 가능한 전달 헤더를 무시하고 TCP 연결 상대의 IP를 기록합니다.
IP와 User-Agent는 기기 식별의 보조 정보이며 인증된 기기 신원을 보장하지 않습니다.

## 운영 전 확인 사항

서비스를 운영 환경에 배포하기 전에 다음 항목을 확인합니다.

- WPA3와 VPN provisioner가 서로 분리되어 있고, 각 `clientAuth` 전용 템플릿과 의도한
  유효기간이 실제 발급 인증서에 적용되는지 확인합니다.
- 인증서 만료 전에 교체할 수 있도록 갱신 주기, 사용자 안내 및 기존 인증서 처리 절차를
  마련합니다.
- 외부 `step-ca` 서버의 이미지 또는 패키지 버전을 고정하고 CA 설정과 DB를 정기적으로
  백업합니다. 백업본으로 복구할 수 있는지도 별도로 시험합니다.
- 신규 PFX의 EKU와 유효기간을 검사하고 실제 WPA3 및 VPN 연결이 정상적으로 이루어지는지
  주기적으로 시험합니다.

## 규모 확대 시 개선 과제

현재 구성은 관리자가 발급과 기기 등록을 통제하는 소규모 환경에 적합합니다. 사용자와
기기가 늘어나거나 인증서별 즉시 차단이 필요해지면 다음 항목을 검토합니다.

- 인증서 일련번호(serial), 사용자, 기기명, 발급일과 만료일을 별도 저장소에 기록하고
  발급·갱신·폐기 이력을 관리합니다.
- FreeRADIUS에서 사용하는 EAP Identity는 인증서 허용 목록이 아니므로, 강한 기기별
  통제가 필요하면 인증서 일련번호 또는 SAN을 승인 DB와 연동하고 폐기 상태를 검사합니다.
- 개인키와 CSR을 가능하면 클라이언트 기기에서 생성하고, Windows TPM이나 MDM/SCEP 등
  개인키를 내보내기 어려운 저장 및 발급 방식을 사용합니다.
