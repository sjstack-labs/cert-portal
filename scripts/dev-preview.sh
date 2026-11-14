#!/bin/sh
# 실제 step-ca 없이 화면과 발급 흐름을 확인하는 미리보기 실행 스크립트입니다.
#
# 가짜 step이 더미 파일을 만들므로 다운로드되는 PFX는 실제 인증서가 아닙니다.
# 개발 모드라 인증 없이 127.0.0.1에서만 접속할 수 있습니다.
#
# 사용법:
#   scripts/dev-preview.sh                    # 정상 발급
#   PREVIEW_STEP_MODE=fail scripts/dev-preview.sh   # CA 거부(502) 화면 확인
#   PREVIEW_STEP_MODE=slow scripts/dev-preview.sh   # 타임아웃(504) 화면 확인
#   PORT=3100 scripts/dev-preview.sh          # 포트 변경
set -eu

cd "$(dirname "$0")/.."
dir="$(pwd)/target/dev-preview"
mkdir -p "$dir"

printf 'PREVIEW WPA3 ROOT CA (not a real certificate)\n' > "$dir/wpa3-root.crt"
printf 'PREVIEW VPN ROOT CA (not a real certificate)\n' > "$dir/vpn-root.crt"
printf 'unused\n' > "$dir/wpa3-password"
printf 'unused\n' > "$dir/vpn-password"

cat > "$dir/fake-step" <<'EOF'
#!/bin/sh
case "${PREVIEW_STEP_MODE:-ok}" in
  fail) echo "preview: simulated step-ca rejection" >&2; exit 1 ;;
  slow) sleep 30 ;;
esac
case "$1 $2" in
  "ca sign") printf 'PREVIEW CERTIFICATE (not valid)\n' > "$4" ;;
  "certificate p12") printf 'PREVIEW PFX (not a real PKCS#12 file)\n' > "$3" ;;
  *) exit 64 ;;
esac
EOF
chmod 755 "$dir/fake-step"

export APP_ENV=development
export BIND_ADDR="127.0.0.1:${PORT:-3000}"
export RUST_LOG="${RUST_LOG:-eap_tls_cert_portal=info}"
export STEP_BINARY="$dir/fake-step"
export STEP_TIMEOUT_SECS="${STEP_TIMEOUT_SECS:-3}"
export STEP_CA_URL=https://wpa3-ca.preview.invalid
export STEP_CA_ROOT="$dir/wpa3-root.crt"
export STEP_CA_PROVISIONER=preview-wpa3
export STEP_CA_PROVISIONER_PASSWORD_FILE="$dir/wpa3-password"
export VPN_STEP_CA_URL=https://vpn-ca.preview.invalid
export VPN_STEP_CA_ROOT="$dir/vpn-root.crt"
export VPN_STEP_CA_PROVISIONER=preview-vpn
export VPN_STEP_CA_PROVISIONER_PASSWORD_FILE="$dir/vpn-password"
export PREVIEW_STEP_MODE="${PREVIEW_STEP_MODE:-ok}"

echo "미리보기: http://${BIND_ADDR} (step 모드: ${PREVIEW_STEP_MODE})" >&2
exec cargo run --quiet
