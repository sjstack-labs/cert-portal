# 기여 안내

## 개발 환경

- Rust stable 툴체인 (edition 2024)
- 화면 확인: `scripts/dev-preview.sh` (실제 CA 불필요, [README](README.md#화면-미리보기와-테스트) 참고)
- 실제 발급 확인: 테스트용 `step-ca`와 `step` CLI

## 커밋 전 확인

CI와 같은 검사를 로컬에서 실행합니다.

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## 프로젝트 약속

형식과 일반적인 Rust 규칙은 `rustfmt`와 `clippy`를 따릅니다. 도구가 잡지 못하는 이
프로젝트만의 약속은 다음과 같습니다.

1. **보안 불변식을 먼저 확인합니다.** 인증, 발급 흐름, CA 설정, 배포 설정을 바꾸기 전에
   [`docs/security-model.md`](docs/security-model.md)를 읽고, 불변식이 바뀐다면 문서와
   `src/router_tests.rs`를 함께 고칩니다.
2. **새 경로는 `handlers::router` 안에 추가합니다.** 인증 미들웨어와 보안 헤더가 자동으로
   적용됩니다. 추가한 경로는 `router_tests.rs`의 `ALL_ROUTES`에도 넣어 인증 테스트 대상에
   포함합니다.
3. **사용자에게 보이는 문구는 한국어 고정 문구로 씁니다.** 서버 오류는
   `error::internal_error`로 만들고, 핸들러에서 `error::with_request_id`로 요청 ID를 붙입니다.
   라이브러리 오류 메시지나 `step` 출력은 응답에 넣지 않고 로그에만 남깁니다.
4. **로그 이벤트 이름은 `snake_case`로 씁니다.** 감사 대상 이벤트에는 `audit = true`와
   `request_id`, `client_ip`, `authenticated_email`, `authenticated_subject`를 넣고, 요청이
   끝나는 이벤트에는 `status`와 `duration_ms`를 넣습니다. 사용자 입력은 길이를 제한해
   기록하고, 비밀번호·개인키·provisioner 비밀번호는 기록하지 않습니다.
5. **화면에는 인라인 스크립트와 스타일을 쓰지 않습니다.** CSP가 `'self'`만 허용하므로
   `static/app.js`, `static/app.css`에 작성합니다.
6. **실제 인프라 정보를 커밋하지 않습니다.** 도메인, IP, Access 팀 이름, 호스트 경로는
   `.env.*`(Git 제외)에만 둡니다. 예시 파일에는 `example.internal` 같은 자리표시자를 씁니다.

## 커밋 메시지

`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:` 접두어를 붙이고 한국어로 씁니다.
