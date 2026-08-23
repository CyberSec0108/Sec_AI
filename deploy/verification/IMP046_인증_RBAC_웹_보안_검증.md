# IMP-046 인증·권한·Web 보안 구현·검증 기록

| 항목 | 결과 |
|---|---|
| 구현 단계 | `IMP-046` |
| 검증일 | 2026-07-24 |
| 개발 프로필 | `DEV-LOCAL` |
| 결과 | `PASS_WITH_DEV_LIMITATIONS` |
| 다음 단계 | `IMP-048` KISA 질문에 필요한 근거 찾기 |

## 1. 사용자가 얻게 된 기능

Sec_AI Web 화면을 열면 이제 바로 점검 화면이 노출되지 않고 로그인 화면이 먼저 열린다.

```text
사용자 이름·비밀번호
→ 개발용 두 번째 인증
→ 서버가 계정·역할·조직·할당 PC를 확인
→ 허용된 화면과 API만 제공
```

현재 개발 계정은 `local-owner`라는 개인별 이름을 사용한다. 비밀번호와 개발용 두 번째 인증코드는 source나 이 문서에 기록하지 않고 `runtime/dev-secrets/`의 보호된 파일로만 주입한다.

## 2. 구현한 보안 경계

- Argon2id 비밀번호 저장, 9~128자·문자·숫자·특수문자 조합과 기본 blocklist
- 비밀번호 30일 만료, 로그인 10회 실패 시 15분 잠금
- 비밀번호 확인 뒤 세션을 교체하고 개발용 두 번째 인증을 완료한 뒤 다시 교체
- 브라우저에는 무작위 opaque session ID만 저장하고 PostgreSQL을 세션 정본으로 사용
- 일반 사용자·보안담당자 30분, 승인자·관리자 15분 미사용 만료, 전체 8시간 절대 만료
- 계정 credential version 또는 역할 assignment version 변경 시 기존 세션 즉시 폐기
- session-bound CSRF token, exact Origin/Referer와 Fetch Metadata 확인
- 브라우저의 자동 `/favicon.ico` 요청을 인증 예외 204로 처리해 pre-auth 쿠키를 교체하지 않음
- loopback 전용 `DEV-LOCAL`에서 브라우저가 검증한 `same-origin` 요청은 세션 CSRF 일치 시 허용하고 `cross-site`는 계속 거부
- `USER`, `SECURITY_OFFICER`, `APPROVER`, `ADMIN` 중앙 permission 표와 deny-by-default
- 조직과 할당 PC 범위를 full page, HTMX fragment, JSON API, SSE 연결, download마다 서버에서 재확인
- 다른 조직·PC의 존재를 노출하지 않도록 범위 밖 ID는 `404`, 범위 안 권한 부족은 `403`
- 로그인·로그아웃·허용·거부 결과를 원본 token이나 PC 식별값 없이 PostgreSQL 감사 이벤트로 저장
- CSP, frame 차단, MIME sniffing 차단, referrer·browser capability 제한과 `no-store`

기존 개발용 POST 화면도 인증이 켜진 환경에서는 동일한 로그인 세션의 CSRF 값만 허용한다.

## 3. 실제 실행 검증

`tools/verify-imp046-auth-rbac-web-security.ps1`이 실행 중인 `http://localhost:18480`에 실제 요청을 보내 다음 17개를 확인했다.

| 시험 | 결과 |
|---|---|
| 익명 사용자를 로그인 화면으로 이동 | PASS |
| 로그인 화면 제공 | PASS |
| 브라우저 favicon 요청 뒤에도 pre-auth CSRF 유지 | PASS |
| 비밀번호 뒤 두 번째 인증 요구 | PASS |
| 두 번째 인증 화면 제공 | PASS |
| 비밀번호+두 번째 인증 성공과 세션 교체 | PASS |
| 로그인 뒤 홈 화면·보안 header 제공 | PASS |
| 할당된 PC 접근 | PASS |
| 다른 PC IDOR를 `404`로 차단 | PASS |
| 다른 조직 IDOR를 `404`로 차단 | PASS |
| HTMX fragment에서 범위 재확인 | PASS |
| SSE 연결에서 범위 재확인 | PASS |
| `USER` 원본 download를 `403`으로 차단 | PASS |
| cross-site logout CSRF를 `403`으로 차단 | PASS |
| 거부된 CSRF가 정상 세션을 종료하지 않음 | PASS |
| 정상 logout이 세션을 폐기 | PASS |
| 폐기된 세션의 API 재연결을 `401`로 차단 | PASS |

실행 결과는 `17 passed / 0 failed`였고, secret 출력은 0건이다. PostgreSQL migration은 `0005_imp046`, 실제 감사 이벤트 저장도 확인했다.

전체 회귀 결과:

- Pytest `417 passed`
- JSON Schema 14종·example 26건 PASS
- Ruff PASS
- mypy strict 210 source files PASS
- AIStor 포함 Core 9개 container `healthy`

## 4. 다시 실행하는 방법

개발 secret이 아직 없다면 다음을 한 번 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Init -AIStorLicensePath <라이선스 파일 경로>
```

그 다음 전체 서비스와 검증을 실행한다. `core.ps1 -Action Up`은 migration 뒤 DEV 계정을 idempotent하게 준비하므로 새 PC에서도 별도 계정 명령이 필요 없다. 계정만 다시 확인해야 할 때는 `tools/bootstrap-dev-auth.ps1`을 수동으로 재실행할 수 있다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Up
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-imp046-auth-rbac-web-security.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

로그인 주소는 `http://localhost:18480/auth/login`이다. 개발 비밀번호와 두 번째 인증코드는 `runtime/dev-secrets/auth_dev_password`, `runtime/dev-secrets/auth_dev_mfa_code` 파일을 해당 PC에서만 열어 확인하고 화면공유·채팅·로그에 붙여 넣지 않는다.

## 5. 아직 운영 승인이 아닌 이유

이번 결과는 개발 PC의 합성 조직·PC와 `DEV-LOCAL` 프로필을 시험한 것이다.

- 개발용 두 번째 인증은 실제 WebAuthn이 아니므로 Pilot용 MFA 또는 AAL2 완료로 주장하지 않는다.
- 현재 주소는 localhost HTTP다. 운영 `__Host-` Secure cookie, 실제 hostname·TLS·WebAuthn RP ID는 아직 적용하지 않았다.
- 조직 OIDC, 실제 named account provisioning, WebAuthn 등록·복구·step-up은 Pilot Gate다.
- download 시험 파일은 권한 확인용 합성 문자열이며 원본 증적 다운로드 기능은 계속 닫혀 있다.
- SSE는 현재 한 번의 합성 event로 연결·재연결 권한을 시험했다. 장시간 stream의 주기적 재검사는 실제 chat/진행 stream 구현 때 다시 시험한다.
- 앱 내 브라우저가 연결되지 않아 이번 차수의 screenshot 기반 시각검토는 수행하지 못했다. HTTP와 HTML 계약 검증은 통과했으며 실제 브라우저 접근성·화면 크기별 검토는 `IMP-054`와 Pilot 인수에서 수행한다.

따라서 `PASS_WITH_DEV_LIMITATIONS`는 IMP-046 개발 완료를 뜻하며 운영 인증 승인, 실제 증적 공개 또는 Pilot 배포 승인을 뜻하지 않는다.
