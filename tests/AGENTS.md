# `tests` 영역 코딩 에이전트 지침

적용 범위는 자동화 시험과 합성 Fixture다. 루트 지침과 [`README.md`](README.md)를 먼저
읽는다.

## 1. 시험 분류

| 위치 | 목적 |
|---|---|
| `unit` | 순수 로직, service, route/UI source 계약 |
| `contract` | JSON Schema, Package, API·보안 계약 |
| `integration` | DB·Queue·service 연결 |
| `e2e` | 사용자·Collector 종단 흐름 |
| `browser` | 실제 DOM·접근성·반응형·보안 표시 |
| `fixtures` | 비식별 합성 입력·기대값 |

## 2. 작성 규칙

- 로직 변경은 가능한 한 실패하는 가장 작은 시험부터 작성한다.
- 하나의 시험은 하나의 명확한 동작을 검증한다.
- 시험 이름에 조건과 기대 동작을 드러낸다.
- network, 시간, UUID, random, filesystem과 외부 모델을 격리한다.
- 실제 token, password, cookie, private key, 사용자명, 조직명, host 정보를 넣지 않는다.
- 테스트 통과를 위해 `skip`, `only`, 느슨한 존재 검사, 요구사항과 다른 hardcode를 추가하지 않는다.
- 기존 실패가 있으면 이번 변경과 관련 있는지 분리하고 숨기지 않는다.

## 3. 보안·판정 시험 최소 조건

- 인증: 비로그인, 만료, 타 사용자·조직·자산, CSRF, IDOR, replay
- Collector: 잘못된 argv, timeout, 큰 출력, 권한 부족, malformed evidence
- 규칙: PASS/FAIL뿐 아니라 ERROR/REVIEW/N/A와 false PASS
- DB: unique key, transaction rollback, RLS, append-only
- AI/RAG: 근거 없음, citation mismatch, prompt injection, timeout, 중단
- CVE: stale/expired/no feed, 후보와 확정 구분, cache fallback
- UI: XSS, 위험 URL, keyboard, focus, mobile, theme

## 4. 실행

잠긴 Docker 개발 image를 사용한다.

```powershell
# 전체 unit·contract
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action Test

# 전체 표준 Gate
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action All
```

집중시험은 `docker compose ... run --rm dev-tools -m pytest <파일>::<시험> -q` 패턴을
사용할 수 있다. 실제 secret 대신 명시적인 합성 test 값이나 fixture를 사용하며, 시험 때문에
runtime secret을 출력하지 않는다.

JavaScript를 바꾸면 관련 UI 시험과 `node --check`를 실행한다. 실제 DB·브라우저·VM이
필요한 시험을 실행하지 못하면 단위시험 통과와 실제 Gate 미검증을 구분해 보고한다.

