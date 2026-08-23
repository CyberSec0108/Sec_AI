# Windows Launcher 미연결 복구 UI 검증

| 항목 | 값 |
|---|---|
| 검증일 | 2026-08-07 |
| 범위 | Windows 결과 화면의 실행 파일 다운로드·열기 안내·연결 재확인·원클릭 복귀 |
| 상태 | 개발 소스·집중시험·정적 파일 반영 `PASS`; 실제 EXE를 사용한 새 탭 Browser E2E는 미실행 |

## 1. 해결한 문제

기존 결과 화면은 Launcher token이 없거나 loopback 통신이 끊기면 실행 파일을 열라는 문장만
표시했다. 현재 Windows EXE는 설치 프로그램이 아니며 브라우저가 다운로드한 EXE를 임의로
실행할 수 없으므로, 처음 사용하는 사용자는 다음 행동을 찾기 어려웠다.

미연결 상태에 다음 네 가지 행동을 직접 표시하도록 변경했다.

1. `점검 프로그램 다운로드` — `/ui/dev-downloads`를 새 탭으로 연다.
2. `다운로드한 파일 여는 방법` — 다운로드 아이콘과 `Ctrl+J` 사용법을 펼친다.
3. `연결 다시 확인` — 현재 탭에서 Launcher token과 `127.0.0.1:18481` 상태를 다시 확인한다.
4. `원클릭 점검으로 돌아가기` — `/?new_scan=1`에서 기준과 동의를 다시 확인한다.

현재 EXE가 설치 프로그램이 아니며 이미 받은 파일은 다시 다운로드할 필요가 없다는 설명,
개발시험용 PC 제한과 Windows·조직 보안 경고를 임의로 우회하지 말라는 안내도 함께 표시한다.

## 2. 새 탭 연결 흐름

```text
기존 결과 탭에서 실행 안내 표시
→ 사용자가 EXE를 직접 실행
→ EXE가 /ui/launcher-connect#launcher_token=... 새 탭을 엶
→ 새 탭 sessionStorage에 token 저장
→ 2분 제한 secai_launcher_continuation 저장 이벤트를 기존 탭이 수신
→ 새 탭은 기존 홈→결과 자동 시작 흐름 진행
→ 기존 탭은 [연결 다시 확인]으로 RUNNING/COMPLETED 상태에 다시 연결
```

`start_scan=1`과 유효한 사용자 동의가 남아 있고 Launcher가 `READY`, `CANCELLED` 또는
`FAILED`이면 기존 자동 scan/retry 흐름을 재사용한다. 다른 탭이 이미 시작해 `RUNNING`이면
중복 시작하지 않고 진행 상태만 연결한다. 동의가 만료됐으면 자동 시작하지 않고 원클릭
점검으로 돌아가 다시 확인하도록 안내한다.

## 3. 유지한 보안 경계

- 브라우저가 EXE를 자동 실행하거나 보안 경고를 우회하지 않는다.
- Launcher token은 URL query나 서버 로그가 아니라 기존 fragment handoff를 사용한다.
- 새 탭은 token을 `sessionStorage`에 보존한다.
- 탭 사이 임시 전달값은 2분 만료 시각과 exact 43자 token 형식을 검증한다.
- 정상 수신 후 `secai_launcher_continuation`은 즉시 삭제하고 현재 탭 session에만 남긴다.
- loopback 요청은 기존 exact origin, `127.0.0.1:18481`, token header 계약을 유지한다.
- 기존 2분 점검 동의, 관리자 동의, 기준 snapshot 정책을 늘리거나 우회하지 않는다.
- 상단 제목줄에 `프로그램 다운로드` 텍스트 메뉴를 다시 추가하지 않았다.

## 4. 검증 결과

```text
docker compose --project-directory . \
  -f deploy/compose/compose.yml -f deploy/compose/compose.dev.yml \
  run --rm dev-tools -m pytest tests/unit/test_imp040_product_ui.py -q \
  -k "disconnected_state_offers_launcher_recovery_actions or launcher_connection_handoff"

2 passed, 11 deselected, 1 existing Starlette deprecation warning
```

```text
docker compose ... run --rm dev-tools -m pytest \
  tests/unit/test_imp040_product_launcher.py \
  tests/unit/test_product_result_consistency_ui.py -q

19 passed
```

```text
docker compose ... run --rm dev-tools -m ruff check \
  tests/unit/test_imp040_product_ui.py

All checks passed!
```

```text
node --check apps/web/static/app/product.js
node --check apps/web/static/app/product-results.js
node --check apps/web/static/app/launcher-connect.js

PASS
```

실행 중인 Gateway에서 변경 JavaScript와 CSS를 다시 받아 HTTP 200과
`retryLauncherConnection`, `secai_launcher_continuation`, `.launcher-recovery-actions` 반영을
확인했다. API와 Gateway container는 모두 `healthy`였다.

## 5. 확대 회귀의 기존 실패

관련 시험 네 파일의 확대 실행은 `35 passed, 4 failed`였다. 실패 네 건은 이번 변경 경로가
아니다.

- 세 건: `dev-tools` 실행 환경에 `/run/secrets/demo_csrf_token`이 없어 기존 TestClient 홈
  요청이 시작 전에 중단됐다.
- 한 건: 현재 화면에서 이미 제거된 과거 `승인 전 시험 판정` 문구를 기대한다.

기대값이나 secret 계약을 이번 UI 변경에서 우회하지 않았다.

## 6. 남은 범위

- 실제 Windows EXE 실행→새 탭 handoff→기존 결과 탭 재확인의 Chrome E2E
- 다운로드에 걸리는 시간이 점검 동의 2분을 넘었을 때의 사용자 육안 확인
- 설치형 Helper, custom protocol, 자동 업데이트·삭제·조직 서명·SmartScreen 인수

이번 변경은 portable EXE 유지 기간의 복구 UI이며 설치형 전환 완료가 아니다.
