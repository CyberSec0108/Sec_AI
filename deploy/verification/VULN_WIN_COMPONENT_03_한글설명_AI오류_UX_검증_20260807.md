# Windows 취약점 한글 설명·AI 오류 UX 검증

| 항목 | 값 |
|---|---|
| 검증일 | 2026-08-07 |
| 범위 | 후보별 공식 자료 기반 한글 접힘 설명, AI 연결 실패·시간 초과 안내, 재시도 |
| 상태 | 개발 소스·집중시험·실제 정적 파일 반영·내부 모델 호출 `PASS`; 인증 브라우저 육안 E2E는 미실행 |

## 1. 확인한 원인

- 화면의 `Failed to fetch`는 API가 반환한 한국어 4xx·5xx 메시지가 아니라 Browser의
  `fetch` Promise가 HTTP 응답을 받기 전에 거부될 때 나오는 원문 오류였다.
- API, Gateway, Model Gateway는 확인 시점에 모두 `healthy`였다.
- 화면과 같은 비식별 합성 공개 후보 한 건으로 내부 Model Gateway를 직접 호출했으며
  `openai/gpt-oss-120b`가 약 11.1초에 검증된 한국어 설명을 반환했다.
- 따라서 모델 기능의 지속 고장으로 단정하지 않고, 일시적인 Browser/API 연결 실패를
  사용자가 이해할 수 있게 처리하지 못한 UI 결함으로 분리했다.

## 2. 변경한 동작

- 각 공개 취약점 후보에 `공식 자료 기반 한글 설명` 접힘 영역을 추가했다.
- 이 영역은 추가 API나 AI 호출 없이 이미 검증된 NVD/OSV 구조화 필드만 사용한다.
- 확인 대상, 공개 자료 중요도, 제공 기관·최종 수정일, 결과의 의미와 다음 확인을 한국어로
  표시한다.
- 해당 설명은 `공식 번역이나 제조사의 취약 확정 판정이 아님`을 같은 영역에 명시한다.
- AI는 선택형 보충 설명으로 유지하며 연결 실패, 110초 Browser 시간 초과, HTTP 오류를
  구분한다. 연결 실패 때 원문 `Failed to fetch` 대신 한국어 안내와 재시도 버튼을 표시한다.
- NVD/OSV 기본 한국어 요약에서 AI 확인을 필수처럼 안내하던 문구를 공식 자료 링크 확인으로
  바꿨다.

## 3. 유지한 안전 경계

- 공개 자료 일치는 계속 영향 가능성 후보이며 공식 Finding 또는 제조사 확정 판정이 아니다.
- 구조화 한글 설명은 영문 원문을 공식 번역했다고 표시하지 않는다.
- AI 실패는 후보, 중요도, 기존 점검 결과를 변경하지 않는다.
- AI에는 기존과 동일하게 공개 후보 한 건의 제한 필드만 전달하며 장비 식별자, 경로, 증적,
  credential은 전달하지 않는다.
- 화면 출력은 `textContent`와 DOM node만 사용하고 `innerHTML`을 사용하지 않는다.

## 4. 검증 결과

```text
docker compose --project-directory . \
  -f deploy/compose/compose.yml -f deploy/compose/compose.dev.yml \
  run --rm dev-tools -m pytest \
  tests/unit/test_known_vulnerability_check.py \
  tests/unit/test_windows_component_vulnerability_check.py -q

24 passed, 1 existing Starlette deprecation warning
```

```text
docker compose ... run --rm dev-tools -m ruff check \
  src/security_audit/application/known_vulnerability_check.py \
  src/security_audit/application/component_vulnerability_check.py \
  tests/unit/test_windows_component_vulnerability_check.py

All checks passed!
```

```text
docker compose ... run --rm dev-tools -m mypy \
  src/security_audit/application/known_vulnerability_check.py \
  src/security_audit/application/component_vulnerability_check.py

Success: no issues found in 2 source files
```

```text
node --check apps/web/static/app/vulnerability-check.js

PASS
```

실행 중인 Gateway에서 JavaScript와 CSS를 다시 받아 HTTP 200과 다음 문자열 반영을 확인했다.

- `공식 자료 기반 한글 설명`: `True`
- `AI 연결이 원활하지 않습니다`: `True`
- `.vulnerability-public-explanation`: `True`
- API, Gateway, Model Gateway: 모두 `healthy`

## 5. 검증 한계와 남은 범위

- `tests/unit/test_windows_component_vulnerability_check.py`까지 strict mypy 대상에 넣으면 이
  변경 전부터 존재한 `JsonValue` type narrowing 오류 149건으로 실패한다. 새 시험은 정적
  문자열 계약만 추가했으며 변경한 운영 source 2개는 strict mypy를 통과했다.
- 로그인된 실제 748건 결과에서 접기, 키보드, 모바일 배치를 확인하는 Browser 육안 E2E는
  아직 수행하지 않았다.
- 공식 한국어 번역문을 제공하는 기능이 아니다. 공급자 권고·VEX 기반 확정 적용성과 검증된
  수정 버전 계산은 후속 `VULN-03~05` 범위다.
