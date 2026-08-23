# `apps` 영역 코딩 에이전트 지침

적용 범위는 `apps/**`다. 루트 [`AGENTS.md`](../AGENTS.md)를 먼저 읽고, 실행 구조의 상세는
[`README.md`](README.md)를 확인한다.

## 1. 계층 책임

`apps`는 실행 Adapter 계층이다. HTTP 요청, 인증 context, DTO, Web 응답, Celery 진입점과
모델 Gateway를 담당한다. 규칙 판정, 장비 수집, SQL 조합, 핵심 비즈니스 정책을 route나
템플릿에 넣지 않는다.

| 위치 | 책임 | 주요 진입점 |
|---|---|---|
| `api` | FastAPI router, 인증·CSRF, REST/SSE, Jinja2 context | `main.py` |
| `web/templates` | 화면과 공통 Jinja2 macro | `components/audit_ui.html` |
| `web/static/app` | 화면별 JS, 공통 CSS, 제한 Markdown | `app.css`, `restricted-markdown.js` |
| `model_gateway` | 외부/로컬 OpenAI 호환 모델 격리 | `main.py` |
| `worker` | Celery task와 복구 인수 CLI | `celery_app.py`, `tasks.py` |
| `scheduler` | Celery Beat 진입 골격 | `celery_app.py` |

## 2. 기능별 진입점

| 기능 | API | Web |
|---|---|---|
| 홈·Launcher·결과 센터 | `api/product.py` | `product_home.html`, `product*.js` |
| 로그인·계정 | `authentication.py`, `auth_support.py` | `login.html`, `mfa.html`, 계정 템플릿 |
| 점검 기준 | `assessment_criteria.py` | `criteria_form.html`, `criteria-reset.js` |
| Windows 결과·AI·PDF | `result_ai_explanation.py`, `result_reports.py` | `product_results.html`, `result_ai_analysis.html` |
| Linux 중앙/one-shot | `linux_audit.py`, `linux_oneshot.py` | `linux_*.html`, `linux-*.js` |
| Aruba Switch | `switch_audit.py` | `switch_scan.html`, `switch_results.html` |
| 가이드 대화·검색 | `chat_conversation.py`, `guide_store.py` | `guide_chat.html`, `guide-chat.js` |
| 알려진 취약점 후보 | `vulnerability_check.py` | `vulnerability_check.html`, `vulnerability-check.js` |
| 다운로드 | `dev_signed_downloads.py` | `dev_signed_downloads.html` |
| 복구 상태 | `queue_recovery.py`, `storage_recovery.py` | 대응 상태 템플릿 |

새 router를 만들면 `api/main.py`에 명시적으로 등록하고 공개 예외 경로가 늘어나는지
검토한다. route가 직접 DB model을 반환하거나 직접 규칙 판정을 만들지 않게 한다.

## 3. API·인증 규칙

- Pydantic DTO는 프로젝트의 `extra="forbid"`, 길이·pattern·enum 제한을 따른다.
- 인증된 기능은 server-side principal, permission, organization/owner/asset scope를 확인한다.
- 상태 변경은 session-bound CSRF를 검증한다.
- 사용자 UUID나 asset UUID를 받았다는 이유만으로 접근을 허용하지 않는다.
- 내부 path, stack, SQL, token과 secret 값을 오류 응답에 포함하지 않는다.
- SSE는 중단·timeout·재시도·중복 요청을 고려하고 완료 상태를 원자적으로 저장한다.
- AI·검색·CVE upstream 장애가 Windows/Linux/Switch의 기존 점검 결과를 훼손하면 안 된다.

인증 예외, download, fragment, SSE route를 바꾸면 비로그인·타 사용자·다른 조직·변조·
replay 시험을 반드시 확인한다.

## 4. Web 규칙

- 공통 header·navigation·theme은 `templates/components/audit_ui.html`에서 수정한다.
- 홈 카드의 제목·설명·상태·링크 정본은
  `src/security_audit/application/product_features.py`다.
- inline script와 CSP `unsafe-inline`을 추가하지 않는다.
- 외부 문자열은 Jinja2 autoescape, `textContent`, DOM allowlist를 사용한다.
- 모델 출력은 `restricted-markdown.js`를 통과시키며 raw HTML·image·위험 URL을 실행하지 않는다.
- 상태를 색상만으로 표현하지 않고 label·텍스트를 함께 제공한다.
- keyboard focus, label, 작은 화면, 주야간 theme을 확인한다.
- 실제 API·권한·감사·시험이 없으면 버튼을 활성화하거나 `LIVE`로 표시하지 않는다.

## 5. Worker·Model Gateway 규칙

- Queue payload에는 대용량 결과·원본 증적·credential이 아니라 식별자만 넣는다.
- task는 redelivery될 수 있으므로 DB unique key와 transaction으로 멱등성을 보장한다.
- 복구 CLI는 Web route로 노출하지 않는다.
- Model Gateway token과 provider key는 `*_FILE` secret으로만 전달한다.
- 자동 provider fallback은 허용하지 않는다.
- 모델 capability를 운영 승인이나 로컬 vLLM 완료로 과장하지 않는다.

## 6. 변경·검증 순서

1. 기존 route·service·template·JS·test의 연결을 추적한다.
2. 사용자 동작 계약을 검증하는 작은 시험을 먼저 추가한다.
3. 핵심 동작은 `src/security_audit` 서비스에 구현하고 route는 조정만 한다.
4. 관련 Pytest와 Ruff를 실행한다.
5. type·API 계약 변경은 mypy, JS 변경은 `node --check`를 추가한다.
6. 인증·SSE·download 변경은 실제 HTTP 경계 시험을 추가한다.

대표 시험 위치:

- 제품 홈·공통 UI: `tests/unit/test_imp040_product_ui.py`
- 인증·RBAC: `tests/unit/test_imp046_auth_rbac_web_security.py`
- Linux: `tests/unit/test_linux_*`
- Switch: `tests/unit/test_switch_product_flow.py`
- 가이드 대화: `tests/unit/test_imp053_live_guide_chat.py`
- 취약점 후보: `tests/unit/test_known_vulnerability_check.py`

