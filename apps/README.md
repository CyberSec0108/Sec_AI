# `apps` 애플리케이션 계층 안내

이 폴더에는 Sec_AI를 실제 프로세스로 실행하는 진입점과 사용자 화면이 있습니다.

- HTTP·Web 요청은 `apps/api`가 받습니다.
- HTML·CSS·브라우저 JavaScript는 `apps/web`에 있습니다.
- 내부 LLM 연결은 `apps/model_gateway`가 격리합니다.
- Redis Queue 작업은 `apps/worker`가 처리합니다.
- 예약 실행 진입점은 `apps/scheduler`에 있습니다.

판정 규칙, 수집기, 인증 도메인, 저장소 구현 같은 핵심 로직은 이 폴더가 아니라
[`../src/security_audit`](../src/security_audit)에 둡니다. `apps`는 입력을 검증하고,
권한을 확인하고, 서비스 계층을 호출한 뒤 안전한 응답으로 변환하는 Adapter 계층입니다.

## 1. 전체 요청 흐름

```text
사용자 브라우저
  └─ Gateway(127.0.0.1:18480)
       └─ apps/api/main.py · FastAPI
            ├─ apps/web · Jinja2/JavaScript/CSS
            ├─ src/security_audit · 서비스/도메인/저장소
            ├─ PostgreSQL · 정본과 RLS
            ├─ Redis → apps/worker · 비동기 작업
            ├─ AIStor/ClamAV · 증적 저장/악성코드 검사
            └─ apps/model_gateway → 승인된 OpenAI 호환 모델 endpoint
```

Gateway와 Docker 설정은 `apps` 밖의 [`../deploy`](../deploy)에 있습니다. 외부에서
들어오는 기본 개발 주소는 `http://localhost:18480`이며 API 컨테이너의 내부 포트는
`8000`입니다.

## 2. 디렉터리 구조

```text
apps/
├─ api/                 FastAPI, 인증 middleware, Web/API/SSE/download route
├─ model_gateway/       내부 전용 OpenAI 호환 모델 Gateway
├─ scheduler/           Celery Beat 실행 진입점
├─ web/
│  ├─ data/             개발 인수 결과를 보여 주는 고정 JSON
│  ├─ static/app/       공통 CSS와 화면별 브라우저 JavaScript
│  └─ templates/
│     ├─ components/    공통 Jinja2 component·fragment
│     └─ pages/         화면별 Jinja2 page
├─ worker/              Celery app, task, Queue/Storage 복구 검증 CLI
└─ __init__.py          Python application package 선언
```

## 3. 실행 프로세스

| 프로세스 | 진입점 | 기본 역할 | 외부 노출 |
|---|---|---|---|
| Audit API | `apps.api.main:app` | 인증, Web UI, REST/SSE, 결과·보고서·점검 흐름 | Gateway를 통해서만 노출 |
| Model Gateway | `apps.model_gateway.main:app` | 모델 설정과 토큰을 Core API에서 격리 | 내부 network 전용 |
| Worker | `apps.worker.celery_app:celery_app` | Redis Queue 소비, 늦은 ACK와 재전달 검증 | HTTP 노출 없음 |
| Maintenance Worker | 같은 Celery app, `maintenance` queue | Queue 복구 검증 작업 분리 | HTTP 노출 없음 |
| Scheduler | `apps.scheduler.celery_app:celery_app` | Celery Beat 실행 진입점 | HTTP 노출 없음 |

현재 `scheduler`는 Worker의 Celery app을 다시 내보내는 골격입니다. 이 폴더에는 별도의
정기 `beat_schedule`이 정의되어 있지 않습니다. 현재 등록된 명시적 Celery task는
`secai.maintenance.verify_delivery`이며 IMP-044 Worker 손실·재전달 인수시험용입니다.

## 4. `apps/api` 파일 역할

### 공통 진입점과 보안

| 파일 | 역할 |
|---|---|
| `main.py` | FastAPI 생성, 모든 router 등록, 정적 파일 mount, 전역 인증 middleware와 보안 header 적용 |
| `auth_support.py` | 세션 인증, 현재 사용자, 관리자 확인, 인증 서비스 연결 |
| `authentication.py` | 로그인, MFA, 계정 생성 요청, 계정 승인·중지, 프로필·비밀번호, logout |
| `browser_csrf.py` | 로그인 세션에 묶인 CSRF 발급·검증 |
| `auth_bootstrap.py` | DEV-LOCAL 최초 계정 준비. 비밀번호나 MFA 원문을 출력하지 않음 |
| `health.py` | PostgreSQL·Redis·AIStor·ClamAV 준비 상태 확인 |
| `container_health.py` | API 컨테이너 healthcheck 진입점 |

`main.py`는 OpenAPI, Swagger UI와 ReDoc을 공개하지 않습니다. 인증이 켜져 있으면
health, 정적 파일, 로그인·MFA·가입, 제한된 Linux 원샷 교환/제출, 정확한 임시 파일
fetch 경로 외에는 모두 세션 인증을 요구합니다. 예외 경로를 추가하면 공개 공격면이
늘어나므로 관련 인증·CSRF·rate-limit 통합시험이 필요합니다.

### 제품 화면과 점검 흐름

| 파일 | 역할 |
|---|---|
| `product.py` | 홈, 도움말, Windows Launcher 연결, 결과 센터, AI 분석 화면, 기능 상태 registry |
| `assessment_criteria.py` | 개인 기준, 조직 기본 기준, 실행 시점 기준 snapshot 선택 |
| `security_surface.py` | 조직·자산 scope가 적용된 전체 화면, fragment, SSE, 합성 download 경계 |
| `linux_audit.py` | 자동 식별된 지원 Linux 자산의 U-01~U-67 점검·결과·AI·PDF |
| `linux_oneshot.py` | 사용자가 Linux 안에서 실행하는 원샷 점검 생성·코드 교환·온라인 제출·오프라인 업로드 |
| `switch_audit.py` | 등록 Aruba AOS-CX 장비 점검 입력·실행·결과·AI·사용자/기술 PDF |
| `dev_signed_downloads.py` | DEV-LOCAL Windows·배포판 자동 식별 Linux 공용 임시 서명 파일과 1회용 다운로드 코드 |

`linux_audit.py`와 `linux_oneshot.py`는 목적이 다릅니다.

- `linux_audit.py`: 중앙 서비스가 사전 등록된 개발 VM에 제한된 SSH Adapter로 접근하는
  관리형 점검입니다.
- `linux_oneshot.py`: 중앙 서비스가 서버에 들어가지 않고 사용자가 서버 안에서 실행한
  프로그램이 결과 Package를 제출하는 자가 점검입니다.

두 경로의 credential, 자산 scope, 결과 보증 수준을 합치면 안 됩니다.

### AI·가이드·보고서

| 파일 | 역할 |
|---|---|
| `chat_conversation.py` | 로그인 사용자의 가이드 대화, 편집·재시도·분기, citation, SSE 생성 상태 |
| `guide_store.py` | 승인된 KISA 가이드 inventory와 PDF/page 조회 |
| `result_ai_explanation.py` | 공식 판정을 바꾸지 않는 결과 설명·후속 질문·재점검 비교 JSON/SSE |
| `result_reports.py` | 사용자용·기술 검증용 PDF 생성, owner/capability 기반 다운로드 |
| `model_runtime.py` | provider token을 숨긴 안전한 모델 Runtime 상태 표시 |

AI 출력은 신뢰하지 않습니다. AI가 `PASS/FAIL/ERROR/REVIEW/N/A`를 새로 만들거나
Finding, Audit Pack, 증적을 변경할 수 없습니다. 브라우저 출력은
`restricted-markdown.js` 계약을 통과시켜야 합니다.

### 운영 진단 화면

| 파일 | 역할 |
|---|---|
| `queue_recovery.py` | 민감 payload를 제외한 PostgreSQL Outbox/Queue 복구 상태 |
| `storage_recovery.py` | PostgreSQL·AIStor·Redis 복구 시험 상태 |

이 화면들은 상태 표시용입니다. 실제 복구 시험 명령은 `apps/worker`의 내부 CLI에 있고
일반 HTTP 요청으로 노출하지 않습니다.

## 5. `apps/web` 구성

### `templates/pages`

화면 단위 Jinja2 템플릿입니다. 파일 이름은 대체로 API 기능과 대응합니다.

| 화면 영역 | 대표 템플릿 |
|---|---|
| 로그인·계정 | `login.html`, `mfa.html`, `register.html`, `account_settings.html`, `admin_accounts.html` |
| Windows 제품 | `product_home.html`, `launcher_connect.html`, `product_results.html`, `result_ai_analysis.html` |
| Linux | `linux_scan.html`, `linux_self_scan.html`, `linux_results.html`, `linux_ai.html` |
| Switch | `switch_scan.html`, `switch_results.html` |
| 가이드·AI | `guide_chat.html`, `guide_store.html`, `model_runtime.html` |
| 운영 상태 | `queue_recovery.html`, `storage_recovery.html`, `session.html` |
| 다운로드 | `dev_signed_downloads.html` |

### `templates/components`

- `audit_ui.html`: 공통 header, navigation, 상태 표시 macro
- `criteria_form.html`: 점검 기준 입력 component
- `security_asset_fragment.html`: scope가 적용된 자산 보안 fragment

### `static/app`

- `app.css`: 전체 화면, theme, 반응형, 상태 카드 공통 스타일
- `theme.js`: 주간·야간 theme
- `restricted-markdown.js`: 제한형 Markdown AST·DOM renderer
- 나머지 `*.js`: 같은 이름의 화면에서 API 호출, polling, SSE, 상태 갱신 담당

브라우저 JavaScript는 CSP 때문에 inline script를 사용하지 않습니다. 외부 입력과 AI
출력은 `innerHTML`로 직접 삽입하지 말고 `textContent`, DOM allowlist 또는 제한형
Markdown renderer를 사용합니다. 상태 변경 요청에는 `X-CSRF-Token` 또는 승인된 form
CSRF 값을 포함합니다.

### `data`

`imp034~039_*.json`은 Windows Collector 개발 인수 상태를 UI에 표시하기 위한 고정
자료입니다. 현재 DB 정본이나 운영 승인 자료가 아니며, 파일명이 오래됐다는 이유로
공식 Release 상태로 승격하면 안 됩니다.

## 6. `apps/model_gateway`

Core API가 OpenRouter 또는 향후 local vLLM을 동일한 내부 계약으로 호출하도록 만드는
격리 계층입니다.

| 파일 | 역할 |
|---|---|
| `main.py` | 내부 FastAPI, capability, 일반 completion, SSE completion |
| `verify_runtime.py` | 비민감 연결시험과 모델 capability Gate |
| `container_health.py` | 컨테이너 live healthcheck |

주요 내부 endpoint:

```text
GET  /health/live
GET  /health/ready
GET  /internal/v1/capabilities
POST /internal/v1/chat/completions
POST /internal/v1/chat/completions/stream
```

`/internal/v1/*`는 `X-SecAI-Gateway-Token`을 요구합니다. API key와 Gateway token은
환경 변수 원문이 아니라 `*_FILE` secret 경로로 전달해야 합니다. 자동 모델 fallback은
허용하지 않으며 모델 장애 시 Core 점검 기능은 계속 동작해야 합니다.

## 7. `apps/worker`와 `apps/scheduler`

| 파일 | 역할 |
|---|---|
| `celery_app.py` | Redis broker, JSON-only payload, late ACK, prefetch 1, remote control 차단 설정 |
| `tasks.py` | UUID 같은 식별자만 받는 등록 task |
| `recovery_cli.py` | IMP-044 Outbox 발행·Worker kill·재전달·중복 방지 내부 인수 CLI |
| `storage_recovery_cli.py` | IMP-045 PostgreSQL·AIStor·Redis 복구 내부 인수 CLI |
| `container_health.py` | Worker 컨테이너 healthcheck |
| `scheduler/celery_app.py` | 같은 Celery app을 Beat 진입점으로 재사용 |

Queue payload에 원본 증적, 비밀번호, token, 대용량 결과를 넣지 않습니다. task에는
식별자만 보내고 Worker가 PostgreSQL 정본을 다시 읽습니다. task는 재전달될 수 있으므로
DB unique key, transaction과 멱등 처리를 유지해야 합니다.

`recovery_cli.py`와 `storage_recovery_cli.py`는 인수시험 전용이며 Web route가 아닙니다.
일반 운영 도구처럼 임의 실행하지 말고 해당 검증 문서와 정확한 대상 ID를 확인합니다.

## 8. 실행 방법

프로젝트는 host Python보다 잠긴 Docker 환경을 기준으로 합니다. 프로젝트 루트의
PowerShell에서 실행합니다. 아래 두 시작 명령 `Up`과 `UpWithoutAIStor`는 환경에 맞는
하나만 선택합니다.

```powershell
# 설정 확인
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Config

# 전체 개발 서비스 시작(AIStor license 포함)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Up

# AIStor license가 없는 제한 시험 환경에서만 사용
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action UpWithoutAIStor

# 상태와 의존성 확인
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

서비스를 직접 디버깅할 때의 Python 진입점은 다음과 같지만, 의존성·secret·DB가 준비된
환경에서만 사용합니다.

```text
python -m uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
python -m uvicorn apps.model_gateway.main:app --host 127.0.0.1 --port 8010
python -m celery -A apps.worker.celery_app:celery_app worker
python -m celery -A apps.scheduler.celery_app:celery_app beat
```

Jinja2와 정적 파일 경로가 프로젝트 루트 기준 상대경로이므로 직접 실행할 때도 현재
작업 디렉터리를 프로젝트 루트로 유지합니다.

## 9. 주요 설정과 Secret

대표 설정 그룹은 다음과 같습니다.

| 그룹 | 대표 환경 변수 |
|---|---|
| 인증 | `SECAI_AUTH_*`, `SECAI_AUTH_SESSION_INDEX_KEY_FILE` |
| DB | `SECAI_POSTGRES_*`, `SECAI_POSTGRES_PASSWORD_FILE` |
| Queue | `SECAI_REDIS_*`, `SECAI_REDIS_PASSWORD_FILE` |
| 모델 | `SECAI_MODEL_GATEWAY_URL`, `SECAI_MODEL_GATEWAY_TOKEN_FILE`, `SECAI_LLM_*` |
| 저장·검사 | `SECAI_AISTOR_ENDPOINT`, `SECAI_CLAMAV_HOST`, `SECAI_CLAMAV_PORT` |
| Linux | `SECAI_LINUX_*`, `SECAI_LINUX_RUNTIME_ROOT` |
| 임시 다운로드 | `SECAI_DEV_SIGNED_DOWNLOAD_ENABLED`, `SECAI_DEV_SIGNED_DOWNLOAD_ROOT` |

실제 secret 값은 [`../runtime/dev-secrets`](../runtime/dev-secrets)에만 두며 코드, 템플릿,
JavaScript, Fixture, README, 로그에 기록하지 않습니다. 개발용 Ed25519 private key도
프로젝트 밖에 보관하며 `apps`에서는 공개키와 검증된 파일만 읽습니다.

## 10. 기능을 수정하거나 추가할 때

### 새 Web/API 기능

1. 외부 요청·응답 DTO와 route는 `apps/api/<기능>.py`에 둡니다.
2. 판정·수집·저장 핵심 로직은 `src/security_audit` 서비스 계층에 둡니다.
3. router를 `apps/api/main.py`에 명시적으로 등록합니다.
4. 화면은 `apps/web/templates/pages`, 공통 UI는 `components`에 둡니다.
5. JavaScript는 `apps/web/static/app`의 외부 파일로 작성합니다.
6. 인증, organization/user/asset scope, CSRF, IDOR, 입력 길이와 파일 크기를 검증합니다.
7. 정상 경로뿐 아니라 비로그인·타 사용자·변조·replay·timeout 시험을 추가합니다.

### 새 Worker task

1. 자유 명령이나 전체 payload가 아니라 allowlist된 task 이름과 식별자만 사용합니다.
2. DB transaction과 중복 실행 방지 key를 먼저 설계합니다.
3. Worker kill·Redis redelivery 뒤 결과가 중복되지 않는지 확인합니다.
4. 공개 HTTP route와 복구 인수 CLI를 분리합니다.

### 새 화면 출력

1. Jinja2 autoescape와 `textContent`를 우선 사용합니다.
2. LLM·증적·외부 문서를 HTML로 직접 실행하지 않습니다.
3. 키보드, 모바일, 주야간 theme와 상태색만으로 의미를 전달하지 않는지 확인합니다.
4. CSP를 약화하는 inline script, `unsafe-inline`, 임의 외부 URL을 추가하지 않습니다.

## 11. 검증 방법

프로젝트 전체 표준 검증:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

변경 범위에 따라 최소한 다음을 확인합니다.

| 변경 | 필수 확인 |
|---|---|
| Python route·service 연결 | 관련 Pytest, Ruff, mypy strict |
| 인증·권한·CSRF·download | 비로그인·타 scope·replay·변조 실제 HTTP 시험 |
| JavaScript | 관련 UI 계약 시험과 `node --check` |
| SSE·AI | 중단·timeout·부분 응답·금지 출력·공식 판정 불변 |
| Worker | kill·redelivery·멱등성·중복 결과 0 |
| Docker 환경·volume·secret | Compose config, 변경 image 재빌드, health/ready |

테스트를 통과시키기 위해 인증 예외를 넓히거나 테스트를 skip하지 않습니다. 현재 전체
검증에 기존 불일치가 있다면 이번 변경의 집중시험 결과와 기존 실패를 분리해 기록합니다.

## 12. 자주 찾는 수정 위치

| 하고 싶은 작업 | 먼저 볼 파일 |
|---|---|
| 홈 메뉴·기능 상태 변경 | `api/product.py`, `web/templates/pages/product_home.html`, `web/templates/components/audit_ui.html` |
| 로그인·계정 관리 | `api/authentication.py`, `api/auth_support.py`, 관련 auth 템플릿 |
| Windows 결과·AI·PDF | `api/result_ai_explanation.py`, `api/result_reports.py`, `web/static/app/product-results*.js` |
| Linux 중앙 점검 | `api/linux_audit.py`, `web/static/app/linux-scan.js`, `linux-results.js`, `linux-ai.js` |
| Linux 원샷 자가 점검 | `api/linux_oneshot.py`, `web/templates/pages/linux_self_scan.html`, `web/static/app/linux-self-scan.js` |
| Linux/Windows 파일 다운로드 | `api/dev_signed_downloads.py`, `web/templates/pages/dev_signed_downloads.html`, `web/static/app/dev-signed-downloads.js` |
| Switch 점검 | `api/switch_audit.py`, `web/static/app/switch-scan.js`, `switch-results.js` |
| 가이드 대화 | `api/chat_conversation.py`, `web/static/app/guide-chat.js`, `restricted-markdown.js` |
| 모델 연결 변경 | `model_gateway/main.py`, `src/security_audit/llm`, Compose의 `SECAI_LLM_*` |
| Queue 복구 | `worker/tasks.py`, `worker/recovery_cli.py`, `api/queue_recovery.py` |

## 13. 현재 개발 경계

- Windows와 Linux 판정 Pack은 개발용 DRAFT이며 공식 Finding 승인이 아닙니다.
- `DEV-SIGNED-TEST` 다운로드는 조직용 서명을 대신하지 않습니다.
- Linux 원샷 결과의 보증 수준은 온라인 `MEDIUM`, 오프라인 사용자 제출 `LOW`입니다.
- Switch는 현재 Aruba AOS-CX 개발 경로이며 공식 Pack·Cisco 실제 장비 인수는 별도입니다.
- Model Gateway는 현재 설정에 따라 외부 OpenAI 호환 endpoint를 사용할 수 있으므로
  승인되지 않은 개인정보·원본 증적을 전송하면 안 됩니다.
- Scheduler 골격이 존재한다고 해서 자동 운영 작업이 승인된 것은 아닙니다.

## 14. 관련 문서

- [`../구현_현황.md`](../구현_현황.md) — 현재 완료 상태와 다음 작업
- [`../README.md`](../README.md) — 전체 프로젝트 구조·실행·보안 기준
- [`../docs/README.md`](../docs/README.md) — 역할별 문서 목차
- [`../docs/maintenance/프로젝트_구조_및_파일_기능_카탈로그.md`](../docs/maintenance/프로젝트_구조_및_파일_기능_카탈로그.md) — 전체 파일 단위 카탈로그
- [`../deploy/compose/compose.yml`](../deploy/compose/compose.yml) — 서비스·network·secret·volume 정의
- [`../deploy/compose/compose.dev.yml`](../deploy/compose/compose.dev.yml) — 개발용 bind mount와 기능 설정
- [`../deploy/docker/api.Dockerfile`](../deploy/docker/api.Dockerfile) — API image
- [`../deploy/docker/worker.Dockerfile`](../deploy/docker/worker.Dockerfile) — Worker/Scheduler image
- [`../deploy/docker/model-gateway.Dockerfile`](../deploy/docker/model-gateway.Dockerfile) — Model Gateway image
