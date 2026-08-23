# 웹 UI 문구 수정 및 반영 안내

## 1. 목적

이 문서는 Sec_AI 웹 화면의 한글 문구를 찾고 수정한 뒤 Docker 실행 화면에 안전하게 반영하는 방법을 설명합니다.

고정 화면 문구, 실행 상태에 따라 바뀌는 문구, AI가 생성하는 답변 형식, 화면 간격과 색상은 서로 다른 파일에서 관리하므로 아래 구분에 따라 수정합니다.

## 2. 가장 먼저 확인할 폴더

| 구분 | 위치 | 역할 |
|---|---|---|
| 화면 고정 문구 | `apps/web/templates/pages/` | 화면 제목, 안내문, 버튼, 입력 안내 |
| 공통 화면 구성 | `apps/web/templates/components/` | 상단 메뉴, 로고, 공통 점검 UI |
| 동적 상태 문구 | `apps/web/static/app/`의 JavaScript 파일 | 진행, 완료, 오류, 스트리밍 상태 |
| 화면 디자인 | `apps/web/static/app/app.css` | 글자 크기, 여백, 폭, 색상, 반응형 |
| AI 답변 지침 | `src/security_audit/application/grounded_ai.py` | AI 답변 제목, 순서, 근거 사용 방식 |
| AI 로컬 대체 답변 | `src/security_audit/application/local_grounded_summary.py` | 외부 모델을 사용하지 못할 때 표시할 답변 |
| 첫 화면 카드 문구·상태 | `src/security_audit/application/product_features.py` | 카드 제목, 설명, 준비 상태, 이동 경로 |

## 3. 화면별 HTML 파일

| 화면 | 파일 |
|---|---|
| 공통 상단 메뉴와 로고 | `apps/web/templates/components/audit_ui.html` |
| 원클릭 점검 첫 화면 | `apps/web/templates/pages/product_home.html` |
| Windows 점검 결과 | `apps/web/templates/pages/product_results.html` |
| Windows AI 설명 | `apps/web/templates/pages/result_ai_analysis.html` |
| Linux 장비 선택과 점검 | `apps/web/templates/pages/linux_scan.html` |
| Linux 점검 결과 | `apps/web/templates/pages/linux_results.html` |
| Linux AI 설명 | `apps/web/templates/pages/linux_ai.html` |
| Linux 원샷 자가 점검 | `apps/web/templates/pages/linux_self_scan.html` |
| 관리자 Linux 서버 등록 | `apps/web/templates/pages/admin_linux_servers.html` |
| 스위치 점검·결과 | `apps/web/templates/pages/switch_scan.html`, `switch_results.html` |
| 알려진 취약점 점검 | `apps/web/templates/pages/vulnerability_check.html` |
| 점검 프로그램 다운로드 | `apps/web/templates/pages/dev_signed_downloads.html` |
| 통합 점검 이력 | `apps/web/templates/pages/result_center.html` |
| 가이드 질의 | `apps/web/templates/pages/guide_chat.html` |
| 도움말 | `apps/web/templates/pages/product_help.html` |
| 로그인 | `apps/web/templates/pages/login.html` |
| 인증 코드 입력 | `apps/web/templates/pages/mfa.html` |
| 계정 생성 요청 | `apps/web/templates/pages/register.html` |
| 계정정보 | `apps/web/templates/pages/session.html` |
| 내 계정정보 변경 | `apps/web/templates/pages/account_settings.html` |
| 관리자 계정 관리 | `apps/web/templates/pages/admin_accounts.html` |
| 개인 점검 기준 | `apps/web/templates/pages/assessment_criteria.html` |
| 관리자 기본 점검 기준 | `apps/web/templates/pages/admin_assessment_criteria.html` |

## 4. 동적 문구를 수정하는 JavaScript 파일

| 기능 | 파일 |
|---|---|
| 가이드 대화, 검색, 스트림, 출처 | `apps/web/static/app/guide-chat.js` |
| Windows 점검 진행 | `apps/web/static/app/product.js` |
| Windows 결과와 관리자 점검 | `apps/web/static/app/product-results.js` |
| Windows AI 설명 | `apps/web/static/app/result-ai-analysis.js` |
| Windows 결과·AI 통합 카드 | `apps/web/static/app/product-results-integrated.js` |
| Linux 점검 진행 | `apps/web/static/app/linux-scan.js` |
| Linux 결과 | `apps/web/static/app/linux-results.js` |
| Linux AI 설명 | `apps/web/static/app/linux-ai.js` |
| Linux 원샷 자가 점검 | `apps/web/static/app/linux-self-scan.js` |
| 스위치 점검·결과 | `apps/web/static/app/switch-scan.js`, `switch-results.js` |
| 알려진 취약점 비교·공식 원문 한글 번역 | `apps/web/static/app/vulnerability-check.js` |
| 개발용 서명 다운로드 | `apps/web/static/app/dev-signed-downloads.js` |
| 제한 Markdown·인라인 출처 | `apps/web/static/app/restricted-markdown.js` |
| 계정 세션 | `apps/web/static/app/account-session.js` |
| 관리자 계정 관리 | `apps/web/static/app/admin-accounts.js` |

`답변을 준비하고 있습니다`, `검색 중입니다`, `연결하지 못했습니다`처럼 실행 중에 바뀌는 문구는 HTML보다 JavaScript에 있을 가능성이 높습니다.

## 5. 문구를 찾는 가장 빠른 방법

1. VS Code에서 프로젝트 루트 `C:\Users\Hala\Desktop\Sec_AI`를 엽니다.
2. `Ctrl+Shift+F`를 누릅니다.
3. 브라우저에 표시된 문구의 일부를 그대로 검색합니다.
4. 검색 결과가 HTML이면 고정 문구, JavaScript이면 동적 문구인지 확인합니다.
5. AI가 생성한 답변 본문이라면 플랫폼별 `*ai*` application service와 stream API를 확인합니다. 프롬프트를 한 파일에 모았다고 가정하지 않습니다.

PowerShell에서는 다음과 같이 검색할 수 있습니다.

```powershell
rg -n "찾을 문구" apps/web src/security_audit/application
```

## 6. 수정할 때 지켜야 할 사항

- 버튼의 화면 문구만 바꾸고 `id`, `name`, `data-*`, `aria-*` 속성은 기능 변경 목적이 아니면 수정하지 않습니다.
- 링크의 표시 문구를 바꿀 때 `href`는 이동 경로 변경이 필요한 경우에만 수정합니다.
- JavaScript의 상태 코드, API 경로, JSON 필드명은 사용자 표시 문구와 구분합니다.
- `PASS`, `FAIL`, `ERROR`, `REVIEW` 내부값은 계약이므로 화면 번역만 바꾸고 내부값은 유지합니다.
- KISA 원문 인용과 판정 문구를 임의로 의미 변경하지 않습니다.
- AI 안내문을 바꿔도 규칙 엔진의 공식 판정은 변경하지 않습니다.
- 사용자에게 표시되는 오류와 내부 디버깅 정보를 분리합니다.

## 7. 디자인 수정 위치

글자 크기, 카드 폭, 질문 말풍선, 답변 폭, 좌우 여백, 모바일 배치는 다음 파일에서 수정합니다.

```text
apps/web/static/app/app.css
```

가이드 대화 화면을 수정할 때 주로 찾는 CSS 선택자는 다음과 같습니다.

```text
.chat-layout
.chat-history-panel
.chat-conversation
.chat-message-list
.chat-message-user
.chat-message-assistant
.chat-composer
.chat-composer-shell
```

### 7.1 첫 화면 카드 수정 위치

첫 화면 카드에는 문구, HTML 구조, 디자인, 버튼 동작이 함께 보이지만 파일은 역할별로 나뉩니다.

| 수정 대상 | 파일 | 검색할 표식 또는 선택자 |
|---|---|---|
| 카드 제목·설명·상태·이동 경로 | `src/security_audit/application/product_features.py` | `[카드수정]`, `_FEATURES` |
| 카드 공통 HTML 구조 | `apps/web/templates/pages/product_home.html` | `[카드수정]`, `feature-grid` |
| 카드 크기·간격·색상 | `apps/web/static/app/app.css` | `[카드수정]`, `.feature-grid`, `.feature-card` |
| Windows PC 점검 카드의 시작 동작 | `apps/web/static/app/product.js` | `[카드수정]`, `start-standard-scan` |

카드의 글만 바꿀 때는 `product_features.py`를, 카드 안의 배치나 태그를 바꿀 때는 `product_home.html`을 수정합니다. 카드 전체 크기와 여백은 `app.css`에서 수정합니다.

## 8. 변경 후 최소 확인

문구만 수정했다면 최소한 다음을 확인합니다.

1. HTML 태그가 닫혀 있는지 확인합니다.
2. JavaScript를 수정했다면 문법 검사를 실행합니다.
3. 변경 화면을 직접 열어 버튼과 링크가 계속 동작하는지 확인합니다.
4. 긴 문장과 모바일 폭에서 글자가 잘리지 않는지 확인합니다.
5. 브라우저에서 `Ctrl+F5`로 캐시를 갱신합니다.

Windows·Linux 결과/AI 문구를 수정할 때는 다음 현재 계약도 함께 확인합니다.

- 상태 배지의 `양호`·`취약`·`확인 필요` 크기·색·굵기를 공통 CSS로 유지
- AI 직접 출처는 `[1] 실제 확인값`, `[2] KISA 근거`, `[3] AI 일반 보안지식`
- 공식 규칙은 판정 영역에만 두고 AI 설명·AI 출처에서는 제외
- 인라인 인용은 관련 문장 뒤에 표시
- `1. 왜 중요한가요?`부터 `4. 용어 간단 설명`까지 번호형 제목 유지
- 완료·취소·실패 뒤 생성 커서 제거
- Linux 내부 `REVIEW`는 원인을 보존하되 사용자 분류는 `확인 필요`에 포함
- 저장된 결과·AI 완성본이 있으면 화면 진입만으로 재생성하지 않고, 명시적 재생성 버튼에서만 새 stream 시작
- 알려진 취약점의 공식 출처 한글 설명과 선택형 `AI로 쉽게 설명`을 혼합하지 않음

JavaScript 문법 검사 예시는 다음과 같습니다.

```powershell
node --check apps/web/static/app/guide-chat.js
```

## 9. Docker 화면에 반영

### 9.1 개발 화면의 HTML·CSS·JavaScript

개발용 `deploy/compose/compose.dev.yml`은 로컬의 `apps/web` 폴더를 API 컨테이너의 `/app/apps/web`에 읽기 전용으로 연결합니다. 따라서 다음 파일은 image를 다시 빌드하지 않아도 됩니다.

- `apps/web/templates/` 아래 HTML
- `apps/web/static/` 아래 CSS와 JavaScript

파일을 저장한 뒤 브라우저에서 일반 새로고침을 합니다. 이전 CSS나 JavaScript가 보이면 `Ctrl+F5`로 브라우저 캐시를 갱신합니다.

이 연결 설정을 처음 추가했거나 변경했을 때만 API 컨테이너를 한 번 다시 만듭니다.

```powershell
cd C:\Users\Hala\Desktop\Sec_AI

docker compose --project-directory . `
  -f deploy/compose/compose.yml `
  -f deploy/compose/compose.dev.yml `
  up -d --no-deps --force-recreate api
```

### 9.2 Python 카드 문구와 API 서버 코드

개발용 Compose는 다음 Python 폴더도 API 컨테이너에 읽기 전용으로 연결합니다.

- `src` → `/app/src`
- `apps/api` → `/app/apps/api`

Uvicorn의 개발용 `--reload`와 Docker Desktop용 polling 감지를 사용하므로 `product_features.py`를 포함한 Python 파일을 저장하면 보통 약 1초 안에 API 프로세스가 자동 재시작됩니다. image 재빌드나 컨테이너 재생성은 필요하지 않습니다.

자동 재시작 순간에는 진행 중인 HTTP 요청이 한 번 실패할 수 있습니다. 저장 후 컨테이너가 다시 정상 상태가 되면 화면을 새로고침합니다.

```powershell
docker logs --since 30s sec-ai-mvp-dev-api-1
docker ps --filter name=sec-ai-mvp-dev-api-1 --format "{{.Names}} | {{.Status}}"
```

이 자동 반영은 `compose.dev.yml`을 함께 사용한 개발 환경에만 적용됩니다. 운영 실행은 source를 연결하거나 reload하지 않고, 검증된 image 안의 고정 코드를 사용합니다.

컨테이너 상태는 다음 명령으로 확인합니다.

```powershell
docker ps --filter name=sec-ai-mvp-dev-api-1 --format "{{.Names}} | {{.Status}}"
```

## 10. 문구 종류별 판단 예시

| 화면에서 보이는 내용 | 먼저 확인할 위치 |
|---|---|
| `가이드 질의` | `guide_chat.html` |
| `무엇을 확인하고 싶으신가요?` | `guide_chat.html` |
| `답변을 준비하고 있습니다` | `guide-chat.js` |
| `핵심 답변` | `grounded_ai.py` 또는 로컬 대체 답변 파일 |
| 상단 `원클릭 점검`, `점검 결과` | `components/audit_ui.html` |
| 질문과 답변의 좌우 여백 | `app.css` |

## 11. 문서 파일명 규칙

- `README.md`는 도구와 사용자가 먼저 찾는 표준 진입 파일이므로 이름을 유지합니다.
- `AGENTS.md`는 코드 에이전트가 자동으로 읽는 규칙 파일이므로 이름을 유지합니다.
- 진행 번호와 계약 식별자인 `IMP`, `PRODUCT-AI`, `ADR`, `KISA`, `RBAC`, `JSON`은 검색과 추적을 위해 유지할 수 있습니다.
- 나머지 설명 부분은 한글로 작성하고 단어 사이는 밑줄(`_`)로 구분합니다.
- 문서명을 바꾸면 Markdown 링크, 코드 주석, 검증 스크립트의 경로 참조를 함께 수정합니다.
