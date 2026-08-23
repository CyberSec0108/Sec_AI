# Sec_AI 코딩 에이전트 작업 안내

이 파일은 저장소 전체에 적용되는 루트 지침이다. 하위 디렉터리에 더 가까운
`AGENTS.md`가 있으면 이 문서와 함께 읽고, 해당 영역에서는 하위 지침을 우선 적용한다.

목표는 새 코딩 에이전트가 긴 완료 이력을 처음부터 다시 해석하지 않고도 다음을 빠르게
판단하게 하는 것이다.

- 현재 실제로 동작하는 사용자 기능
- 기능별 코드·계약·시험의 시작 위치
- 개발용 `LIVE`와 운영 승인 상태의 차이
- Collector·규칙·AI·DB 사이의 권한 경계
- 변경 후 필요한 최소 검증과 문서 갱신 범위

---

## 1. 작업 시작 순서와 정본 우선순위

### 1.1 처음 5분에 읽을 문서

1. [`구현_현황.md`](구현_현황.md)의 첫 표, 최신 구현 Snapshot, 다음 작업
2. 이 문서의 현재 기능 지도와 요청별 코드 진입점
3. 변경 대상 디렉터리의 가장 가까운 `AGENTS.md`와 `README.md`
4. [`docs/README.md`](docs/README.md)에서 관련 ADR·계획·사용자 문서 선택
5. 관련 기능의 가장 최근 [`deploy/verification`](deploy/verification) 기록
6. 변경할 계약·Schema·Pack·Fixture와 기존 시험

프로젝트 전체 Markdown이나 과거 IMP 기록을 무조건 모두 읽지 않는다. 현재 요청과 직접
연결된 문서만 선택하되, 인증·DB·판정·수집·외부 AI·배포 경계를 바꾸면 관련 ADR과
검증 기록을 반드시 확인한다.

### 1.2 정보가 충돌할 때

| 판단 대상 | 우선 확인 |
|---|---|
| 사용자가 원하는 동작 | 현재 대화의 최신 사용자 지시 |
| 실제 코드 동작 | source, Schema, migration, 실행 가능한 시험 |
| 완료·미완료·다음 작업 | `구현_현황.md` 첫 표와 최신 검증 기록 |
| 보안·승인 경계 | 승인 ADR, Pack 상태, 서명·Release Gate |
| 과거 구현 이유 | 해당 IMP·기능의 `deploy/verification` 기록 |

코드와 문서가 다르면 실제 동작 분석에는 코드를 우선하지만 문서를 조용히 맞춰 쓰지 않는다.
불일치, 어느 쪽을 기준으로 판단했는지, 필요한 후속 동기화를 보고한다. 특히 빠르게 개발 중인
CVE·Linux one-shot·Switch 영역은 파일 수정시각과 최신 검증 기록을 함께 확인한다.

### 1.3 탐색 원칙

- 파일 검색은 `rg --files`, 정의·문구 검색은 `rg -n`을 먼저 사용한다.
- 전체 파일 역할은 생성 문서인
  [`프로젝트_구조_및_파일_기능_카탈로그.md`](docs/maintenance/프로젝트_구조_및_파일_기능_카탈로그.md)에서 찾는다.
- Collector·판정 기준은
  [`수집기_구조_판정_기준_유지보수_상세가이드.md`](docs/maintenance/수집기_구조_판정_기준_유지보수_상세가이드.md)에서 먼저 찾는다.
- 실제 `.env`, `runtime/dev-secrets`, 원본 증적, credential, VM 내부 정보는 탐색 결과로
  출력하지 않는다.

---

## 2. 현재 제품 기능 지도

기준일은 2026-08-06이다. 이 표는 분석 출발점이며 완료 상태의 정본은 항상
`구현_현황.md`의 최신 표와 검증 기록이다.

| 기능 | 현재 개발 상태 | 대표 코드 진입점 | 아직 운영 완료가 아닌 것 |
|---|---|---|---|
| 계정·로그인 | DEV-LOCAL 계정 요청, 관리자 승인, Argon2id, 개발용 두 번째 인증, session·CSRF·RBAC | `apps/api/authentication.py`, `src/security_audit/security/auth` | Pilot WebAuthn/OIDC, 실제 hostname·TLS |
| Windows 점검 | Windows 10·11 x64 PC-01~18, 일반 15·동의형 관리자 5 Probe, 결과·재점검·PDF·AI 설명 | `apps/api/product.py`, `src/security_audit/collector`, `src/security_audit/analysis`, `audit_packs/kisa_2026_pc` | Windows 10 실제 VM, Server/DC 전용 기준, 조직 Publisher, 운영 Pack |
| Linux 중앙 점검 | Ubuntu 22.04·24.04, Debian 12, Rocky·AlmaLinux 9 x64 지원과 RHEL 9 Pilot 자동 식별, 고정 42 Probe, U-01~U-67 DRAFT 결과·AI·PDF | `apps/api/linux_audit.py`, `src/security_audit/platforms/linux*.py` | RHEL 9 공식 image, 권한 부족·timeout, 운영 Pack·서명 |
| Linux one-shot | 서버 내부 실행, online/offline 제출, 배포판별 launcher와 Package 검증 | `apps/api/linux_oneshot.py`, `src/security_audit/application/linux_oneshot_processing.py`, `collectors/one_shot/linux_*` | 조직 서명 Pilot·공격/장애 Release Gate의 최신 상태 확인 필요 |
| Aruba Switch 점검 | AOS-CX 10.13, 인증서 고정 REST GET 18개, N-01~N-38 DRAFT 결과·사용자 승인형 AI | `apps/api/switch_audit.py`, `src/security_audit/platforms/aruba_rest.py`, `kisa_network.py` | 현재 VM 재시험, Cisco 실제 장비, 공식 Pack·Finding·PDF |
| 결과·AI 설명 | 공식 판정과 AI 설명 분리, token stream, cache, 후속 질문, 제한 Markdown, 3종 직접 출처 | `apps/api/result_ai_explanation.py`, `src/security_audit/application/*ai*`, `apps/web/static/app/restricted-markdown.js` | AI가 공식 상태를 만드는 기능은 의도적으로 없음 |
| 점검 기준 Profile | Windows 개인/조직, Linux 안전 기본값, Switch 26개 기준+N-12/N-17 조직 입력, 실행 snapshot/hash | `apps/api/assessment_criteria.py`, `src/security_audit/application/assessment_criteria.py` | 범용 자연어 규칙 실행, 무검토 공식 Pack 승격 |
| 가이드 검색·대화 | KISA와 승인된 공공기관 가이드 통합 검색, pgvector/BGE-M3, reranker, citation·PDF page | `apps/api/chat_conversation.py`, `src/security_audit/guides`, `integrated_guide_qa.py` | 검색 품질 정식 benchmark, 승인 범위 밖 원문 전송 |
| 알려진 취약점 점검 | Windows inventory와 NVD 후보 비교, append-only 공개 Feed cache, offline cache UI | `apps/api/vulnerability_check.py`, `known_vulnerability_check.py`, migration `0029` | Microsoft 공급자 확정, KEV/VEX/서명 offline Bundle, 공식 취약 확정 |
| Queue·저장소 복구 | PostgreSQL Outbox·Redis redelivery·멱등 결과, AIStor 격리 복구 개발 시험 | `apps/worker`, `queue_recovery_status.py`, `storage_recovery_status.py` | 운영 KMS·Object Lock·책임자·RPO/RTO Pilot |
| 모델 연결 | 내부 model-gateway, 현재 승인된 OpenRouter 개발 연결, local vLLM 전환 계약 | `apps/model_gateway`, `src/security_audit/llm` | 로컬 GPU 추론은 취약점·GPU·승인 모델 Gate로 차단 |

### 2.1 상태 용어를 혼동하지 않는다

- `LIVE`: 현재 개발 환경에서 실제 API·권한·감사·시험이 연결됐다는 뜻이다.
- `PREVIEW`: 비식별 고정 예시이며 수집·저장·판정을 호출하지 않는다.
- `BLOCKED`: 외부 승인이나 안전 Gate가 없어 실행할 수 없다.
- `HIDDEN`: 일반 사용자 화면에 노출하지 않는다.
- `DRAFT`: 개발 판정 기준이다. 운영 승인이나 공식 Finding을 뜻하지 않는다.
- `PASS/FAIL/ERROR/REVIEW/N/A`: 규칙 결과 상태다. 권한 부족·수집 실패는 `FAIL`이 아니다.

제품 registry의 상태는
[`src/security_audit/application/product_features.py`](src/security_audit/application/product_features.py)가
코드 정본이다. 화면이 `LIVE`여도 Audit Pack, 배포, 외부 모델, 실장비 승인 상태는 각각
별도 Gate로 판단한다.

---

## 3. 아키텍처와 디렉터리 지도

### 3.1 실행 흐름

```text
Browser / Windows Launcher / Linux one-shot
        ↓ localhost Gateway
apps/api (FastAPI, 인증·DTO·HTTP/SSE)
        ↓
src/security_audit/application (유스케이스 조정)
        ├─ analysis     검증·정규화·적용성·규칙·Finding
        ├─ collector    Windows/Linux 실행·Package
        ├─ platforms    Linux SSH·Aruba REST·장비별 DRAFT 평가
        ├─ guides       Catalog·적재·검색·근거
        ├─ llm          내부 model-gateway client
        ├─ security     인증·RBAC·서명
        └─ persistence  PostgreSQL repository
              ↓
PostgreSQL/pgvector · Redis/Worker · AIStor · ClamAV · Model Gateway
```

### 3.2 폴더와 하위 지침

| 위치 | 책임 | 먼저 읽을 파일 |
|---|---|---|
| [`apps`](apps) | API·Web·Worker·Scheduler·Model Gateway 실행 진입점 | [`apps/AGENTS.md`](apps/AGENTS.md), [`apps/README.md`](apps/README.md) |
| [`src/security_audit`](src/security_audit) | 핵심 Python 서비스·규칙·수집·보안·저장 | [`src/security_audit/AGENTS.md`](src/security_audit/AGENTS.md), [`src/README.md`](src/README.md) |
| [`collectors`](collectors) | one-shot 진입점, Probe, allowlist·안전·Release 계약 | [`collectors/AGENTS.md`](collectors/AGENTS.md) |
| [`audit_packs`](audit_packs) | KISA DRAFT Pack, Fixture, Adapter Catalog | [`audit_packs/AGENTS.md`](audit_packs/AGENTS.md) |
| [`database`](database) | JSON Schema, Alembic migration, 검증 도구 | [`database/AGENTS.md`](database/AGENTS.md) |
| [`guides`](guides) | Guide Catalog·Page Map·Control Source Mapping | `guides/README.md`, ADR 15 |
| [`data`](data) | 승인된 원본 PDF 등 정적 입력 | Catalog의 hash·license·page 계약 |
| [`deploy`](deploy) | Compose·Docker·Gateway·lock·검증 기록 | [`deploy/AGENTS.md`](deploy/AGENTS.md) |
| [`tests`](tests) | unit·contract·integration·browser·fixture | [`tests/AGENTS.md`](tests/AGENTS.md) |
| [`docs`](docs) | ADR·계획·사용자·유지보수 문서 | [`docs/AGENTS.md`](docs/AGENTS.md) |
| [`requirements`](requirements) | 직접 의존성 입력과 hash lock | `requirements/README.md` |
| [`tools`](tools) | 개발·검증·build·이전 자동화 | 각 script의 `-Help`, 호출 문서 |
| `runtime`, `.runtime`, `downloads`, `tmp` | 생성물·cache·secret·실행 자료 | source로 취급하거나 문서에 복제하지 않음 |

---

## 4. 요청별 코드 진입점

| 요청 | 먼저 확인 | 함께 확인할 시험·계약 |
|---|---|---|
| 홈 카드·상단 메뉴·공통 UI | `product_features.py`, `apps/api/product.py`, `apps/web/templates/components/audit_ui.html`, `product_home.html` | `test_imp040_product_ui.py`, 관련 UI 계약 |
| 로그인·계정·권한 | `apps/api/authentication.py`, `auth_support.py`, `security/auth`, `security/rbac` | IMP-046·계정 관리 시험, migration·RLS |
| Windows Probe·판정 | `collectors/one_shot`, `src/security_audit/collector/windows.py`, `analysis/rule_engine` | Probe allowlist, PC Pack Fixture, collector·rule 시험 |
| Linux 중앙·one-shot | `apps/api/linux_audit.py`, `linux_oneshot.py`, `platforms/linux*.py`, `collector/linux*.py` | Linux preflight·Package·submission·AI 시험 |
| Switch 수집·N 판정 | `apps/api/switch_audit.py`, `platforms/aruba_rest.py`, `kisa_network.py`, `switch_audit_service.py` | `test_platform_adapters.py`, `test_switch_product_flow.py` |
| 점검 기준 수정 | `assessment_criteria.py`, `collector/criteria_contract.py`, 플랫폼 기준 계약 | ADR 20, reset·snapshot·hash·권한 시험 |
| 결과 AI·SSE·Markdown | `result_ai_explanation.py`, `device_ai_token_stream.py`, `restricted-markdown.js` | 판정 불변, citation, XSS, 중단·재시도 시험 |
| Guide/RAG | `guides/*`, `integrated_guide_qa.py`, `chat_conversation.py` | Catalog·Page Map·조직 scope·검색 품질 시험 |
| CVE 후보 점검 | `known_vulnerability_check.py`, `vulnerability_feed_repository.py`, `vulnerability_check.py` | VULN 계획, migration `0029`, feed/cache/UI 시험 |
| DB Schema·migration | `database/schemas`, `database/alembic/versions`, `persistence/database` | valid/invalid Schema 예제, RLS·migration 시험 |
| Docker·서비스 | `deploy/compose`, `deploy/docker`, `tools/core.ps1` | Compose config, image build, health·ready |

---

## 5. 반드시 유지할 설계·보안 경계

### 5.1 수집과 판정

- Collector와 플랫폼 Adapter는 읽기 전용으로 사실을 수집한다.
- 임의 shell, 사용자 입력 command, raw SQL, 임의 REST path를 실행하지 않는다.
- 일반 권한을 우선하고 관리자·sudo는 사용자 설명과 별도 동의, exact allowlist가 필요하다.
- timeout, 출력 크기, process tree 종료, locale, redaction을 유지한다.
- Package 검증 실패는 정규화·규칙·Finding으로 넘기지 않는다.
- 부분 증적으로 `PASS`를 만들지 않는다.
- 공식 판정은 승인·서명된 Audit Pack과 결정론 규칙만 만들 수 있다.
- 현재 Linux·Switch 결과와 Windows 개발 Pack의 `DRAFT`를 운영 `APPROVED`로 바꾸지 않는다.

### 5.2 Guide·AI·CVE

- Guide Catalog `APPROVED`와 Audit Pack `APPROVED`는 다른 승인이다.
- LLM이 만든 mapping·rule·Fixture는 실행 불가능한 `DRAFT` 제안이다.
- AI 설명은 실제값·공식 판정·근거를 입력으로 받을 뿐 이를 변경하지 않는다.
- 모델·가이드·CVE 본문은 비신뢰 입력이며 지시문으로 실행하지 않는다.
- 외부 모델에는 승인된 비식별 projection과 검색 문단만 보낸다.
- CVE 후보, vendor confirmed, KEV, VEX와 조직 공식 Finding을 구분한다.
- Feed가 오래됐거나 없으면 `취약점 없음` 또는 `양호`로 표시하지 않는다.

### 5.3 인증·데이터·저장

- 외부 DTO는 `extra="forbid"`, 길이·형식·enum·범위를 프로젝트 패턴대로 검증한다.
- organization, owner, asset scope는 API, service/repository와 RLS에서 다시 확인한다.
- ORM model을 그대로 외부 응답으로 노출하지 않는다.
- append-only 결과·대화·Feed·감사 기록을 덮어쓰거나 삭제하지 않는다.
- 기존 migration은 수정하지 않는다. Schema 변경은 새 migration으로 작성한다.
- token, cookie, password, private key, 실제 `.env`, AIStor license, 원본 증적을 source·시험·문서·로그에 넣지 않는다.

### 5.4 Web·상태 표시

- 기능 상태는 `LIVE/PREVIEW/BLOCKED/HIDDEN`만 사용한다.
- API·권한·감사·자동시험이 없는 기능을 활성 버튼이나 `LIVE`로 표시하지 않는다.
- 모델·외부 문서·증적을 `innerHTML`로 직접 넣지 않는다. `textContent`나 제한 Markdown DOM 계약을 사용한다.
- CSP, CSRF, IDOR, keyboard, focus, 모바일, 주야간 theme을 유지한다.

---

## 6. 작업 방법

1. 사용자 요청을 한 개의 작은 변경 범위로 고정한다.
2. 현재 변경 파일, 관련 시험, 관련 문서와 Git 상태를 확인한다.
3. 기존 사용자 변경과 작업 중인 파일을 덮어쓰지 않는다.
4. 로직 변경이면 가능한 한 실패하는 최소 시험을 먼저 작성한다.
5. JSON·Schema·Pack 변경은 계약과 valid/invalid Fixture를 코드보다 먼저 변경한다.
6. 기존 계층과 패턴을 따라 최소 구현한다.
7. 위험도에 맞는 집중시험, Ruff, mypy, JS syntax, Schema 또는 실제 HTTP 시험을 실행한다.
8. 공개 동작·Gate·현재 상태가 바뀌면 관련 문서와 `구현_현황.md`를 같은 변경 묶음에서 갱신한다.
9. 완료 Gate를 통과하지 못하면 완료로 표시하지 않는다.

다음은 사용자 명시 승인 없이 수정하지 않는다.

- CI/CD, Docker/Kubernetes/Terraform, production 설정과 배포 script
- 인증·권한·보안 정책 핵심, secret·certificate·key
- 기존 DB migration, 데이터 삭제·대량 이동
- 공식 Pack 승인 상태, 서명·폐기·rotation 상태
- package manager 설정과 신규 고위험 production dependency

사용자가 해당 영역 변경을 명시한 경우에도 exact 대상과 rollback·호환·검증 범위를 먼저
확인하고 최소 변경만 수행한다.

---

## 7. 검증 선택

프로젝트는 host Python보다 잠긴 Docker 개발 image를 기준으로 한다.

```powershell
# 전체 표준 Gate
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action All

# 서비스 상태가 필요한 변경
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Health
```

| 변경 | 최소 검증 |
|---|---|
| 문서·AGENTS | Markdown 상대 링크, 경로 존재, 중복·정본 충돌 검사 |
| Python 순수 로직 | 관련 Pytest, Ruff; 공개 type 변경이면 mypy |
| API·인증·SSE | 정상·비로그인·타 scope·변조·timeout 시험, Ruff, mypy, 필요 시 실제 HTTP |
| JS·UI | 관련 UI 계약, `node --check`, 접근성·반응형 영향 확인 |
| Schema·Pack | valid/invalid 예제, Fixture, 결정론·false PASS 회귀 |
| DB migration | 새 migration, upgrade, RLS·transaction·구버전 호환 시험 |
| Collector | allowlist·timeout·출력 상한·설정 diff 0, 실제/합성 플랫폼 회귀 |
| Docker·secret·network | 사용자 승인, Compose config, 변경 image 재빌드, health·ready |

전체 Gate가 현재 작업 밖 기존 불일치로 실패하면 시험을 약화하거나 숨기지 않는다. 이번
변경과 관련된 실패인지 분리하고, 집중시험 결과와 기존 실패를 함께 보고한다.

---

## 8. 문서와 완료 상태 갱신

- 현재 상태와 다음 작업: `구현_현황.md`
- 전체 구조·실행: 루트 `README.md`
- 문서 목차: `docs/README.md`
- 설계 결정: `docs/adr`
- 실행·검증 증거: `deploy/verification`
- 유지보수 설명: `docs/maintenance`

IMP나 명명된 기능 단계를 완료하면 검증 기록과 상태 문서를 함께 갱신한다. 검증 기록은
과거 실행 주장이므로 현재 코드와 다르다는 이유로 덮어쓰거나 삭제하지 않는다. 새 문서를
추가하면 `docs/README.md`와 해당 하위 `README.md`의 링크를 갱신한다.

`docs/maintenance/프로젝트_구조_및_파일_기능_카탈로그.md`는 생성 문서다. 직접 수정하지
말고 source 구조 변경 후 다음 도구로 다시 생성한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\generate-repository-catalog.ps1
```

---

## 9. 완료 보고 형식

최종 보고에는 다음을 포함한다.

### 변경 요약

- 사용자가 얻게 된 결과와 유지한 안전 경계

### 변경 파일

- 파일별 변경 이유와 주요 진입 줄

### 검증 결과

- 실행한 명령과 PASS/FAIL, 실행하지 못한 검증의 이유

### 가정 및 판단

- 문서·코드 불일치, 자율적으로 선택한 최소 범위

### 추가 발견 사항

- 요청 범위 밖 기존 결함·보류 Gate. 임의로 수정하지 않은 이유
