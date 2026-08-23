# 핵심 Python 소스 안내

이 폴더는 Sec_AI의 재사용 가능한 Python 패키지 `security_audit`를 보관합니다. HTTP, Celery, 화면 같은 실행 진입점은 [`../apps/README.md`](../apps/README.md)에 두고, 이곳에는 점검·판정·인증·저장·가이드 검색 같은 핵심 동작을 둡니다.

## 큰 흐름

```text
apps 또는 Collector
  → application 서비스
  → analysis / collector / guides / llm / platforms / security
  → persistence repository
  → 외부 DB·Queue·Model·장비
```

HTTP route가 규칙 판정이나 SQL을 직접 수행하지 않도록 하고, 핵심 로직은 framework와 분리해 단위시험할 수 있게 유지합니다.

## 패키지별 역할

| 위치 | 책임 | 대표 내용 |
|---|---|---|
| `analysis/` | Package 검증부터 Finding 생성까지의 결정론적 분석 | strict JSON, archive Gate, 정규화, 적용성, rule registry, hash·멱등성 |
| `application/` | 사용자 작업 단위의 흐름 조정 | Windows/Linux/Switch 실행, 결과 설명, 보고서, 재점검, 복구·인수 검증 |
| `collector/` | 로컬·SSH 수집, Manifest, 안전 실행, Package 생성 | allowlist, process 제한, Windows/Linux CLI |
| `common/` | 계층 공통의 작은 안전 유틸리티 | canonical JSON, secret file, 서비스 설정 |
| `guides/` | 승인 가이드 적재·검색·근거 결합 | Catalog 계약, ingestion, retrieval, grounding |
| `llm/` | 내부 OpenAI 호환 모델 경계 | provider 계약, gateway client, local vLLM 준비 상태 |
| `persistence/database/` | PostgreSQL model과 repository | Finding, Guide, Chat, Queue, Linux/Switch 실행, 보고서 |
| `platforms/` | 장비별 읽기 전용 Adapter | Linux, SSH, Cisco/Aruba Switch, 공통 사실 계약 |
| `security/` | 인증·인가·서명·악성코드 경계 | account/session, Collector credential, RBAC, offline signature |
| `supply_chain/` | Collector build·release·다운로드 검증 | Windows/Linux 산출물, 개발 서명 Catalog |
| `chat/` | 대화 Thread·Message·Citation 계약 | append-only 대화 모델 |
| `adapters/` | inbound/outbound Adapter 확장 자리 | 현재 공통 골격 |
| `domain/`, `ports/` | framework 독립 domain·port 확장 자리 | 현재 최소 골격 |

빈 골격 패키지는 삭제 대상으로 단정하지 않습니다. 승인된 아키텍처에서 확장 경계를 미리 고정한 위치일 수 있으므로 관련 ADR과 사용 참조를 먼저 확인합니다.

## 핵심 안전 경계

### 판정 경계

```text
Package 검증
  → 정규화
  → 적용성 평가
  → allowlisted 규칙
  → Finding Builder
  → append-only 저장
```

- 검증 실패 Package는 Evidence, 규칙 또는 Finding 단계로 넘기지 않습니다.
- 수집 실패와 권한 부족은 `FAIL`이 아닙니다.
- 공식 판정은 승인된 Audit Pack 규칙 엔진만 만듭니다.
- AI, UI, Collector와 repository는 공식 상태를 임의로 변경하지 않습니다.
- 같은 canonical 입력은 같은 출력 hash를 내야 하며 충돌 replay를 거부합니다.

### 외부 입력 경계

- HTTP, JSON, 파일, archive, LLM 출력과 장비 응답을 모두 검증합니다.
- SQL은 parameter binding과 repository를 사용하며 route에서 직접 조합하지 않습니다.
- 파일 경로는 기준 디렉터리, 허용 이름, canonical path를 확인합니다.
- shell 명령은 exact allowlist와 고정 인수를 사용하고 임의 문자열을 실행하지 않습니다.
- 외부 호출에는 timeout, 제한 크기, 취소와 안전한 오류 변환을 적용합니다.

### 조직·자산 격리

- 사용자 입력의 organization/asset UUID만으로 접근을 허용하지 않습니다.
- application, repository와 DB RLS에서 소유권·역할·범위를 다시 확인합니다.
- Chat, Finding, Guide, 보고서, Linux/Switch 실행 모두 조직 범위를 유지합니다.
- 로그와 외부 AI 요청에는 비밀정보나 불필요한 원본 증적을 넣지 않습니다.

## 새 기능을 어디에 넣을지

| 기능 | 권장 위치 |
|---|---|
| 새 API endpoint·응답 조립 | `apps/api` 또는 `apps/web` |
| 사용 사례의 순서·권한·transaction | `application` |
| 순수 판정·정규화 규칙 | `analysis` |
| 새 로컬 Probe·Package 생성 | `collector`와 `collectors` 계약 |
| 새 OS·장비 연결 | `platforms`와 application service |
| DB 읽기·쓰기 | `persistence/database`와 신규 migration |
| 로그인·RBAC·서명 | `security` — 보안 핵심 변경 승인 필요 |
| 가이드 적재·검색 | `guides` |
| 모델 provider 연결 | `llm` — 공식 판정 write 금지 |
| build·SBOM·서명 Gate | `supply_chain` |

한 파일에서 여러 계층을 우회하지 않습니다. 예를 들어 API route가 DB에 직접 접속하거나, domain/규칙 코드가 HTTP client를 직접 호출하거나, LLM 응답을 검증 없이 실행하면 안 됩니다.

## 코드 변경 순서

1. 관련 ADR, Schema, Audit Pack과 기존 시험을 확인합니다.
2. 로직 변경이면 가장 작은 실패 시험을 먼저 작성합니다.
3. 현재 계층의 기존 계약·dataclass·error 형식을 재사용합니다.
4. 요구사항을 만족하는 최소 구현만 추가합니다.
5. 관련 단위·계약 시험을 먼저 실행합니다.
6. DB, 인증, SSE, Queue, 외부 AI처럼 고위험 경계는 통합시험과 서비스 재빌드를 추가합니다.
7. 변경된 공개 동작과 검증 결과를 대응 문서에 기록합니다.

## 품질 기준

프로젝트 기준은 CPython `3.14`, Ruff line length `100`, mypy strict입니다. 호스트에 우연히 설치된 package 대신 잠긴 개발 container를 사용합니다.

```powershell
# 단위·계약 시험
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Test

# Ruff
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Lint

# mypy strict
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Type

# 전체 표준 Gate
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

## 관련 문서

- 실행 진입점: [`../apps/README.md`](../apps/README.md)
- 점검 기준: [`../audit_packs/README.md`](../audit_packs/README.md)
- Collector 계약: [`../collectors/README.md`](../collectors/README.md)
- DB 계약: [`../database/README.md`](../database/README.md)
- 시험 분류: [`../tests/README.md`](../tests/README.md)
- 유지보수 안내: [`../docs/maintenance/유지보수_가이드.md`](../docs/maintenance/유지보수_가이드.md)
