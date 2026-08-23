# `src/security_audit` 영역 코딩 에이전트 지침

적용 범위는 핵심 Python package 전체다. 루트 [`AGENTS.md`](../../AGENTS.md)와
[`../README.md`](../README.md)를 먼저 읽는다.

## 1. 계층 방향

```text
apps / collector entrypoint
        ↓
application use case
        ↓
analysis · collector · platforms · guides · llm · security
        ↓
persistence repository / 외부 Adapter
```

API가 SQL을 직접 조합하거나, 규칙 코드가 HTTP client를 직접 호출하거나, repository가
사용자 화면 DTO를 결정하지 않게 한다. 순수 판정은 framework·DB·network 없이 시험할 수
있어야 한다.

## 2. 패키지별 책임

| 패키지 | 책임 | 변경 시 핵심 확인 |
|---|---|---|
| `analysis` | strict Package 검증, 정규화, 적용성, 규칙, Finding·멱등 hash | Schema·Pack·Fixture·false PASS |
| `application` | 사용자 작업 순서, transaction 경계, 결과·AI·보고서 | DTO·권한·공식 상태 불변 |
| `collector` | Manifest, allowlist, process 안전, Windows/Linux Package | 고정 argv·timeout·권한·redaction |
| `platforms` | Linux SSH, Aruba REST, 플랫폼 fact와 DRAFT 평가 | 장비 응답 검증·TLS/host key·적용성 |
| `guides` | Catalog, ingestion, retrieval, grounding | 원본 hash·page·조직 scope·citation |
| `llm` | 내부 모델 계약과 Gateway client | 비식별 입력·timeout·자동 fallback 금지 |
| `persistence/database` | ORM model과 repository | transaction·RLS·append-only·parameter binding |
| `security` | 계정/session, RBAC, Collector credential, signature | 보안 핵심 변경 승인·공격 회귀 |
| `supply_chain` | Windows/Linux build·release·임시 다운로드 검증 | lock·SBOM·서명·악성코드 검사 |
| `chat` | Thread·Message·Citation 계약 | append-only·분기·소유자 scope |
| `common` | canonical JSON, secret file, service 설정 | 작은 의존성 없는 유틸리티만 허용 |

`adapters`, `domain`, `ports`의 최소 골격은 사용 참조와 ADR을 확인하기 전 삭제하지 않는다.

## 3. 핵심 파이프라인

Windows Package 기반 판정:

```text
archive/strict JSON/Schema 검증
→ normalized evidence
→ applicability
→ allowlisted rule registry
→ Finding Builder
→ canonical hash·idempotency
→ append-only repository
```

Linux·Switch 제품 판정:

```text
고정 읽기 Adapter
→ 허용된 비식별 fact
→ 플랫폼 적용성·DRAFT evaluator
→ 실행 시점 criteria snapshot
→ DRAFT result repository
```

두 경로 모두 결과 표시·가이드 근거·AI 설명으로 이어질 수 있지만 AI 출력은 이전 단계의
fact, status, Pack, hash를 변경할 수 없다.

## 4. 구현 위치 선택

| 변경 | 위치 |
|---|---|
| 순수 규칙·정규화 | `analysis` |
| 작업 흐름·여러 repository 조정 | `application` |
| 새 Probe·Manifest·Package | `collector`와 루트 `collectors` |
| 새 OS·장비 API | `platforms`와 application service |
| DB 읽기·쓰기 | `persistence/database`와 신규 migration |
| 가이드 검색 | `guides` |
| 모델 호출 | `llm`; 공식 판정 write 금지 |
| 인증·권한·서명 | `security`; 사용자 승인과 공격시험 필요 |
| build·서명·다운로드 | `supply_chain` |

## 5. 구현 규칙

- 외부 입력은 먼저 validate하고 내부 dataclass/value object로 변환한다.
- canonical hash 입력 필드와 정렬을 임의로 바꾸지 않는다.
- 수집 오류·권한 부족·미지원은 `FAIL`이 아니다.
- 불완전한 evidence로 `PASS`를 만들지 않는다.
- DB write는 repository와 transaction 안에서 수행한다.
- 외부 호출에는 timeout, response size, schema 검증, 안전한 오류가 필요하다.
- 실제 credential·PII·원본 증적을 로그에 넣지 않는다.
- 새 public type이나 status를 추가하면 API DTO·Schema·repository·UI·시험의 소비자를 모두 찾는다.

## 6. 시험

순수 로직은 DB·network 없이 unit test를 우선한다. 외부 API는 합성 응답과 실패 case를
사용하며 실제 network 호출을 기본 시험으로 만들지 않는다.

변경 영향별로 다음을 선택한다.

- `analysis`: rule/normalization/package validation 시험과 100회 결정론 회귀
- `collector/platforms`: allowlist, timeout, malformed response, 권한 부족, 설정 diff 0
- `application`: 상태 전이, retry, idempotency, 공식 판정 불변
- `persistence`: transaction, unique key, RLS, append-only
- `guides/llm`: citation, 근거 없음, prompt injection, upstream 중단
- `security`: 비로그인, 타 scope, 만료, replay, 변조

관련 Pytest 뒤 Ruff와 공개 type 변경 시 mypy strict를 실행한다.

