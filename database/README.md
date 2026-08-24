# Database 계약·마이그레이션 안내

이 폴더는 Sec_AI가 교환하는 JSON 문서 계약, PostgreSQL 스키마 변경 이력과 실제 DB 통합 검증 도구를 보관합니다.

애플리케이션의 repository 구현은 [`../src/security_audit/persistence/database/`](../src/security_audit/persistence/database/)에 있고, 서비스 실행 구성은 [`../deploy/README.md`](../deploy/README.md)에 있습니다. 이 폴더는 “데이터 모양”과 “변경 이력”의 정본입니다.

## 구조

```text
database/
├─ schemas/                 JSON Schema Draft 2020-12 계약과 예제
│  ├─ *.schema.json
│  ├─ schema-catalog.json
│  ├─ examples/valid/
│  ├─ examples/invalid/
│  └─ validate_examples.py
├─ alembic/                 PostgreSQL 순방향 migration
│  └─ versions/0001...0026
├─ verification/            실제 PostgreSQL·서비스 통합 검증기
└─ migrate.py               고정 DB role 준비 후 Alembic head 적용
```

현재 migration head는 `0035_windows_linux_platform_expansion.py`입니다. 과거 revision은 이미 적용된 환경과 감사 이력을 재현하는 파일이므로 수정하지 않습니다.

## JSON Schema와 DB Schema의 차이

| 구분 | 담당 | 예시 |
|---|---|---|
| JSON Schema | Collector, API, Worker, UI 사이의 문서 형식 | Manifest, Package, Evidence, Finding, Chat |
| PostgreSQL migration | table, index, constraint, trigger, RLS, role grant | append-only Finding, Guide vector, Linux/Switch 실행 |
| Python model/repository | 업무 객체 매핑과 안전한 조회·저장 | `src/security_audit/persistence/database` |

JSON Schema를 바꿨다고 DB가 자동 변경되지 않으며, migration을 추가했다고 API 계약이 자동 갱신되지 않습니다. 기능 변경 시 두 경계가 모두 영향을 받는지 먼저 확인합니다.

## 데이터 흐름

```text
외부 입력
  → strict JSON parser
  → schema-catalog에 등록된 exact Schema 검증
  → 인증·조직·자산·nonce·서명·hash 검증
  → application service
  → repository
  → DB constraint·RLS·append-only trigger
```

Schema 통과만으로 신뢰 결정을 하지 않습니다. 인증, 권한, replay, scope, archive 안전성, Pack 승인과 서명은 별도 검증입니다.

## `schemas/` 변경 규칙

- `$id`와 `schema_version`이 배포된 Schema는 제자리에서 의미를 바꾸지 않습니다.
- 알 수 없는 property는 기본적으로 거부하고, remote `$ref`를 runtime에서 가져오지 않습니다.
- 새 Schema는 `schema-catalog.json`과 valid/invalid example에 함께 등록합니다.
- 시간은 RFC 3339 UTC, hash는 lowercase SHA-256, canonical JSON은 RFC 8785 JCS를 사용합니다.
- 실제 비밀번호, token, cookie, private key, 원본 전체 명령 출력과 개인 식별정보를 example에 넣지 않습니다.
- `Finding`의 공식 상태는 승인된 규칙 엔진만 만들며 AI 설명은 이를 변경할 수 없습니다.

자세한 계약은 [`schemas/README.md`](schemas/README.md)를 확인합니다.

## `alembic/` 변경 규칙

1. 기존 `versions/*.py`를 수정하지 않습니다.
2. 변경은 새 revision으로 추가하고 이전 head를 정확히 `down_revision`으로 연결합니다.
3. 데이터 삭제, type 축소, column 강제 변환처럼 손실 가능성이 있으면 구현 전에 승인을 받습니다.
4. 애플리케이션 구버전과 신버전의 배포 순서를 고려해 expand/contract 방식을 우선합니다.
5. RLS, 조직 범위, append-only trigger와 runtime role 최소 권한을 우회하지 않습니다.
6. migration 안에 비밀번호나 환경별 접속 주소를 넣지 않습니다.
7. 실제 업그레이드와 재기동 후 API/Worker 호환성을 검증합니다.

`finding_versions` 같은 정본은 UPDATE·DELETE·TRUNCATE를 차단합니다. 현재 표시 상태가 필요하면 별도 projection을 사용하며 과거 기록을 덮어쓰지 않습니다. 자세한 기본 규칙은 [`alembic/README.md`](alembic/README.md)를 따릅니다.

## DB 역할과 비밀정보

`migrate.py`는 migration owner로 접속하여 고정된 `secai_runtime`, `secai_db_admin` role을 준비한 뒤 Alembic head까지 올립니다.

- 접속 비밀번호는 환경 변수 값이 아니라 지정된 secret file에서 읽습니다.
- role 이름은 계약에 고정되어 있으며 임의 환경 변수로 바꿀 수 없습니다.
- PostgreSQL port는 기본 Compose에서 host에 공개하지 않습니다.
- pgAdmin의 관리 role도 superuser가 아니며 RLS와 DB 제약을 그대로 적용받습니다.
- secret file 내용은 로그, README, Fixture 또는 검증 결과에 출력하지 않습니다.

## 검증 방법

Schema 전체 검사:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Schema
```

동일한 검증기를 직접 실행해야 할 때:

```powershell
python database\schemas\validate_examples.py
```

Compose 설정과 migration을 포함한 Core 기동:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action UpWithoutAIStor
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

`database/verification/verify_*.py`는 특정 IMP 또는 제품 기능의 실제 PostgreSQL 검증기입니다. 단독 실행법과 필요한 서비스는 대응하는 [`../deploy/verification/`](../deploy/verification/) 기록 또는 wrapper `tools/verify-*.ps1`을 먼저 확인합니다.

## 변경 유형별 함께 볼 파일

| 변경 | 함께 확인할 위치 |
|---|---|
| Manifest·Package·Evidence | `database/schemas`, `src/security_audit/analysis`, `collectors` |
| Finding·규칙 | `audit_packs`, `src/security_audit/analysis`, Finding repository |
| Guide·vector | `guides`, Guide repository, ingestion/search 검증 |
| 인증·세션·RBAC | `src/security_audit/security`, API route, auth migration·시험 |
| Queue·Outbox | Worker/Scheduler, queue repository, 복구 검증 |
| Linux·Switch 실행 | application service, platform adapter, 전용 repository·UI |

## 완료 체크리스트

- [ ] 계약과 DB 중 영향을 받는 경계를 모두 갱신했습니다.
- [ ] 기존 migration을 수정하지 않고 새 revision을 추가했습니다.
- [ ] valid example은 통과하고 invalid example은 예상 이유로 거부됩니다.
- [ ] 조직·자산 IDOR, RLS와 최소 권한을 시험했습니다.
- [ ] replay와 중복 요청에도 논리 결과가 하나입니다.
- [ ] 정본의 append-only 제약이 유지됩니다.
- [ ] rollback 또는 복구 경로와 배포 순서를 기록했습니다.
- [ ] 관련 집중시험과 Schema·타입 검사를 실행했습니다.

