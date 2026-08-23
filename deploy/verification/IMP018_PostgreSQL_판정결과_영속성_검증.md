# IMP-018 PostgreSQL Finding persistence 검증 기록

| 항목 | 결과 |
|---|---|
| 구현 ID | `IMP-018` |
| 검증일 | 2026-07-22 |
| migration | `0001_imp018 (head)` |
| PostgreSQL | `18.4`, 내부 network 전용 |
| 결과 | 원자적 create-once·append-only DML 차단 PASS |

## 1. 구현 범위

이번 단계는 모든 미래 업무 table을 한 번에 만들지 않고 Finding 저장에 필요한 최소 scope만 생성했다.

```text
organizations
  → assets
    → audit_jobs
      → finding_versions (append-only 정본)
        → finding_current (별도 projection)
```

- composite foreign key로 organization·asset·job scope 혼합을 차단한다.
- `finding_versions.input_sha256`를 `uq_finding_versions_input_sha256`로 고정한다.
- Finding JSON의 ID·job·asset·Control·status·Pack·hash와 정규 column 일치를 check constraint로 확인한다.
- 후속 version은 predecessor ID와 allowlisted change reason을 함께 가져야 한다.
- 원본 package/evidence bytes는 PostgreSQL에 넣지 않는다.

## 2. 원자적 멱등성 계약

Repository는 PostgreSQL 한 문장으로 `INSERT ... ON CONFLICT ON CONSTRAINT uq_finding_versions_input_sha256 DO NOTHING RETURNING id`를 실행한다.

- 최초 input hash: `CREATE`
- 동일 input hash·동일 Finding ID·output hash: `RETURN_EXISTING`
- 동일 input hash·다른 output 또는 ID: `REPLAY_REJECTED`
- process-local cache나 조회 후 삽입 순서에 중복 방지를 맡기지 않는다.

Named unique constraint가 동시 Worker race의 최종 중복 방지점이다. IMP-017 pure resolver는 충돌 후 읽은 기존 JSON과 candidate fingerprint를 다시 비교한다.

## 3. Append-only 계약

`finding_versions`에는 다음 PostgreSQL trigger를 설치했다.

- `trg_finding_versions_reject_row_mutation`: UPDATE·DELETE 거부
- `trg_finding_versions_reject_truncate`: TRUNCATE 거부

과거 Finding을 수정하지 않고 새 version row로 추가한다. 현재 version 포인터는 mutable `finding_current` projection에 분리했다. Alembic downgrade는 보호 trigger와 function을 먼저 제거한 뒤 신규 table을 역순으로 제거하지만 자동 실행하지 않았다.

## 4. 실 PostgreSQL 검증

`database/verification/verify_imp018.py`를 API 컨테이너 안에서 실행했다. 모든 fixture는 외부 transaction rollback으로 제거했다.

```json
{"first_action":"CREATE","replay_action":"RETURN_EXISTING","finding_rows":1,"conflicting_replay":"REJECTED","update":"REJECTED","delete":"REJECTED","unique_constraint":"PRESENT","fixtures_retained":false}
```

추가 확인:

- Alembic current: `0001_imp018 (head)`
- Alembic schema drift: `No new upgrade operations detected`
- rollback 뒤 `finding_versions` row count: `0`
- Core 8개 service: 모두 `healthy`
- `/health/ready`: PostgreSQL·Redis·AIStor·ClamAV 모두 `true`

## 5. 자동 검증 결과

| Gate | 결과 |
|---|---|
| IMP-018 집중시험 | `7 passed` |
| 전체 Pytest | `140 passed`, 기존 Starlette deprecation warning 1건 |
| JSON Schema | 8 schemas·14 examples PASS |
| Ruff | PASS |
| mypy strict | 64 source files PASS |
| Core rebuild·Health | 8 services PASS |

재현 명령:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
docker exec sec-ai-mvp-dev-api-1 python -m alembic upgrade head
docker exec sec-ai-mvp-dev-api-1 python database/verification/verify_imp018.py
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

## 6. 재현 기준

| Artifact | SHA-256 또는 ID |
|---|---|
| `models.py` | `0286ceafc956e67b39d08936ba98b047571739d8c375fd795ca3d36a039a1fea` |
| `finding_repository.py` | `c9ecd0cf1d9451e04cdaa7c3a6065b90a3ae214ceaa413e2e2c5f045da8b8e2b` |
| migration `0001_imp018` | `709793dfd244c549c4a94ad11d366c7e79351b9e5c6f651d4b327c3e8b67b089` |
| 실DB 검증 script | `19bac1c2ac7e42ebe1329c48f0b7ff843ee461a0923db7e9c445cd856cd8e113` |
| 로컬 API image ID | `sha256:a763b2cf97ad90b64dc4c8cd01bc7ded6df84253722d4caa243a7f150305d1e7` |
| 로컬 Worker image ID | `sha256:ef4ef3cb03d9410ca15abe0a43171faa49f5ef621da33bb362ffae26efa40559` |

로컬 BuildKit image ID는 rebuild마다 달라질 수 있으므로 release 공급망 digest로 승인하지 않는다.

## 7. IMP-019 후속 반영

- 이 기록의 `0001_imp018 (head)`와 동일 DB user는 IMP-018 완료 당시 기준이다.
- IMP-019 migration `0002_imp019`에서 owner/migrator `secai_app`과 application `secai_runtime`을 분리했다. runtime role은 필요한 SELECT·INSERT와 `finding_current` UPDATE만 허용하며 DDL·Finding version UPDATE·DELETE는 권한 단계에서 먼저 거부한다.
- IMP-019에서 합성 Package 제출·Finding current 갱신·UI/API 조회를 연결했다. 실제 organization authorization과 Queue redelivery는 아직 없다.
- PC-07 Pack `0.1.0`은 계속 `DRAFT`이며 DB 계약 통과만으로 운영 공식 Finding이 되지 않는다.

현재 다음 작업은 `IMP-020` 시연 안정화·Gap Review다.
