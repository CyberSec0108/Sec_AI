# `database` 영역 코딩 에이전트 지침

적용 범위는 JSON Schema, Alembic migration과 DB 검증 도구다. 루트 지침과
[`README.md`](README.md)를 먼저 읽는다.

## 1. 책임 분리

| 위치 | 책임 |
|---|---|
| `schemas` | 외부·내부 JSON 계약, catalog, valid/invalid 예제 |
| `alembic/versions` | 순차 PostgreSQL Schema·role·RLS migration |
| `verification` | 실제 DB 계약 검증 script |
| `migrate.py` | migration 실행 진입점 |
| `src/security_audit/persistence/database` | ORM model과 runtime repository |

DB 변경은 migration만 만들고 repository/model을 빼먹거나, repository만 바꾸고 migration을
빼먹지 않는다.

## 2. Schema 변경

1. 소비자와 producer를 모두 검색한다.
2. JSON Schema를 먼저 바꾼다.
3. valid와 invalid 예제를 함께 갱신한다.
4. unknown field, 길이, enum, format, 범위와 nested object 제한을 확인한다.
5. canonical hash 입력이면 field 추가·누락·정렬 영향을 검증한다.
6. `schema-catalog.json`과 관련 code contract를 갱신한다.

## 3. Migration 규칙

- 기존 migration은 절대 수정하지 않는다.
- 현재 head와 down revision을 실제 파일에서 확인한 뒤 새 revision을 추가한다.
- 현재 파일 기준 최신 번호가 바뀔 수 있으므로 문서에 적힌 번호만 믿지 않는다.
- 데이터 손실, table rewrite, 대량 backfill 가능성이 있으면 사용자 확인을 요청한다.
- 신규 table에도 organization/owner scope, RLS, runtime role grant, index와 unique key를 검토한다.
- append-only 정본은 UPDATE/DELETE 권한과 repository 동작을 모두 차단한다.
- migration과 구버전 application의 배포 순서·nullable/default 호환을 검토한다.
- downgrade가 데이터 손실을 일으키면 명시하고 임의 실행하지 않는다.

## 4. 보안·일관성

- route의 UUID가 아니라 인증 principal과 RLS context를 기준으로 범위를 제한한다.
- SQL은 parameter binding을 사용한다.
- session, credential digest, Finding, 대화, AI cache, Feed snapshot의 불변 의미를 유지한다.
- replay·retry가 중복 row나 다른 결과를 만들지 않게 unique key와 transaction을 사용한다.
- DB 오류 응답에 DSN, SQL, schema name, secret 값을 노출하지 않는다.

## 5. 검증

- `database/schemas/validate_examples.py`
- 관련 migration upgrade와 실제 PostgreSQL 시험
- runtime role의 SELECT/INSERT/UPDATE/DELETE matrix
- owner/organization RLS와 IDOR 시험
- unique key·transaction·redelivery·append-only 시험
- 관련 repository Pytest, Ruff, mypy

DB 서비스나 secret이 없어 실행하지 못한 검증은 합성시험과 구분해 보고한다.

