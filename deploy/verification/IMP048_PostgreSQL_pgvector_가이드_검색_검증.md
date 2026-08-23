# IMP-048 PostgreSQL+pgvector 가이드 근거 검색 검증

| 항목 | 결과 |
|---|---|
| 상태 | `COMPLETE` |
| 사용자 결과 | 승인된 실제 KISA PC 41쪽을 조직·가이드·버전·조회 범위에 맞게 검색할 저장소 준비 완료 |
| 저장 전략 | PostgreSQL 정본 + pgvector 검색 projection |
| 대체 대상 | Milvus·PyMilvus·Attu·Milvus용 etcd·전용 object store 미도입 |
| Runtime | PostgreSQL 18.4·pgvector 0.8.2 |
| Migration | `0008_imp048` |
| 실제 KISA 원문 | 문서 1건·text chunk 41건·embedding 41건·ACTIVE generation 1건 |
| 일반 조회 UI | `http://localhost:18480/ui/guide-store` |
| 관리자 UI | pgAdmin 9.16, `http://127.0.0.1:18490`, 선택 기동 |
| 관리자 이미지 보안 | fixable Alpine/Python package 갱신, CPython 3.14 공식 `CVE-2026-15308` 수정 backport·동작 시험 PASS |

## 1. 결정 근거

`renew_v4/docs/adr`의 PostgreSQL business truth·격리된 vector projection·versioned generation·fail-closed scope 원칙을 검토했다. Sec_AI는 기존 PostgreSQL의 transaction, RLS, backup과 권한 체계를 재사용하고 vector를 다시 만들 수 있는 projection으로 분리하는 방향이 현재 규모와 운영 복잡도에 더 적합하다.

결정은 [`docs/adr/16.ADR_PostgreSQL_pgvector_가이드_검색.md`](../../docs/adr/16.ADR_PostgreSQL_pgvector_가이드_검색.md)에 기록했다. Milvus 계열 구성요소는 Compose와 image lock의 선택 대상에서 제거하고 `NOT_SELECTED` 이력으로만 남겼다.

## 2. 구현 범위

- 승인 전 실제 문서 반입을 거부하는 Guide ingest Gate
- page·Control·source hash 계보가 포함된 결정론적 chunk
- 합성 시험 embedding과 실제 내부용 32차원 KISA 보안용 결정론 lexical embedding
- `guide_content` 정본과 `vector_store` projection schema
- immutable vector generation과 조직·가이드·version·scope별 ACTIVE pointer
- HNSW cosine index
- 다섯 table의 RLS·`FORCE ROW LEVEL SECURITY`
- 고정 `search_path`의 제한된 검색 함수
- runtime role의 raw embedding 직접 조회 차단
- dense 30%·lexical 70%의 결정론적 합성 rerank
- 검색 결과 ID·score를 canonical chunk로 다시 확인하는 repository
- PyMilvus 직접·전이 의존성 제거와 `ingestion.lock`·`dev.lock` 재생성

`secai-ko-lexical-hash-v1`은 외부 전송 없이 KISA PC 보안 용어를 투영하는 실제 내부 검색용 초기 모델이다. 검색 품질 승인과 운영 모델 확정은 IMP-049·050에서 별도로 수행한다.

> 이 문단의 30%·70%는 IMP-048 당시 합성 기준선이다. IMP-049 실제 PC-01~18 질문 평가에서 임계값을 유지한 채 dense 15%·lexical 85%로 조정했고 18/18을 통과했다. 최신 검색 품질 기준은 [`IMP049_KISA_질문_근거화_검증.md`](IMP049_KISA_질문_근거화_검증.md)를 따른다.

## 3. 실제 DB 검증

`tools/verify-imp048-pgvector.ps1`은 migration을 확인한 뒤 rollback 가능한 합성 generation과 chunk 2건을 준비하고 실제 runtime role로 검색한다.

```json
{
  "accepted": true,
  "cross_organization_hits": 0,
  "first_control": "PC-01",
  "imp": "IMP-048",
  "pgvector_version": "0.8.2",
  "postgresql_migration": "0006_imp048",
  "provider": "POSTGRES_PGVECTOR",
  "raw_vector_read_blocked": true,
  "real_kisa_ingested": false,
  "search_hits": 2,
  "synthetic_chunks": 2,
  "wrong_scope_hits": 0
}
```

다른 조직과 잘못된 조회 범위의 결과는 0건이고 runtime role의 raw vector 조회는 거부됐다. 검증 transaction은 rollback되어 합성자료도 운영 데이터로 남기지 않는다.

실제 반입은 별도 승인형 도구 `tools/ingest-approved-guide.py`로 수행했다. 같은 source·page·generation ID를 재사용하는 원자적 transaction이며 정확히 41개 chunk와 41개 embedding이 아니면 commit하지 않는다.

```json
{
  "embedding_count": 41,
  "embedding_model_id": "secai-ko-lexical-hash-v1",
  "extraction_mode": "TEXT_LAYER",
  "malware_status": "CLEAN",
  "ocr_required_pages": 0,
  "page_count": 41,
  "source_sha256": "44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d",
  "status": "INGESTED"
}
```

## 4. 자동검증

```text
IMP-047·048 focused tests: 24 PASS
Pytest: 433 PASS
JSON Schema: 16 schemas·30 examples PASS
Ruff: PASS
mypy strict: 217 source files PASS
Docker Compose config: PASS
Core: 9/9 healthy
Web: 로그인·두 번째 인증 후 /ui/guide-store와 safe API PASS
pgAdmin: /misc/ping HTTP 200, 127.0.0.1:18490 only
pgAdmin focused regression: 8 PASS, Ruff PASS
pgAdmin CVE backport test: HTMLParser 200,000 incremental feeds 0.078s PASS
PyMilvus active dependency/import: 0
ingestion.lock clean hash install: PASS
Requirement lock SHA-256 baseline: PASS
```

추가된 계약은 실제 DRAFT 원문에 `synthetic=true`를 붙여도 승인을 우회하지 못하게 하고, 중복 page·미승인 scope·비활성 generation을 검색에서 제외한다.

## 5. 완료한 Source Gate

사용자는 2026-07-24에 다음 범위를 명시적으로 승인했다.

1. 실제 KISA 원문의 프로젝트 내부 처리·검색
2. 파생 text·chunk·embedding 저장
3. 해당 PDF의 안전성 확인
4. OCR·text 추출 품질검사 시행
5. 승인 범위 PC 41쪽 실제 적재

검사 결과 exact PDF는 ClamAV 1.4.5에서 `CLEAN`이었다. PDF 552~592쪽은 모두 내장 텍스트 계층을 사용했고, IMP-047 Page Map의 SHA-256과 정규화 글자 수가 41쪽 전부 일치했다. OCR이 필요한 쪽은 0쪽이었다. 원문 재배포 권한은 승인 범위에 포함하지 않았으므로 catalog의 `redistribution_allowed`는 계속 `false`다.

Guide 검색 승인은 Audit Pack 승인과 분리했다. Control Mapping과 Audit Pack은 계속 `DRAFT`, `runtime_activation_allowed=false`, `audit_pack_activation_allowed=false`다.

## 6. 조회·관리 UI와 권한

- 일반 사용자 화면 `/ui/guide-store`는 PostgreSQL·pgvector 버전, 문서·chunk·embedding 수, Control·페이지·text만 보여준다.
- 일반 API는 raw vector, DB URL, 비밀번호를 반환하지 않는다.
- 관리자 UI는 digest로 잠근 `dpage/pgadmin4:9.16` 기반 `sec-ai-mvp/pgadmin:0.1.0`이다.
- `18490`만 loopback에 publish하고 PostgreSQL `5432`는 계속 internal이다.
- `secai_db_admin`은 `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`, `NOREPLICATION`이며 DEV 조직의 Guide table DML과 `pg_monitor`만 허용한다.
- pgAdmin 로그인 비밀번호와 DB 비밀번호는 서로 다른 보호 파일로 관리하며 image·문서·로그에 넣지 않는다.
- 기존 DB constraint, RLS와 append-only trigger는 관리자 UI에서도 우회되지 않는다.

### 관리자 이미지 보안 재검사

2026-07-24 Grype의 `--only-fixed --fail-on high` 검사에서 처음 발견된 fixable 항목을 다음과 같이 보완했다.

- Alpine `c-ares 1.34.8-r0`, `libcurl 8.21.0-r0`
- hash 고정 wheel `Pillow 12.3.0`, `pyasn1 0.6.4`, `setuptools 83.0.0`
- Python 재단의 CPython 3.14 수정 commit `07efb08123ba9367a7107325adb9d5626dca1ca9`를 이미지 빌드에서 고정 backport

재검사기는 Python binary version이 계속 `3.14.6`이므로 High `CVE-2026-15308` 1건과 3.15 prerelease를 fixed version으로 제시하는 Medium 3건(`CVE-2025-15366`, `CVE-2025-15367`, `CVE-2026-12003`)을 보고한다. High 항목의 실제 이미지에는 Python 재단의 3.14 공식 수정 코드가 적용되어 있고, 취약 패턴의 200,000회 분할 입력 회귀 시험도 통과했다. 이 버전 기반 잔여 보고를 숨기지 않고 image label과 이 검증 기록에 남긴다. Docker Scout는 Docker ID 로그인이 없어 실행하지 못했고, 로컬 Grype DB를 사용했다.

pgAdmin은 개발 관리자 도구로만 허용한다. `admin-tools` profile, loopback bind, 별도 로그인, `cap_drop: ALL`, `no-new-privileges`, 비-superuser DB role 제한은 유지한다. 운영·Pilot 배포 전에는 새 공식 pgAdmin/CPython 이미지로 이 backport를 제거하고 다시 취약점 검사를 통과해야 한다.

## 7. 다음 작업

`IMP-049`에서 대표 KISA 질문의 정답 페이지·절·문단 인용 정확도, 근거 없음과 문서 충돌 평가를 완료했다. 다음 `IMP-050`에서 검증된 근거만 사용하는 로컬 AI를 연결한다. 실제 LLM 답변과 공식 Audit Pack 승격은 아직 수행하지 않았다.
