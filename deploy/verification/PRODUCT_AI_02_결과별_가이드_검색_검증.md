# PRODUCT-AI-02 결과별 KISA 근거 검색 검증

| 항목 | 결과 |
|---|---|
| 작업일 | 2026-07-25 |
| 상태 | 완료 `[x]` |
| 선행 계약 | `PRODUCT-AI-01` explanation input DTO |
| 다음 작업 | `PRODUCT-AI-03` 규칙 결과와 AI 설명 API 연결 |

## 1. 구현 범위

PRODUCT-AI-01의 불변 점검 결과를 기존 PostgreSQL+pgvector 검색, 로컬 한국어 embedding, deterministic reranker, IMP-049 페이지·문단 인용 계층과 연결했다.

- explanation input canonical hash 검증
- PC-01~18 Control과 승인 Guide Catalog·KISA source mapping exact 일치 확인
- `what_was_checked` 중심 검색 질의와 query SHA-256 생성
- 조직·guide·version·scope·Control exact 필터
- KISA page·section·chunk·paragraph ordinal·paragraph hash 반환
- LLM 호출 전 `FOUND`, `INSUFFICIENT_EVIDENCE`, `CONFLICT` 상태 분리
- 규칙 상태 권한은 계속 `RULE_ENGINE`
- 공식 Finding 쓰기와 Audit Pack 변경은 항상 금지
- output canonical SHA-256 고정

다른 Control을 근거로 대신 답하거나 다른 조직의 검색 결과를 반환하지 않는다. 충분한 근거가 없으면 citation과 문단을 빈 값으로 반환한다.

## 2. 주요 산출물

- `src/security_audit/application/result_guide_retrieval.py`
- `database/schemas/finding_guide_evidence.schema.json`
- `database/schemas/examples/valid/finding_guide_evidence.json`
- `database/schemas/examples/invalid/finding_guide_evidence.json`
- `tests/unit/test_product_ai_02_result_guide_retrieval.py`
- `database/verification/verify_product_ai_02.py`
- `tools/verify-product-ai-02.ps1`

재현 SHA-256:

| 파일 | SHA-256 |
|---|---|
| application service | `38E59507B527F487AB59EB5D8104A6BA2636D2BA3A455C8872986453B95E2B88` |
| output JSON Schema | `306AF185F70ABE46265BA1B1BED0A38C536512F9A02DB2F6522F75BBE5967066` |
| unit test | `189F754A3B102977CE7328412914C726DC641D6E5C838022CB1CAFB1B0F7101D` |
| actual DB verification | `5E151C8A5273F0D6375F4688B7C315C1B612FE57E6ED7D014D88DBDC1F08FDAE` |

## 3. 집중 검증

- PRODUCT-AI-02 단위시험: 6 PASS
- PC-01~18 합성 결과별 page·section·paragraph·chunk: 18/18
- 다른 Control fallback: 0
- 다른 조직 scope 노출: 0
- 충돌 상태 citation: 0
- 변조된 explanation hash·source mapping: fail-closed
- 동일 입력 100회 output hash: 1개
- 생성 결과 JSON Schema: PASS
- 집중 Ruff·mypy: PASS

## 4. 실제 PostgreSQL+pgvector 검증

명령:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-product-ai-02.ps1
```

최종 결과:

| 검증 | 결과 |
|---|---|
| PC-01~18 근거 발견 | 18/18 |
| Control·page·section 일치 | 18/18 |
| paragraph evidence term 일치 | 18/18 |
| 다른 조직 citation | 0 |
| 승인 문서 충돌 citation | 0 |
| 공식 Finding write | 0 |

첫 실행에서 PC-08은 Control·page·section은 맞았지만 결과값과 기준 문구를 과도하게 검색 질의에 넣어 문단 선택이 17/18이었다. 검색 질의를 `Control + 무엇을 확인했는지`로 축소하고 실제값·규칙 상태는 input/output hash로 결합해, 검색 정확도와 결과 계보를 분리했다. 수정 후 18/18을 통과했다.

## 5. 전체 표준 Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

최종 결과:

- Docker Compose config: PASS
- Python: `3.14.6`
- Pytest: `518 passed`, 기존 Starlette deprecation warning 1건
- JSON Schema: 24 schemas·46 examples PASS
- Ruff: PASS
- mypy strict: 242 source files PASS

첫 전체 실행에서는 기존 Launcher 재실행 시험이 브라우저 handoff 직후의 50ms shutdown timer race로 1회 실패했다. 재실행 응답 후 전용 shutdown thread를 즉시 시작하도록 수정했고 동일 시험 동시 5회와 최종 전체 Gate가 통과했다.

## 6. 배포 확인

변경된 API 서비스만 빌드하고 `--no-deps`로 교체했다.

| 항목 | 결과 |
|---|---|
| image | `sec-ai-mvp/audit-api:0.1.0` |
| image ID | `sha256:215884c8a6eca5fee86a9c752265d16a849a09d2fafaa5ab177664622a86a3f9` |
| container | `sec-ai-mvp-dev-api-1` |
| image/container 일치 | PASS |
| 상태 | running·healthy |
| API `/health` | PASS |
| API `/ready` | PostgreSQL·Redis·AIStor·ClamAV 모두 `true` |

PostgreSQL migration과 운영 데이터는 변경하지 않았다. Gateway·worker·model-gateway·데이터 계층 이미지는 재빌드하지 않았다.
