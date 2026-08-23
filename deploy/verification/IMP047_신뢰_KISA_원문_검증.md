# IMP-047 믿을 수 있는 KISA 원문 준비 검증

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-07-24 |
| 단계 | `IMP-047` |
| 결과 | `PASS_WITH_APPROVAL_GATES` |
| 다음 단계 | `IMP-048` KISA 질문에 필요한 근거 찾기 |

## 1. 완료한 범위

사용자가 제공한 KISA PDF를 나중에 다른 파일과 혼동하지 않고, 답변 출처를 실제 페이지까지 되짚을 수 있도록 세 계약을 분리했다.

```text
Guide Catalog
→ 원문 파일의 신원·판본·이용 조건·조회 범위

Page Map
→ PDF 실제 페이지·표시 페이지·비내용 text 지문

Control Source Mapping
→ PC-01~18과 기존 DRAFT Audit Pack 인용의 일치
```

구현 위치:

- `guides/catalog.json`
- `guides/page_maps/kisa_2026_pc_pages.json`
- `guides/mappings/kisa_2026_pc_control_sources.json`
- `database/schemas/guide_catalog.schema.json`
- `database/schemas/guide_page_map.schema.json`
- `database/schemas/control_source_mapping.schema.json`
- `src/security_audit/guides/contracts.py`
- `tools/verify_imp047_guide_source.py`
- `tools/verify-imp047-guide-source.ps1`
- `tests/unit/test_imp047_trusted_guide_source.py`

## 2. 확인한 원문 신원

| 항목 | 확인값 |
|---|---|
| 원본 위치 | 프로젝트 기준 `data/주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf` |
| 크기 | 8,415,536 bytes |
| SHA-256 | `44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d` |
| 전체 페이지 | 873 |
| PDF 형식 | `PDF 1.4` |
| 암호화 | 없음 |
| 문서 metadata 생성시각 | `2025-12-23T16:15:37+09:00` |
| PC 장 목차 범위 | PDF 552~592쪽 |
| PC-01~18 본문 범위 | PDF 555~592쪽 |
| 등록한 Page Map | 552~592쪽, 연속 41쪽 |
| Control Mapping | PC-01~PC-18, 18개 |

PDF에는 별도의 `PageLabels`가 없었다. 화면으로 확인한 PDF 552쪽의 `07. PC` 목차, 555쪽의 PC-01 시작, 592쪽의 PC-18 마지막을 기준점으로 삼았으며, 이 범위에서는 PDF 실제 페이지 번호와 문서에 표시된 페이지 번호가 같다.

Page Map에는 원문 전체 문장을 저장하지 않았다. 잠긴 `PyMuPDF 1.28.0`으로 추출한 페이지별 정규화 글자 수와 SHA-256만 보관한다. 따라서 페이지 내용이 바뀌었는지는 탐지하면서 원문을 source나 검증 보고서에 복제하지 않는다.

## 3. 닫아 둔 승인 경계

현재 상태는 다음과 같다.

| Gate | 상태 | 의미 |
|---|---|---|
| 원문 hash | 확인 완료 | 현재 로컬 PDF가 등록 파일과 동일함 |
| 페이지 맵 | 확인 완료 | PC 범위 41쪽을 다시 찾을 수 있음 |
| 시각 기준점 | 확인 완료 | 목차·첫 Control·마지막 Control을 화면으로 확인함 |
| 악성코드 검사 | 미완료 | `IMP-048` 승인형 반입 전 수행 |
| OCR·추출 품질 승인 | 미완료 | 검색 품질 시험 전 수행 |
| 이용 조건 검토 | `REVIEW_REQUIRED` | 현재는 로컬 내부 개발에만 사용 |
| 검색 품질 승인 | 미완료 | `IMP-048~049`에서 수행 |

PDF 안에서 명시적인 공개 라이선스를 확인하지 못했으므로 재배포와 원문·파생 text 저장은 허용하지 않았다. 원문은 Docker image, 이동 묶음과 source 디렉터리에 포함하지 않는다.

다음 세 승인은 서로 다르며 자동 승격되지 않는다.

```text
Guide Catalog APPROVED
≠ Control Source Mapping APPROVED
≠ Audit Pack APPROVED
```

현재 Guide Catalog, Control Source Mapping과 Audit Pack `0.6.0`은 모두 `DRAFT`다. 질문 검색 기본 활성화와 규칙 실행 활성화는 `false`이며, LLM·Milvus·공식 Finding은 이 단계에서 연결하지 않았다.

## 4. 변조·오승격 시험

추가한 자동시험 8개는 다음을 확인한다.

1. Unicode·공백 정규화 결과가 항상 같음
2. 중복 JSON key 거부
3. 873쪽 원문·41쪽 Page Map·18개 Control 연결 일치
4. 원문 PDF hash 변경 거부
5. 페이지 text 지문 변경 거부
6. Audit Pack 인용과 Control Mapping 불일치 거부
7. DRAFT 검색·규칙 활성화 거부
8. 미검토 이용 조건을 임의로 완화하면 거부

## 5. 재실행 방법

원문 신원과 페이지 연결:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp047-guide-source.ps1
```

정상 요약:

```json
{"imp":"IMP-047","accepted":true,"source_sha256_verified":true,"source_page_count":873,"mapped_pc_page_count":41,"mapped_control_count":18,"catalog_status":"DRAFT","license_status":"REVIEW_REQUIRED","query_default_enabled":false,"runtime_activation_allowed":false,"full_text_persisted":false,"errors":[]}
```

전체 표준 검증:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action All
```

## 6. 최종 검증 결과

| 검증 | 결과 |
|---|---|
| 실제 PDF lineage verifier | PASS |
| Pytest | 417 passed, 기존 Starlette deprecation warning 1건 |
| JSON Schema | 14 schemas·26 examples PASS |
| Ruff | PASS |
| mypy strict | 210 source files PASS |
| Docker Compose config | PASS |
| Core | 9개 모두 healthy |
| API health/readiness | `ok` / PostgreSQL·Redis·AIStor·ClamAV 모두 `true` |

## 7. 다음 단계 진입 조건

`IMP-048`에서는 먼저 이용 조건과 반입 승인을 확정하고, 원문 악성코드 검사·추출 품질 검사를 통과한 자료만 검색용으로 처리한다. 그 뒤 Milvus·Embedding·Reranker와 조직·가이드 범위 필터를 연결한다.

이 단계 완료는 원문 신원과 페이지 계보를 준비했다는 뜻이다. KISA 질문답변, 검색 품질 승인, Guide `APPROVED`, Audit Pack 승인 또는 운영 배포 승인이 아니다.
