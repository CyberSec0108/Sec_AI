# Sec_AI Guide Catalog

이 디렉터리는 보안가이드 원문 자체가 아니라 원문의 신원, 페이지 연결과 Control 출처 연결을 보관한다.

```text
Guide Catalog
→ exact PDF SHA-256·version·license·조회범위
→ Page Map
→ PDF 물리 페이지·인쇄 페이지·추출 text hash
→ Control Source Mapping
→ 가이드 페이지와 내부 Control의 DRAFT 연결
```

## 디렉터리 구조

```text
guides/
├─ catalog.json
├─ page_maps/
│  ├─ kisa_2026_all_pages.json
│  └─ kisa_2026_pc_pages.json
├─ mappings/
│  ├─ kisa_2026_all_control_sources.json
│  ├─ kisa_2026_pc_control_sources.json
│  └─ kisa_2026_unix_control_sources.json
└─ evaluations/
   └─ kisa_2026_pc_questions.json
```

| 구분 | 역할 | 바뀌면 확인할 것 |
|---|---|---|
| Catalog | exact 원문 신원·hash·판본·이용 범위 | 원문 악성코드·크기·페이지·license |
| Page Map | PDF 물리 페이지와 표시 페이지·text hash 연결 | 페이지 이동·추출 품질·비내용 페이지 |
| Mapping | Guide의 절·페이지·문단과 내부 Control 연결 | 사람 검토·원문 인용·Pack과의 차이 |
| Evaluation | 대표 질문의 기대 Control·페이지·근거 | recall·MRR·인용 정확도·근거 없음 |

원문 PDF는 [`../data/README.md`](../data/README.md)의 규칙에 따라 `data/`에 한 번만 보관합니다. 이 폴더에는 원문 복사본, OCR 결과, chunk text, embedding 또는 실제 검색 DB를 넣지 않습니다.

## 현재 등록 원문

| 항목 | 값 |
|---|---|
| Guide ID | `kisa-major-infrastructure-detailed-guide` |
| Version | `2026` |
| 원본 위치 | 프로젝트 루트 기준 `data/주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf` |
| 전체 페이지 | 873 |
| 현재 질문 준비 범위 | PDF 전체 분류 질의 경로 + PC-01~18·UNIX U-01~U-67 Control Source Mapping |
| PC-01~18 본문 | 555~592쪽 |
| Catalog 상태 | `APPROVED` — 프로젝트 내부 검색용 |
| 이용 상태 | `APPROVED_INTERNAL_GUIDE_QA` |
| 실제 검색 저장 | PostgreSQL 문서 1건, 기존 PC 41개 32차원 rollback 세대와 BGE-M3 1024차원 vector 908건 병렬 보존 |
| 검색 품질 | PC-01~18 IMP-049 근거 검증 `APPROVED`; 전체 분류 BGE-M3 recall·MRR·인용 정확도·p95 benchmark 대기 |

원문 PDF는 container image, source ZIP, 이동 묶음과 이 디렉터리에 복사하지 않는다. Catalog의 상대경로와 SHA-256으로 사용자가 제공한 로컬 원본을 찾고 동일 파일인지 확인한다.

## 중요한 승인 분리

다음 세 상태는 서로 자동 승격되지 않는다.

```text
Guide Catalog APPROVED
≠ Control Source Mapping APPROVED
≠ Audit Pack APPROVED
```

현재 Guide Catalog의 내부 검색과 승인된 범위의 가이드 Q&A는 허용되지만 Mapping과
기존 `0.6.0` PC Audit Pack, `2026-DRAFT` UNIX Audit Pack은 계속 `DRAFT`다. 따라서
LLM 답변은 근거 설명에만 사용하며 Mapping이나 Audit Pack을 자동 승인하거나 공식
판정을 만들 수 없다.

IMP-048에서 사용자가 내부 이용·파생 text 저장·실제 반입을 승인했다. exact PDF는 ClamAV `CLEAN`, PC 41쪽 text hash·글자 수·페이지 연결 일치, OCR 필요 0쪽을 통과했고 PostgreSQL+pgvector에 실제 적재됐다. 외부 원문 재배포는 계속 금지한다.

IMP-049에서는 [`evaluations/kisa_2026_pc_questions.json`](evaluations/kisa_2026_pc_questions.json)의 PC-01~18 대표 질문 18개와 범위 밖 질문 4개를 실제 DB에서 검증했다. 정답 Control·페이지·문단 근거 18/18, 근거 없음 4/4, 충돌 문서 처리 3/3, 조직·가이드 범위 누출 0건을 통과했다.

2026-08-03 확장에서는 PDF 전체 분류와 PC·UNIX/Linux·Switch·Network·Web 범위의
복합·비교·모호 질문 경로, BGE-M3 1024차원 generation과 전용 reranker를 추가했다.
UNIX U-01~U-67의 제목·중요도·쪽수는
[`mappings/kisa_2026_unix_control_sources.json`](mappings/kisa_2026_unix_control_sources.json)에
고정한다. 이 구현은 전체 분류 검색의 운영 품질 승인이나 UNIX Audit Pack 승인을
뜻하지 않으며 정식 benchmark가 남아 있다.

원문 확인 과정에서 기존 `0.6.0 DRAFT` Audit Pack과 실제 KISA 제목이 다른 PC-04·06·08·09를 확인했다. Source Mapping은 실제 원문에 맞춘 `0.2.0`으로 바로잡았지만 DRAFT Pack의 규칙·Finding은 이번 단계에서 바꾸거나 승인하지 않았다. Pack 수정은 별도 검토와 회귀시험을 거쳐야 한다.

## 재검증

잠긴 개발 container에서 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp047-guide-source.ps1
```

이 명령은 원문 내용을 출력하지 않고 source hash·파일 크기·873쪽, PC 41쪽의 text hash, PC-01~18 page range와 기존 DRAFT Pack의 citation 일치만 JSON 요약으로 출력한다.

실제 적재·일반 조회·관리자 UI 통합 재검증은 다음 명령으로 수행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp048-guide-store.ps1
```

질문별 정답 페이지·절·문단 인용, 근거 없음, 문서 충돌과 범위 누출 검증은 다음 명령으로 수행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp049-guide-grounding.ps1
```

## 새 가이드·판본 추가 절차

1. 공식 출처·이용 조건과 내부 반입 승인을 확인합니다.
2. 원문을 `data/`에 추가하고 malware·exact SHA-256·페이지·추출 품질을 검사합니다.
3. 기존 Catalog entry를 덮어쓰지 않고 새 문서 또는 새 version을 등록합니다.
4. Page Map을 만들고 non-content 페이지와 표시 페이지를 확인합니다.
5. 필요한 Control Source Mapping을 DRAFT로 작성해 사람 검토를 받습니다.
6. valid/invalid Schema와 대표 질문 Evaluation을 추가합니다.
7. staging generation에 적재해 범위 누출, 근거 없음과 인용 정확도를 검증한 뒤 원자적으로 활성화합니다.

검색 품질을 통과해도 Audit Pack을 자동 수정하거나 승인하지 않습니다. 원문과 DRAFT Pack의 제목·기준 차이는 별도 Pack 변경 및 결정론 회귀로 처리합니다.

## 변경 체크리스트

- [ ] exact 원문 hash와 Catalog version을 확인했습니다.
- [ ] 실제 원문 문장을 불필요하게 Fixture·로그에 복제하지 않았습니다.
- [ ] 조직·가이드·version·Control 범위를 검색 요청과 결과에 유지합니다.
- [ ] prompt injection 문서를 시스템 지침처럼 처리하지 않습니다.
- [ ] 근거가 없을 때 추측 인용을 만들지 않습니다.
- [ ] 외부 AI로 전송되는 내용과 이용 승인을 검토했습니다.
- [ ] Mapping/Pack의 `DRAFT` 상태를 임의로 승격하지 않았습니다.

JSON 계약은 [`../database/schemas/README.md`](../database/schemas/README.md), 적재·검색 구현은 [`../src/README.md`](../src/README.md), 점검 기준은 [`../audit_packs/README.md`](../audit_packs/README.md)를 확인합니다.
