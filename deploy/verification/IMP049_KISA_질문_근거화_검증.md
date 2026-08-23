# IMP-049 KISA 질문별 검색·인용 정확도 검증

| 항목 | 결과 |
|---|---|
| 상태 | `COMPLETE` |
| 평가셋 | `kisa-2026-pc-grounding-v1` |
| 실제 근거 저장소 | PostgreSQL 18.4 + pgvector 0.8.2, KISA PC 41쪽 |
| 정답 근거 질문 | PC-01~18 대표 질문 18개 |
| 정답 Control top-1 | 18/18 PASS |
| 페이지·절 인용 | 18/18 PASS |
| 문단 근거·hash | 18/18 PASS |
| 근거가 없는 질문 | 4/4 `NO_EVIDENCE` PASS |
| 문서 충돌 | 3/3 `CONFLICT` 또는 명시적 최신판 선택 PASS |
| 조직·가이드 범위 누출 | 0건 |
| 다음 단계 | `IMP-050` 내 PC에서 답변할 로컬 AI 연결 |

## 1. 사용자가 얻게 되는 안전성

검색 결과가 질문과 관련 있어 보인다는 이유만으로 답변 근거로 사용하지 않는다. 다음 정보가 실제 승인 원문과 모두 맞아야 인용 가능한 근거가 된다.

```text
Guide ID·version·원문 SHA-256
→ 조회 조직·가이드·버전·PC 범위
→ PDF 물리 페이지·인쇄 페이지
→ Control ID·절 제목
→ 문단 순번·문단 SHA-256·text SHA-256
→ 질문 핵심어와 인용 문단의 일치
```

일치하는 근거가 없으면 `NO_EVIDENCE`, 같은 우선순위의 승인 문서가 서로 다른 내용을 말하면 `CONFLICT`로 닫힌다. 명시적으로 대체한 최신 버전만 우선 선택할 수 있다. 이 단계는 검색·근거 계약의 검증이며 아직 LLM 답변을 생성하지 않는다.

## 2. 평가셋과 계약

- [`guides/evaluations/kisa_2026_pc_questions.json`](../../guides/evaluations/kisa_2026_pc_questions.json)
  - PC-01~18을 각각 한 번 이상 포함하는 실제 질문 18개
  - PC 범위를 분명히 벗어난 질문 4개
  - top-1 Control·페이지·문단·근거 없음 기준을 모두 100%로 고정
  - 허용 범위 누출 최대 0건
- [`database/schemas/guide_question_evaluation.schema.json`](../../database/schemas/guide_question_evaluation.schema.json)
  - 평가 질문, 정답 Control·페이지, 핵심 인용어와 임계값 계약
- [`database/schemas/guide_search_result.schema.json`](../../database/schemas/guide_search_result.schema.json)
  - `FOUND`·`NO_EVIDENCE`·`CONFLICT`
  - 문서·원문·페이지·절·문단 계보와 hash
- [`src/security_audit/guides/grounding.py`](../../src/security_audit/guides/grounding.py)
  - 결정론적 문단 선택, 인용 검증, 근거 부족과 충돌 fail-closed 처리

검색 후보는 pgvector와 어휘 검색 결과를 함께 받지만 최종 재정렬은 실제 41쪽 평가 결과에 따라 dense 15%·lexical 85%로 고정했다. 평가 기준을 낮추지 않았으며 같은 입력은 같은 순서와 인용 hash를 반환한다.

## 3. 실제 PostgreSQL 검증

재빌드한 API image 안의 코드와 평가셋을 사용해 실제 PostgreSQL+pgvector의 승인된 KISA PC 41쪽을 조회했다. 원본 PDF와 `data/`는 image에 넣지 않았다.

```json
{
  "citation_page_pass": 18,
  "conflict_pass": 3,
  "conflict_total": 3,
  "evaluation_id": "kisa-2026-pc-grounding-v1",
  "failures": [],
  "imp": "IMP-049",
  "no_evidence_pass": 4,
  "no_evidence_questions": 4,
  "paragraph_evidence_pass": 18,
  "scope_leaks": 0,
  "supported_questions": 18,
  "top1_control_pass": 18
}
```

초기 실제 평가는 top-1 7/18이었다. 임계값을 완화하지 않고 한국어 질의 표현 정규화, 문자 2·3-gram, PC 범위 제목 제외와 재정렬을 보완했다. 이 과정에서 단순 검색 튜닝으로 숨길 수 없는 원문 제목 차이도 발견해 아래와 같이 분리 처리했다.

## 4. KISA 원문과 기존 DRAFT Pack 차이

실제 KISA 원문 제목은 기존 `0.6.0 DRAFT` Audit Pack 설명과 다음 네 항목에서 달랐다.

| Control | 실제 KISA 원문 제목 |
|---|---|
| PC-04 | 공유 폴더 제거 |
| PC-06 | 비인가 상용 메신저 사용 금지 |
| PC-08 | Windows 서버를 제외한 다른 OS로 멀티 부팅할 수 없도록 설정 |
| PC-09 | 브라우저 종료 시 임시 인터넷 파일 폴더 내용 삭제 |

[`guides/mappings/kisa_2026_pc_control_sources.json`](../../guides/mappings/kisa_2026_pc_control_sources.json)은 실제 원문 기준 `0.2.0`으로 바로잡았다. 기존 DRAFT Pack의 규칙·Fixture·Finding은 IMP-049에서 임의 변경하지 않았다. 따라서 Mapping과 Audit Pack은 계속 `DRAFT`, `runtime_activation_allowed=false`, `audit_pack_activation_allowed=false`다. 네 항목의 공식 Pack 수정은 별도 검토·결정론 회귀·승인 절차가 필요하다.

## 5. 전체 검증

```text
Pytest: 444 PASS, 기존 Starlette deprecation warning 1건
JSON Schema: 17 schemas·32 examples PASS
Ruff: PASS
mypy strict: 219 source files PASS
KISA source gate: accepted=true, source/page hash PASS, DRAFT label drift warning 4건
IMP-049 actual DB: top-1 18/18, page 18/18, paragraph 18/18
근거 없음: 4/4
문서 충돌: 3/3
조직·가이드 범위 누출: 0
API image: sec-ai-mvp/audit-api:0.1.0 재빌드
API image manifest: sha256:d54bc4a055e08b63f51fb919173b76b5e27e0f7ca20c22c7c220418936cf0471
```

재실행:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp049-guide-grounding.ps1

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action All
```

## 6. 범위 밖과 다음 작업

- LLM 답변·Streaming·대화 기록은 구현하지 않았다.
- Guide 검색 품질 승인만 열었으며 공식 Audit Pack과 Finding 승인은 열지 않았다.
- 원문 재배포·원본 증적 다운로드·운영 OIDC·운영 배포는 열지 않았다.
- `IMP-050`에서 모델 license·CPU/GPU 자원·빠른/정밀 모드와 장애 시 대체 동작을 검증한 뒤, 이 단계에서 통과한 근거만 로컬 AI 입력으로 사용한다.
