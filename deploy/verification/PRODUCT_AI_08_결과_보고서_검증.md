# PRODUCT-AI-08 결과 PDF·AI 모델 활용 명세 검증

검증일: 2026-07-26  
결과: **PASS**

## 구현 결과

- 점검 결과 화면에 다음 기능을 추가했다.
  - `사용자용 PDF 받기`
  - `기술 검증용 PDF 받기`
  - `AI 모델 활용 명세 받기`
  - 이전 보고서 version·PDF SHA-256 확인과 재다운로드
- 동일한 `result ID + result version + owner + organization`은 하나의 불변
  snapshot으로 저장한다. 같은 식별자로 내용 hash가 바뀌면
  `REPORT_SNAPSHOT_CONFLICT`로 거부한다.
- 보고서를 다시 만들면 기존 파일을 갱신하지 않고 같은 snapshot 아래
  `report_version`을 1씩 증가시켜 append-only로 저장한다.
- PDF는 신규 외부 의존성 없이 A4·한국어 CID font 계약으로 생성한다.

## 사용자용·기술 검증용 분리

### 사용자용 PDF

- 전체 판정 요약, AI 종합 설명, PC-01~18 항목별 실제 확인 내용,
  KISA 권고 기준, 자연어 판정 이유, 다음 행동과 KISA 페이지를 포함한다.
- `PASSWORD_COMPLEXITY_NOT_OBSERVED` 같은 내부 이유 코드,
  PowerShell/API/Registry 기술 locator, 수집기·Adapter 내부 이름과
  원시 증적은 포함하지 않는다.

### 기술 검증용 PDF와 모델 명세

- 내부 이유 코드, 확인 방법·기술 위치, Collector/Probe/Adapter version,
  설명 입력·규칙 결과·snapshot·보고서·AI 계보 SHA-256을 포함한다.
- AI 활용 유형, provider, deployment, base/served model, revision, license,
  외부 전송 여부, AI 역할·비역할을 기록한다.
- 현재 OpenRouter는 `VLLM_COMPATIBILITY_TEST_DOUBLE`인 시험 대역으로
  기록하며 로컬 vLLM image·digest·SBOM·weight·악성코드 검사를 완료했다고
  표시하지 않는다. 이 공급망 Gate는 `DEFERRED_PRODUCT_AI_09`다.
- 기술 검증용 PDF와 모델 명세는
  `evidence.original.download` 권한을 가진 승인된 보안 검증 담당자만
  생성·다운로드할 수 있다.

## 데이터·보안 계약

- 신규 migration head: `0012_product_ai_08`
- 신규 테이블:
  - `result_report_snapshots`
  - `result_reports`
  - `result_report_access_events`
- 세 테이블 모두 조직·소유자 기준 PostgreSQL
  `FORCE ROW LEVEL SECURITY`를 사용한다.
- `secai_runtime` 권한은 `SELECT, INSERT`만 허용하며
  `UPDATE, DELETE` 권한은 없다.
- 보고서 대상 Asset ID와 다운로드 파일명은 브라우저 입력으로 받지 않는다.
  로그인 Principal에 단 하나 배정된 Asset을 서버가 결정하고 파일명은
  고정된 안전한 이름을 사용한다.
- 생성은 인증 세션 CSRF를 검증하고, 소유자 밖 report ID는 404로 처리한다.
- 생성·다운로드·모델 명세 다운로드·권한 거부는 append-only 감사 이벤트로
  기록한다.

## 검증 결과

| 검증 | 결과 |
|---|---|
| PRODUCT-AI-08 계약 Pytest | 6 PASS |
| PRODUCT-AI-01~08 집중 회귀 | 57 PASS, 기존 Starlette deprecation warning 1건 |
| 변경 Python Ruff | PASS |
| 변경 애플리케이션 mypy strict | PASS |
| `product-results.js` Node 문법 검사 | PASS |
| 실제 DEV-LOCAL 로그인 | PASS |
| 일반 사용자용 PDF 생성·다운로드 | PASS |
| 같은 snapshot 재생성 | 최종 검증 report version 5→6 append-only PASS |
| 일반 사용자의 기술 PDF 생성 | 403 `TECHNICAL_REPORT_PERMISSION_REQUIRED` PASS |
| PostgreSQL 검증 자료 | 검증 snapshot 1건·사용자 report 6건 |
| 감사 이력 | 전체 생성 7건·다운로드 4건·권한 거부 4건, IDOR 404 거부 감사 1건 포함 |
| 최종 실검증 PDF SHA-256 | `55ec27ee34de0f795d14119dcd0ccf7b53a093aa3135d089b948db291707b094` |
| 마이그레이션 | `0012_product_ai_08 (head)` |

실제 API 검증에 사용한 result ID `0808080808080808`의 시험 snapshot과
사용자 보고서 v1~v6은 append-only 및 감사 계약 확인 자료로 보존했다.
현재 Launcher 결과 화면에서는 다른 result ID를 조회하므로 일반 사용자
이력에 섞이지 않는다.

## 배포 확인

- API image/container:
  `sha256:318ab44cc51b356921e573818989214a128179e05a6eed56224b5fac2fb4a924`
- API health: `healthy`
- Gateway health: `healthy`
- PostgreSQL health: `healthy`
- 기존 점검·대화·가이드 데이터는 보존했다.

## 보류 Gate

- 현재 DEV-LOCAL 일반 계정은 `USER` 역할이므로 실제 UI에서 기술 검증용
  버튼이 비활성화되는 것이 정상이다.
- 로컬 vLLM image/digest, SBOM, model weight hash·source, 악성코드 검사,
  외부 egress 0과 실제 `LOCAL_VLLM_FULL_CONTEXT` 보고서 생성은
  `PRODUCT-AI-09`에서 검증한다.
- 깨끗한 Windows 11 VM·서명·SmartScreen·Pilot은 `IMP-055` 이후다.

## 다음 작업

`PRODUCT-AI-09 — 아이콘·반응형·SSE·로컬 vLLM 최종 제품 인수`를 진행한다.
해·달 및 패널 아이콘, 초보 사용자 desktop/mobile·keyboard 과업,
점검→AI 설명→후속 질문→PDF 전체 흐름과 로컬 vLLM 공급망·외부 egress 0을
최종 전체 Gate에서 검증한다.
