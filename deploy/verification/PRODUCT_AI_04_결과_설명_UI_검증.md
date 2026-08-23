# PRODUCT-AI-04 점검 결과 AI 설명 화면 검증 기록

| 항목 | 결과 |
|---|---|
| 작업 ID | `PRODUCT-AI-04` |
| 검증일 | 2026-07-26 |
| 상태 | **PASS — 단계 완료** |
| 현재 AI Runtime | OpenRouter `openai/gpt-oss-120b`를 `VLLM_COMPATIBILITY_TEST_DOUBLE`로 사용 |
| 최종 AI Runtime | `LOCAL_VLLM_FULL_CONTEXT` — `PRODUCT-AI-09` 인수 대상 |
| 공식 판정 권한 | 규칙 엔진만 보유, LLM 변경 권한 없음 |
| 공식 Finding·Audit Pack write | 없음 |

## 1. 완료한 사용자 흐름

```text
Windows Launcher의 현재 시험 점검 결과
→ 원시 증적·식별정보를 제외한 PRODUCT-AI-01 설명 입력
→ 로그인 조직 범위의 PostgreSQL+pgvector KISA 근거 검색
→ 내부 model-gateway
→ 현재 OpenRouter(vLLM 호환 시험 대역) AI 설명
→ 결과 화면의 전체 종합·우선 확인 3개·항목별 설명
```

결과 화면은 다음 정보를 분리해 표시한다.

- `규칙 엔진의 공식 판정`: 무엇을 확인했는지, 확인 방법·도구·위치,
  내 PC에서 확인한 내용, KISA 기준, 자연어 판정 이유, 제한, 출처와 다음 행동
- `AI 해석·권장`: 전체 상태, 관련 위험, AI 권장 우선순위와 이유,
  사용자 조치, 관리자 요청, 한계와 항목별 KISA 근거

`PASSWORD_COMPLEXITY_NOT_OBSERVED` 같은 내부 판정 이유 코드는 일반 사용자
화면에 표시하지 않는다. 공식 상태는 AI 응답과 별도로 규칙 엔진 값을 유지한다.

## 2. OpenRouter 시험 승인과 전송 범위

사용자는 현재 OpenRouter를 로컬 vLLM 호환 시험 대역으로 보고 현재 시험 환경의
결과를 전송하는 것을 승인했다.

허용하는 모델 입력:

- `control_id`, 제목, 중요도
- 규칙 엔진의 불변 상태
- 사용자용으로 정규화한 실제 확인 내용과 KISA 기준
- 확인 방법의 사용자용 요약
- 해당 결과에 PostgreSQL+pgvector가 검색한 KISA 관련 문단

금지하는 모델 입력:

- 원시 증적
- SID, 사용자명, hostname, 조직·Asset 식별자
- token, password, API key와 credential
- 전체 레지스트리 dump와 전체 KISA 원문
- 내부 판정 이유 코드와 기술 locator

API 요청 DTO에는 계보 검증용 기술 필드가 포함될 수 있지만, 외부 모델 메시지는
`ResultAIExplanationService`가 allowlist 필드만 다시 구성한다. 최종 제품에서는
`SECAI_LLM_API_BASE`와 `SECAI_LLM_MODEL`을 로컬 vLLM 값으로 바꾸고 같은 API·SSE·UI
계약을 사용한다. OpenRouter 시험 통과를 로컬 vLLM 완료 또는 외부 egress 0으로
표시하지 않는다.

## 3. SSE와 장애 처리

화면은 다음 생성 단계를 `aria-live="polite"` 상태로 즉시 표시한다.

1. 공식 판정과 전송 범위 확인
2. KISA 근거 검색
3. AI 위험·조치 설명 생성
4. 완료 또는 안전한 실패

KISA 검색, PostgreSQL 또는 모델 연결이 실패하면 AI 영역만 실패 메시지를 표시한다.
규칙 엔진의 공식 판정·실제값·기준·KISA 페이지 표시는 계속 사용할 수 있으며
Finding이나 PC 설정을 변경하지 않는다.

## 4. 변경 파일

- `src/security_audit/application/result_explanation_input.py`
  - 일반 15개 Probe 결과와 실행하지 않은 관리자 Probe를 구분해 전체 설명 입력 구성
  - 호출자가 보낸 부가 필드를 복사하지 않고 계약 필드와 수집 상태만 사용
- `src/security_audit/application/result_explanation_presentation.py`
  - 내부 이유 코드·기술 locator가 없는 사용자용 공식 판정 projection
- `src/security_audit/collector/launcher.py`
  - 완료 결과에 사용자 설명 projection과 AI 설명 입력을 메모리에서 연결
- `apps/api/result_ai_explanation.py`
  - 실제 시험 결과→조직 범위 KISA 검색→AI 설명 SSE endpoint
- `apps/api/product.py`
  - 결과 화면에 session-bound CSRF token 제공
- `apps/web/templates/pages/product_results.html`
  - 공식 판정과 AI 해석·권장 영역, 시험 Runtime·외부 전송 안내
- `apps/web/static/app/product-results.js`
  - 구조화 렌더링, 우선 확인 3개, SSE 단계 갱신, 내부 이유 코드 제거
- `apps/web/static/app/app.css`
  - AI 종합·목록·항목별 설명과 모바일 반응형 스타일
- `tests/unit/test_product_ai_04_result_explanation_ui.py`
  - 입력·API·SSE·화면·스크립트·CSS 집중 회귀
- `tests/unit/test_imp042_result_guidance.py`
  - 결과 화면 CSRF context 회귀 보완

## 5. 집중 검증 결과

단계별 검증 전략에 따라 전체 Gate를 반복하지 않고 변경 경계만 검증했다.

| 검증 | 결과 |
|---|---|
| PRODUCT-AI-04 집중 Pytest | `7 passed` |
| PRODUCT-AI-01~04 + Launcher·결과 회귀 | `52 passed` |
| 변경 Python Ruff | `All checks passed` |
| 변경 Python mypy | `Success: no issues found in 5 source files` |
| `product-results.js` Node syntax | PASS |
| API `/health/ready` | HTTP `200`, PostgreSQL·Redis·Aistor dependency ready |
| source↔container 핵심 파일 SHA-256 | 3/3 일치 |
| Windows EXE native build acceptance | 10/10 PASS |

Pytest의 `httpx`/Starlette deprecation warning 1건은 기존 의존성 경고이며 이번 기능
실패가 아니다.

## 6. 배포 확인

- 재빌드 서비스: `api`만
- image: `sec-ai-mvp/audit-api:0.1.0`
- image/container digest:
  `sha256:bed8ebb8d24a02468c62a6e3bb7d350f01157dc5c879591bd2f22871e7b843fe`
- container: `sec-ai-mvp-dev-api-1`
- 상태: `healthy`
- PostgreSQL, pgvector, model-gateway, gateway와 worker image는 변경하지 않음

Windows Launcher도 새 설명 입력 코드를 포함하도록 재빌드했다.

- artifact:
  `runtime/imp034-artifacts/build-20260726T010842Z/SecAI-Collector-Windows-x64.exe`
- bytes: `11,842,488`
- SHA-256:
  `d0aa75756787b987c6e7b240eaadf79ea8075ea65bbe2eaa9eee3fa97e5df6d6`
- CPython/PyInstaller: `3.14.6` / `6.21.0`
- embedded resources: `99 PASS` — PRODUCT-AI-01 source contract와 KISA Control mapping 포함
- 알려진 의존성 취약점: `0`
- ClamAV: `CLEAN`
- Microsoft Defender: `CLEAN`
- release: `DEV-UNSIGNED`, 운영 배포 아님
- 이동 묶음: 생성하지 않음

## 7. 남은 Gate

- `PRODUCT-AI-05`: 선택한 결과 ID·Control·citation을 문맥으로 후속 질문
- `PRODUCT-AI-06~08`: 재점검 비교, 대화 관리, 사용자·기술 검증 PDF
- `PRODUCT-AI-09`: 실제 로컬 vLLM, 외부 egress 0, 반응형·키보드·SSE·PDF 최종 인수
- `IMP-055~062`: 깨끗한 Windows 11 VM·서명·SmartScreen·Pilot 검증

따라서 이 기록은 `PRODUCT-AI-04` 완료를 의미하지만 전체 AI PC 보안 제품 또는
로컬 vLLM 인수 완료를 의미하지 않는다.

## 8. 2026-07-26 PRODUCT-AI-05 시작 전 보완

실제 일반 권한 점검에서 수집된 Control만 DRAFT 평가해 AI 입력이 18개보다 적어지는
문제를 수정했다. 이제 미수집 항목을 임의 PASS/FAIL로 판단하지 않고
`확인 필요(ERROR)`로 포함하므로 AI 설명 입력이 비어 버리지 않는다.

이 보완을 포함한 최신 Windows artifact는 다음과 같다.

- `runtime/imp034-artifacts/build-20260726T015046Z/SecAI-Collector-Windows-x64.exe`
- bytes: `11,842,729`
- SHA-256:
  `7f251a2eb880befeff5d0e4ddd86818901a1a161418719df16bfa50df5a281d1`
- embedded resources: `99`
- 알려진 의존성 취약점: `0`
- ClamAV / Microsoft Defender: `CLEAN`

이 기록의 6절에 적힌 이전 artifact는 당시 검증 이력으로 보존하며, 현재 실행 기준은
위 보완 artifact와
[`PRODUCT_AI_05_결과_후속_질문_검증.md`](PRODUCT_AI_05_결과_후속_질문_검증.md)다.
