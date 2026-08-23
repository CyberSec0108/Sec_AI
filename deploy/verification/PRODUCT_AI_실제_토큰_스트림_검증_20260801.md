# PRODUCT-AI 점검 결과 실제 token stream·별도 AI 분석 화면 검증

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-08-01 |
| 범위 | `PRODUCT-AI-09` 후속 제품 흐름 보완 |
| 판정 | PASS — 현재 OpenRouter 시험 환경 |
| 다음 작업 | `IMP-055` 깨끗한 Windows 11 기준 VM 제품 회귀 |

## 1. 사용자 흐름

```text
원클릭 점검 동의
→ 일반 권한 PC-01~18 수집·규칙 판정
→ 선택한 경우 관리자 UAC 결과 수신
→ 별도 /ui/ai-analysis 화면
→ PC-01부터 PC-18까지 항목별 실제 token stream
→ 마지막 AI 종합 설명 token stream
→ 상세 점검 결과·PDF·후속 질문
```

상세 점검 결과 화면은 삭제하거나 AI 출력으로 대체하지 않았다. AI 화면은 설명 생성 과정을 먼저 보여 주고, 공식 판정·실제 확인값·KISA 근거·보고서는 기존 불변 결과 화면에서 계속 확인한다.

## 2. 구현 계약

- 신규 사용자 경로: `POST /api/v1/result-explanations/from-scan/token-stream`
- 신규 화면: `/ui/ai-analysis`
- PC-01~18을 Control ID 순서로 한 건씩 생성
- upstream OpenAI 호환 SSE `delta`를 model-gateway와 API가 즉시 전달
- 한 Control이 완료될 때까지 다음 Control을 시작하지 않음
- PC-18 완료 뒤 전체 종합 설명을 별도 호출
- 호환용 기존 `/api/v1/result-explanations/from-scan/stream` validated batch API는 유지
- 관리자 추가 점검을 선택한 경우 관리자 결과 수신 뒤 허용 필드만 병합하고 explanation input canonical hash 재계산

SSE 이벤트 순서는 다음과 같다.

```text
ANALYSIS_STARTED
SEARCHING_KISA_EVIDENCE
CONTROL_STARTED
CONTROL_DELTA ...
CONTROL_COMPLETED
... PC-18까지 반복 ...
SUMMARY_STARTED
SUMMARY_DELTA ...
SUMMARY_COMPLETED
ANALYSIS_COMPLETED
```

안전하게 중단된 경우 `FAILED`를 보내며, 일부 AI 문장을 공식 완료 결과로 저장하지 않는다.

## 3. 보안·정합성

- 공식 `PASS/FAIL/ERROR/REVIEW/N/A`는 규칙 엔진 입력에서 표시하며 LLM이 변경하지 않는다.
- OpenRouter에는 사용자가 승인한 시험 환경의 비식별·정규화 결과 projection과 해당 Control의 승인 KISA 근거만 전송한다.
- 원본 Windows 증적, SID, hostname, 사용자·조직·Asset 식별자, 내부 판정 이유 코드, 명령·스크립트 전문은 전송하지 않는다.
- 관리자 결과는 allowlist 필드만 사용하고 병합 후 canonical hash를 다시 계산한다.
- AI 연결·생성 실패가 공식 점검 결과, Finding 또는 Audit Pack을 변경하지 않는다.
- 현재 OpenRouter는 `VLLM_COMPATIBILITY_TEST_DOUBLE`이며 로컬 vLLM 완료나 외부 egress 0을 의미하지 않는다.
- 향후 승인된 local vLLM은 같은 OpenAI 호환 주소·모델·SSE 계약으로 교체하며 OpenRouter 자동 fallback을 허용하지 않는다.

## 4. 변경 파일

- `src/security_audit/llm/contracts.py`
- `src/security_audit/llm/provider.py`
- `src/security_audit/llm/internal_gateway.py`
- `src/security_audit/application/result_ai_token_stream.py`
- `apps/model_gateway/main.py`
- `apps/api/result_ai_explanation.py`
- `apps/api/product.py`
- `apps/web/templates/pages/result_ai_analysis.html`
- `apps/web/static/app/result-ai-analysis.js`
- `apps/web/static/app/product-results.js`
- `apps/web/static/app/product.js`
- `apps/web/static/app/app.css`
- 관련 unit·UI 계약 시험

Collector 코드와 `SecAI-Collector-Windows-x64.exe`는 변경하지 않았다.

## 5. 검증 결과

- 관련 Pytest 묶음: 30 PASS
- cross-tab 관리자 동의 상태 전달 후속 회귀: 3 PASS
- Ruff: PASS
- mypy strict: 변경 source·test 8개 파일 PASS
- JavaScript `node --check`: PASS
- 실제 OpenRouter upstream stream:
  - delta chunk 6개 확인
  - `finish_reason=stop`
  - 빈 일괄 응답이 아니라 복수 token delta가 순차 도착
- 포함 router 기준 route 확인:
  - `/ui/ai-analysis`: 등록
  - `/api/v1/result-explanations/from-scan/token-stream`: 등록
  - `/internal/v1/chat/completions/stream`: 등록
- API·model-gateway 변경 image 재빌드와 container 재생성: PASS
- API·model-gateway health: `healthy`

이번 후속 변경에서는 직전 전체 기준선인 Pytest 566, JSON Schema 25/48, Ruff, mypy strict 261 source files를 다시 전부 실행하지 않았다. API·SSE·외부 전송 경계 변경에 직접 관련된 집중시험, 정적 검사, 실제 OpenRouter stream과 변경 서비스 재빌드를 수행했다. 전체 제품 회귀는 `IMP-055` clean Windows 11 VM Gate에서 다시 수행한다.

## 6. Runtime

- API image/container: `sha256:93dfe0981e1eecbf743ad66f9ba79dfc7c76f1b88c54ada8c4e51e39e5d17c05`
- model-gateway image/container: `sha256:0722912b079b40d41df580fdcb0f69ec264e2da7ae3e17655823f714e1546362`
- `sec-ai-mvp-dev-api-1`: healthy
- `sec-ai-mvp-dev-model-gateway-1`: healthy

## 7. 남은 Gate

- `IMP-055` 깨끗한 Windows 11 VM에서 다운로드·실행·일반/관리자 수집·AI 분석·상세 결과·PDF·후속 질문 전체 회귀
- 승인된 local vLLM 모델 적재, GPU 실행, 성능, 모델/weight/license 공급망, 외부 egress 0을 확인하는 `LOCAL-VLLM-RUNTIME-GATE`
- 조직 서명·SmartScreen·Pilot 인수

따라서 현재 상태는 “OpenRouter를 vLLM 호환 시험 대역으로 사용한 실제 token stream 제품 흐름 PASS”이며 “로컬 vLLM 운영 인수 완료” 또는 “운영 배포 승인”이 아니다.
