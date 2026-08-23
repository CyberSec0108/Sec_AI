# PRODUCT-AI-05 점검 결과 문맥 후속 질문 검증 기록

| 항목 | 결과 |
|---|---|
| 작업 ID | `PRODUCT-AI-05` |
| 검증일 | 2026-07-26 |
| 상태 | **PASS — 단계 완료** |
| 현재 AI Runtime | OpenRouter `openai/gpt-oss-120b`를 `VLLM_COMPATIBILITY_TEST_DOUBLE`로 사용 |
| 최종 AI Runtime | `LOCAL_VLLM_FULL_CONTEXT` — `PRODUCT-AI-09` 인수 대상 |
| 공식 판정 권한 | 규칙 엔진만 보유, LLM 변경 권한 없음 |
| 공식 Finding·Audit Pack write | 없음 |

## 1. 완료한 사용자 흐름

```text
점검 결과 카드의 ‘이 결과를 AI에게 질문’
→ 선택한 result ID·version·Control·공식 상태·설명 입력 hash 고정
→ 로그인 조직 범위의 PostgreSQL+pgvector에서 해당 KISA 문단 검색
→ 내부 model-gateway
→ 현재 OpenRouter(vLLM 호환 시험 대역) 후속 설명
→ 위험 시나리오·조치 주의점·우선순위 이유·한계·추천 질문 표시
```

후속 질문은 전체 PC 원시 증적이나 다른 결과를 모델에 보내지 않는다. 사용자가
선택한 결과 한 건과 승인된 KISA 문단 한 건만 사용한다.

## 2. 문맥 고정과 안전 경계

요청 문맥은 다음 항목을 canonical hash로 묶는다.

- `result_id`, `result_version`, `selected_control_id`
- 규칙 엔진의 불변 `rule_status`
- PRODUCT-AI-01 `explanation_input_sha256`
- PRODUCT-AI-02 `guide_evidence_sha256`
- 사용자 질문

다음 조건은 fail-closed로 거부한다.

- 선택한 Control과 설명 입력 Control이 다름
- 공식 상태, 설명 입력 hash 또는 KISA 근거 계보가 다름
- 다른 결과·사용자·Asset 문맥을 함께 사용하려는 요청
- 원시 증적·민감 식별자 포함
- 프롬프트 인젝션 또는 실행형 모델 출력
- 모델이 공식 규칙 상태를 바꾸려는 출력

모델 메시지에는 result ID와 `PASSWORD_CHANGE_PERIOD_NOT_COMPLIANT` 같은 내부
이유 코드를 넣지 않는다. result ID는 서버가 응답을 원래 화면에 연결할 때만 사용한다.

## 3. OpenRouter와 최종 로컬 vLLM 경계

사용자 승인에 따라 현재 OpenRouter는 로컬 vLLM의 OpenAI 호환 API를 미리 시험하는
대역으로 사용한다. 비식별 시험 결과와 해당 KISA 문단을 보내는 범위만 허용한다.

현재 live 검증:

- runtime profile: `VLLM_COMPATIBILITY_TEST_DOUBLE`
- model: `openai/gpt-oss-120b`
- 외부 전송: `true`
- 시험 자료만 사용: `true`

최종 제품에서는 동일한 DTO·프롬프트·SSE·UI 계약을 유지하고
`SECAI_LLM_API_BASE`와 `SECAI_LLM_MODEL`을 로컬 vLLM 값으로 바꾼다.
`PRODUCT-AI-09`에서 `LOCAL_VLLM_FULL_CONTEXT`, 외부 egress 0, model·revision·license
표시를 검증하기 전에는 로컬 AI 인수 완료로 표시하지 않는다.

## 4. PRODUCT-AI-04 실제 점검 누락 보완

기존 일반 권한 점검은 수집한 Control만 평가해 결과가 18개보다 적으면 AI 입력 생성을
중단했다. 이 때문에 화면에 “AI 설명에 필요한 시험 점검 결과가 준비되지 않았습니다”가
표시될 수 있었다.

수정 후에는 PC-01~18을 항상 반환한다.

- 실제로 읽은 항목: 읽은 값으로 DRAFT 규칙 판정
- 관리자 권한이 필요한 미수집 항목:
  `관리자 권한이 필요한 자료를 아직 확인하지 못했습니다`
- 그 밖의 미수집 항목:
  `점검에 필요한 자료를 아직 확인하지 못했습니다`
- 미수집 상태는 임의 PASS/FAIL이 아니라 `확인 필요(ERROR)`

따라서 AI 입력이 비어 버리지 않으며, 관리자 점검 전의 항목도 안전하다고 추정하지 않는다.

## 5. live 통합 검증

실제 로그인 세션과 CSRF를 사용해 비식별 PC-01 시험 결과를 후속 질문 API에 전송했다.

| 확인 항목 | 결과 |
|---|---|
| HTTP | `200` |
| SSE 순서 | 문맥 검증 → 선택 KISA 근거 검색 → 후속 답변 생성 → 완료 |
| 최종 상태 | `GENERATED` |
| 선택 결과 | PC-01, result version 1 |
| 공식 규칙 상태 | `FAIL` 유지 |
| KISA 인용 | 1건, KISA 2026 PC-01, PDF 555쪽, 문단 4 |
| 구조화 답변 | 답변·위험 시나리오·조치 주의점·우선순위 이유·한계·추천 질문 생성 |
| 외부 전송 | `true` — 사용자 승인 비식별 시험 범위 |
| output hash | 64자리 canonical SHA-256 생성 |
| Finding·Pack write | 0 |

OpenRouter가 `limitations`를 단일 문자열로 반환하는 호환성 편차도 확인했다. 서버는
문자열 한 건을 안전한 목록 한 건으로 정규화하며, 그 밖의 잘못된 필드나 실행형 출력은
계속 거부한다.

## 6. 변경 파일

- `src/security_audit/application/current_host_regression.py`
  - 일반 점검에서 PC-01~18 전체를 안전한 DRAFT 판정 입력으로 구성
- `src/security_audit/application/result_ai_explanation.py`
  - PRODUCT-AI-03 계보 검증을 후속 질문에서도 재사용할 공개 검증 함수 제공
- `src/security_audit/application/result_follow_up.py`
  - 한 결과·한 Control·한 KISA 근거의 후속 질문 계약과 모델 출력 검증
- `apps/api/result_ai_explanation.py`
  - 조직 범위 검색과 인증·CSRF가 적용된 SSE 후속 질문 endpoint
- `apps/web/templates/pages/product_results.html`
  - 선택 결과 문맥, 예시 질문, 생성 상태, 답변·출처 패널
- `apps/web/static/app/product-results.js`
  - 선택 결과 고정, SSE 즉시 갱신, DOM 기반 안전 렌더링
- `apps/web/static/app/app.css`
  - 후속 질문 패널과 반응형 구성
- `tests/unit/test_product_ai_04_result_explanation_ui.py`
  - 실제 부분 수집에서도 18개 안전 입력을 만드는 회귀
- `tests/unit/test_product_ai_05_result_follow_up.py`
  - 문맥 고정·혼합 차단·안전 모델 입력·canonical hash·SSE·UI 계약
- `tests/unit/test_imp042_result_guidance.py`
  - 미수집 Control의 안전한 `ERROR` 회귀

## 7. 검증 결과

| 검증 | 결과 |
|---|---|
| PRODUCT-AI-05 집중 Pytest | `5 passed` |
| PRODUCT-AI-01~05 + Launcher·결과 회귀 | `59 passed` |
| 변경 Python Ruff | `All checks passed` |
| 변경 Python mypy | `Success: no issues found in 4 source files` |
| `product-results.js` Node syntax | PASS |
| live 인증·CSRF·pgvector·OpenRouter SSE | `GENERATED`, citation 1, 공식 `FAIL` 유지 |
| API OpenAPI path | 기존 설명 + 후속 질문 2/2 등록 |
| API container | `healthy` |
| source↔container 핵심 파일 SHA-256 | 4/4 일치 |
| Windows EXE native build acceptance | 10/10 PASS |

Pytest의 Starlette/httpx deprecation warning 1건은 기존 의존성 경고이며 이번 기능
실패가 아니다.

## 8. 배포 확인

- 재빌드 서비스: `api`만
- image: `sec-ai-mvp/audit-api:0.1.0`
- image/container digest:
  `sha256:a731012889ed8a1e746fefae0fb4c7d55602b1f3a4c3d604bf31bf2810132e55`
- container: `sec-ai-mvp-dev-api-1`
- 상태: `healthy`
- 후속 질문 OpenAPI path:
  `/api/v1/result-explanations/follow-up/stream`
- PostgreSQL, pgvector, model-gateway, gateway와 worker image는 변경하지 않음

Windows Launcher는 PRODUCT-AI-04의 18개 안전 입력 보완을 포함해 재빌드했다.

- artifact:
  `runtime/imp034-artifacts/build-20260726T015046Z/SecAI-Collector-Windows-x64.exe`
- bytes: `11,842,729`
- SHA-256:
  `7f251a2eb880befeff5d0e4ddd86818901a1a161418719df16bfa50df5a281d1`
- CPython/PyInstaller: `3.14.6` / `6.21.0`
- embedded resources: `99`
- dependency components: `24`
- 알려진 의존성 취약점: `0`
- ClamAV: `CLEAN`
- Microsoft Defender: `CLEAN`
- release: `DEV-UNSIGNED`, 운영 배포 아님
- 이동 묶음: 생성하지 않음

## 9. 다음 Gate

바로 다음 작업은 `PRODUCT-AI-06`이다.

- 결과가 있어도 PC 점검 화면으로 항상 이동
- 다시 점검하면 이전 결과를 덮어쓰지 않는 새 이력 생성
- 이전/현재를 개선·악화·미변경·남은 위험으로 비교
- AI는 규칙 판정을 바꾸지 않고 변화의 의미와 다음 행동을 설명
- Launcher 중복 실행과 포트 충돌 0

`PRODUCT-AI-09`의 실제 로컬 vLLM·외부 egress 0 최종 인수와 `IMP-055~062`의
깨끗한 Windows 11 VM·서명·SmartScreen·Pilot 검증은 아직 남아 있다.
