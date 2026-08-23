# PRODUCT-AI-03 규칙 판정·적극적 AI 설명 API 검증

| 항목 | 결과 |
|---|---|
| 작업일 | 2026-07-25 |
| 상태 | 완료 `[x]` |
| 선행 계약 | `PRODUCT-AI-01` explanation input, `PRODUCT-AI-02` result guide evidence |
| 현재 모델 환경 | OpenRouter `openai/gpt-oss-120b`를 `VLLM_COMPATIBILITY_TEST_DOUBLE`로 사용 |
| 최종 모델 환경 | `LOCAL_VLLM_FULL_CONTEXT` — PRODUCT-AI-09에서 별도 인수 |
| 다음 작업 | `PRODUCT-AI-04` AI 종합·항목별 결과 화면 |

## 1. 구현 결과

규칙 엔진이 확정한 결과와 검증된 KISA 근거를 읽기 전용 AI 설명으로 결합했다.

- 공식 `PASS·FAIL·ERROR·REVIEW·N/A`의 권한은 `RULE_ENGINE`으로 고정
- 전체 상태 요약, 결과 간 관련 위험, 사용자·관리자 조치와 한계 생성
- 항목별 위험 의미, AI 권장 우선순위와 이유, 사용자·관리자 조치 생성
- `무엇을 확인했나요`, 실제 확인 요약, 기준, 자연어 판정 이유와 KISA 근거 보존
- JSON API와 SSE API에 같은 최종 Schema 적용
- SSE 단계 `VALIDATING_LINEAGE → COMPARING_RULE_RESULTS → GENERATING_EXPLANATION → COMPLETED`
- prompt·입력·모델 출력·최종 출력 canonical SHA-256과 model ID·runtime profile 기록
- 근거 부족·문서 충돌이면 모델을 호출하지 않고 공식 결과 보존
- 모델/Gateway 장애·잘못된 JSON·판정 변경 시도·실행형 출력은 안전하게 차단
- 공식 Finding과 Audit Pack 쓰기 권한은 항상 `false`

모델에는 내부 판정 이유 코드, Probe ID, Adapter ID, 기술 경로를 보내지 않는다.
OpenRouter에서는 합성·비식별 시험 데이터만 허용하며 실제 PC 전체 문맥은 보내지 않는다.

## 2. API 계약

| 경로 | 역할 |
|---|---|
| `POST /api/v1/result-explanations` | 구조화 AI 설명 JSON 반환 |
| `POST /api/v1/result-explanations/stream` | 생성 단계와 같은 최종 결과를 SSE로 반환 |

두 경로 모두 개발 기능 Gate, 인증 미들웨어와 브라우저 CSRF 검사를 통과해야 한다.
PRODUCT-AI-04에서 결과 화면이 이 계약을 사용하도록 연결한다.

## 3. 주요 산출물

- `src/security_audit/application/result_ai_explanation.py`
- `src/security_audit/llm/internal_gateway.py`
- `apps/api/result_ai_explanation.py`
- `database/schemas/result_ai_explanation.schema.json`
- `tests/unit/test_product_ai_03_result_ai_explanation.py`
- `database/verification/verify_product_ai_03.py`
- `tools/verify-product-ai-03.ps1`

재현 SHA-256:

| 파일 | SHA-256 |
|---|---|
| application service | `88BAB9F2B32A6A80E60F24B14656E22BF4AA9508D5483B1228E6F5C8165A9727` |
| internal gateway client | `C75F848588ECA3880FCBBD999926FBB5E9FDDD9B6F66E1879974B91654304408` |
| API router | `FE566A0C5FA653FA19CE2E433A41167095CCD3C9CD95BC3E403B32DF9A7ACDE6` |
| output JSON Schema | `3DB879C4E285A222447B43B1C823AAF87C08EF97642BAE46FACCCECC3AEE765D` |
| unit test | `2C53A428A5A8A6570CF45080A623BCD279A0C52703673EE4A5A20230AB4BCB5E` |
| runtime verification | `9AD92923F206F25F6D3CBD5BBB0BA8D1F7E7F08C9BF85703EB76400FB0690CD7` |

## 4. 집중 검증

| 검증 | 결과 |
|---|---|
| PRODUCT-AI-03 단위시험 | 8 PASS |
| 공식 상태 불변 | PC-01 `FAIL`, PC-02 `REVIEW` 유지 |
| 모델의 `rule_status` 출력 시도 | `SECURITY_BLOCKED` |
| 근거 부족 | 모델 호출 0, 공식 결과 보존 |
| Gateway 장애 | `MODEL_UNAVAILABLE`, 재시도 가능 상태로 분류 |
| OpenRouter 정책 | 승인된 합성·비식별 시험 외 fail-closed |
| 로컬 vLLM 정책 | 외부 전송 선언 시 fail-closed |
| 동일 모델 출력 100회 | 최종 output hash 1개 |
| JSON/SSE 최종 계약 | 동일 output hash |
| Ruff·mypy | PASS |

## 5. 실제 OpenRouter 호환성 시험

명령:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-product-ai-03.ps1
```

합성·비식별 PC-01·02 두 항목만 전송했다.

| 검증 | 결과 |
|---|---|
| provider kind | `OPENROUTER` |
| runtime profile | `VLLM_COMPATIBILITY_TEST_DOUBLE` |
| model | `openai/gpt-oss-120b` |
| 생성 상태 | `GENERATED` |
| 공식 결과 | PC-01 `FAIL`, PC-02 `REVIEW` |
| 설명 결과 | PC-01 `FAIL`, PC-02 `REVIEW` |
| citation | 2 |
| input/model/output SHA-256 | 모두 생성 |
| 공식 Finding write | 0 |
| Audit Pack write | 0 |

첫 `PRECISE` 시험은 상위 모델 응답 지연으로 제한 시간을 넘겼다. 이때도 공식 결과,
citation과 입력 hash는 보존됐으며, 재시도 가능한 Gateway 장애를
`MODEL_UNAVAILABLE`로 분류하도록 계약을 보완했다. 제품 기본 `FAST` 시험은 정상 생성됐다.

이 결과는 OpenRouter가 현재 OpenAI-compatible API 계약의 시험 대역으로 동작한다는
뜻이며, 로컬 vLLM 로딩·성능·외부 통신 차단 인수 완료를 뜻하지 않는다.

## 6. 전체 표준 Gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

- Docker Compose config: PASS
- Python: `3.14.6`
- Pytest: `526 passed`, 기존 Starlette deprecation warning 1건
- JSON Schema: 25 schemas·48 examples PASS
- Ruff: PASS
- mypy strict: 246 source files PASS

첫 전체 실행에서 새 Schema를 등록한 뒤 catalog 고정 개수가 24로 남아 1건 실패했다.
계약 기대값을 25로 동기화한 뒤 전체 Gate를 처음부터 다시 통과했다.

## 7. 배포 확인

변경된 API 서비스만 빌드하고 `--no-deps`로 교체했다. model-gateway·worker·데이터
계층 이미지는 변경하지 않았다.

| 항목 | 결과 |
|---|---|
| API image | `sec-ai-mvp/audit-api:0.1.0` |
| image ID | `sha256:a9f7697fe3ca69169f8ebecd96d8c487f8c7d1d13d9fd16a6fb2cd64acaed199` |
| container | `sec-ai-mvp-dev-api-1` |
| image/container 일치 | PASS |
| API 상태 | running·healthy |
| `/health` | PASS |
| `/ready` | PostgreSQL·Redis·AIStor·ClamAV 모두 `true` |
| OpenAPI 경로 | JSON·SSE 2개 등록 |

PostgreSQL migration과 운영 데이터는 변경하지 않았다.
