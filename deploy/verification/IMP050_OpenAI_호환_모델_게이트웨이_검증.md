# IMP-050 OpenAI 호환 모델 게이트웨이 검증

| 항목 | 결과 |
|---|---|
| 상태 | **COMPLETE** |
| 검증일 | 2026-07-24 |
| 현재 공급자 | OpenRouter 원격 API |
| 현재 모델 | `openai/gpt-oss-120b` |
| 향후 기본 실행 엔진 | 로컬 vLLM |
| 현재 로컬 vLLM | 실행하지 않음 |
| 모델 gateway image | `sec-ai-mvp/model-gateway:0.1.0` |
| image digest | `sha256:b19e4a468ce18e050796dc793498b54ad69d69be1d4f01a2f6127427d379abbc` |
| 외부 공개 port | 없음 |
| 공식 Finding·Pack 변경 권한 | 없음 |

## 1. 사용자가 얻게 된 결과

현재 Sec_AI는 `renew_v4`에서 사용하던 OpenRouter 설정을 비밀값을 출력하지 않고
runtime 전용 파일로 가져와, 내부 `model-gateway` container를 통해
`openai/gpt-oss-120b`에 실제 접속한다.

```text
현재
Sec_AI API → model-gateway → OpenRouter → openai/gpt-oss-120b

향후
Sec_AI API → 같은 model-gateway → local vLLM → 승인된 local model
```

향후 로컬 전환 때 connector code와 Core API는 바꾸지 않고 다음 두 설정만
변경한다.

```text
SECAI_LLM_API_BASE=http://vllm:8000/v1
SECAI_LLM_MODEL=<승인된 vLLM served model name>
```

vLLM image·CUDA·모델 weight는 이번 image에 포함하지 않았다. GPU·driver·VRAM,
모델 hash·license와 성능 기준을 승인하기 전에는 local engine을 실행하지 않는다.

## 2. 실제 연결 결과

고정된 `NON_SENSITIVE_CONNECTIVITY_TEST`만 OpenRouter로 보냈다. KISA 원문,
PC 정보, 사용자 질문과 Finding은 보내지 않았다.

```json
{
  "accepted": true,
  "provider_kind": "OPENROUTER",
  "deployment_mode": "REMOTE_API",
  "configured_model": "openai/gpt-oss-120b",
  "resolved_model": "openai/gpt-oss-120b",
  "connection_status": "AVAILABLE",
  "response_received": true,
  "completion_http_status": 200,
  "local_model_loaded": false,
  "model_license": "Apache-2.0",
  "automatic_model_fallback_allowed": false,
  "failure_behavior": "AI_UNAVAILABLE_CORE_CONTINUES",
  "secret_values_printed": false,
  "official_finding_write_allowed": false,
  "audit_pack_write_allowed": false
}
```

실제 응답 내용과 API key·gateway token·provider 오류 원문·내부 reasoning은
검증 기록에 저장하지 않았다.

## 3. 보안 경계

- OpenRouter key는 `runtime/dev-secrets/llm_api_key` runtime 파일에만 있다.
- API container에는 OpenRouter key를 주지 않는다.
- API와 model-gateway는 별도 256-bit 내부 token으로 통신한다.
- model-gateway는 host port를 publish하지 않는다.
- 원격 endpoint는 HTTPS만 허용하고, HTTP는 loopback·사설망·Docker 내부
  host의 local vLLM에만 허용한다.
- 호출자가 model·URL·추가 provider parameter를 선택할 수 없다.
- 메시지 수·본문·출력 token·temperature를 제한한다.
- 인증 실패·사용량 제한·rate limit·timeout·모델 장애를 안전한 오류 범주로
  바꾸며 upstream 오류 본문은 버린다.
- 자동 fallback은 금지한다. 다른 비용·license·출력 특성의 모델로 몰래
  바꾸지 않는다.
- model-gateway를 실제 중단한 상태에서도 Core `/health/live`와
  `/health/ready`가 모두 정상임을 확인했고 곧바로 복구했다.

사용자 화면 `/ui/model-runtime`은 현재 원격 전송, 로컬 모델 미실행,
모델·license와 장애 격리 상태를 쉬운 한글로 표시한다. 실제 KISA 질문답변은
아직 `PREVIEW`이며 `IMP-051~053` 검증 전에는 `LIVE`로 표시하지 않는다.

## 4. 기반 image·SBOM·취약점

처음 사용한 `python:3.14.6-slim-bookworm`에는 수정 가능한 OpenSSL
Critical 1건과 High 항목이 남아 최종 image에서 제외했다.

최종 connector는 같은 CPython 3.14.6의 공식
`python:3.14.6-alpine3.23@sha256:e10f6e0f219a81c65c518e339e7e9bf2f8c63b6ba1bf112e1bb2d1e395ed0c17`
기반이며 다음을 확인했다.

- OpenSSL `3.5.7`
- non-root `10001:10001`
- read-only filesystem, `no-new-privileges`, capability 전체 제거
- 잠긴 `api.lock` 설치와 native module import 성공
- CPython 3.14 보안 commit
  `07efb08123ba9367a7107325adb9d5626dca1ca9`의 `html.parser` backport
- backport file SHA-256
  `5c5ed245889135564e75dfed9a47aeb6b4d3e5a2e9614d918a986767e3747539`

Grype raw 결과는 CPython binary version 기준 High 1·Medium 3을 표시한다.
High는 위 exact upstream backport로 실제 파일을 수정했지만 version scanner가
이를 인식하지 못한 항목이다. Medium 2건은 connector가 사용하지 않는
`imaplib`·`poplib`, 나머지 1건은 Linux container에 적용되지 않는 Windows
legacy 설치 경로다. 따라서 항목별 검토 후 조치 가능한 Critical·High는 0건이다.

| 산출물 | SHA-256 |
|---|---|
| `sec-ai-mvp-model-gateway-0.1.0.sbom.spdx.json` | `E35F622D1E17D2D01856680468BD775CED34388E56DE4435FBD54AE2A1E3E7C4` |
| `sec-ai-mvp-model-gateway-0.1.0.vulnerability.json` | `82CB2BC5A1410D2203EBB3308582EBFBEE342A22535CA073688AF40C3F66402C` |
| `sec-ai-mvp-model-gateway-0.1.0.vulnerability-triage.json` | `06D9C30034C18CAFA6E301F4E5726C3E465C8AE523F23BE23C4DF41B87F29E04` |

## 5. 검증 결과

| 검증 | 결과 |
|---|---|
| IMP-050 집중 test | 17 PASS |
| JSON Schema | 18 schemas·34 examples PASS |
| Ruff | PASS |
| mypy 집중 범위 | 9 source files PASS |
| Compose config | PASS |
| OpenRouter model 목록·생성 | PASS |
| 모델 중단 중 Core readiness | PASS |
| 실제 로그인 후 `/ui/model-runtime` | HTTP 200, 필수 안내 5/5 PASS |
| 전체 표준 검증 | 459 tests, Schema 18/34, Ruff, mypy 228 files PASS |

구현 중 PowerShell 버전 차이로 `RandomNumberGenerator.Fill`이 동작하지 않은
문제, 빈 `.env` 목록 처리, dotenv의 따옴표 포함 key를 발견했다.
`RandomNumberGenerator.Create().GetBytes()`, 명시적 list, matching quote 제거로
수정했고 key 값은 출력하지 않았다. Docker BuildKit snapshot 오류 1건은
모델 image만 재빌드해 최종 digest와 실행 container 일치를 다시 확인했다.

## 6. 공식 근거

- OpenRouter Quickstart:
  https://openrouter.ai/docs/quickstart
- OpenRouter models API:
  https://openrouter.ai/docs/api/api-reference/models/get-models
- OpenRouter 오류 처리:
  https://openrouter.ai/docs/api/reference/errors-and-debugging
- vLLM OpenAI 호환 server:
  https://docs.vllm.ai/en/latest/serving/online_serving/openai_compatible_server/
- vLLM Quickstart:
  https://docs.vllm.ai/en/latest/getting_started/quickstart/
- OpenAI gpt-oss-120b:
  https://developers.openai.com/api/docs/models/gpt-oss-120b
- OpenAI gpt-oss model card:
  https://openai.com/index/gpt-oss-model-card/
- CPython 3.14 CVE-2026-15308 backport:
  https://github.com/python/cpython/commit/07efb08123ba9367a7107325adb9d5626dca1ca9

## 7. 다음 작업

`IMP-051 — 대화 기록·중단·재시도 기능 만들기`다. Thread·Message·Citation,
streaming·stop·edit·retry·branch·history 계약을 만들되, 실제 KISA Q&A의
`LIVE` 전환은 `IMP-052~053`의 근거·보안·UI 검증 뒤에 수행한다.
