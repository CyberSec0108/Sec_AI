# PRODUCT-AI-09 현재 환경 최종 제품 인수 검증

## 1. 결론

`PRODUCT-AI-09`의 현재 환경 범위는 PASS다.

- 실제 AI 설명 Runtime은 OpenRouter `openai/gpt-oss-120b`다.
- OpenRouter에는 승인된 시험 환경의 비식별·정규화 결과와 검색된 KISA 근거만 전달한다.
- GPU vLLM image와 자동 시작되지 않는 container만 준비했다.
- 로컬 모델 weight는 없고 vLLM 추론은 실행하지 않았다.
- GPU vLLM 취약점 Gate는 실패했으므로 실제 로컬 전환은 차단한다.
- CPU vLLM image는 만들지 않았다.

이 완료는 현재 OpenRouter 시험 환경의 제품 인수이며
`LOCAL_VLLM_FULL_CONTEXT`, 외부 egress 0, 깨끗한 Windows VM, 조직 서명,
SmartScreen 또는 Pilot 인수가 아니다.

## 2. 사용자 제품 계약

- theme 전환은 글자 대신 해·달 icon과 접근성 이름을 사용한다.
- 최근 대화와 답변 출처 panel은 icon control, tooltip과 `aria-label`을 사용한다.
- 답변 SSE 완료 상태와 결과 AI SSE reader 계약을 유지한다.
- 사용자용·기술 검증용 PDF 다운로드 계약을 유지한다.
- UI와 PDF 기술 명세에서 OpenRouter 외부 전송, GPU vLLM
  `PREPARED_NOT_ACTIVE`, 모델 미적재와 추론 미실행을 구분한다.
- 공식 PASS·FAIL·ERROR·REVIEW 판정은 규칙 엔진만 결정하고 AI는 설명·권장만 한다.

## 3. GPU vLLM 준비 자산

| 항목 | 확인 결과 |
|---|---|
| project image | `sec-ai-mvp/vllm-openai-gpu:0.23.0` |
| project image digest | `sha256:48f9f370497eee3748a693c01030c82dbcee87a0db52f5e7901c9744787f4a00` |
| upstream | `vllm/vllm-openai:v0.23.0` |
| upstream `linux/amd64` digest | `sha256:3a1e7f5904e1a1192a02aa0086ceaffc33985d7044c7bb25b3a43d61bdbe3ac0` |
| upstream revision | `91df0fad4dc98a67c7659d9dbd915245d5c43d96` |
| container | `sec-ai-mvp-dev-vllm-1` |
| container 상태 | `Created`, `Running=false` |
| GPU 요청 | `Count=-1`, capability `gpu` |
| network | internal `sec-ai-mvp-model`만 사용 |
| host port | 없음 |
| root filesystem | read-only |
| model volume | `/models` read-only |
| model 경로 | `/models/NOT_CONFIGURED` fail-closed |
| model weight | 없음 |

## 4. 공급망·보안 Gate

CycloneDX SBOM:

- `deploy/verification/vllm/sec-ai-mvp-vllm-openai-gpu-0.23.0.sbom.cdx.json`
- SHA-256 `0b6048abfbdc8c053437ab34d2864995a9c88d482c625211dbf53c52828bf247`

Grype `--only-fixed` 결과:

- `deploy/verification/vllm/sec-ai-mvp-vllm-openai-gpu-0.23.0.vulnerability.json`
- SHA-256 `d78c3126769d2f3a9d9594899b8339dcfbd22ac8f5f282400c5ee95e31e63b06`
- Critical 13
- High 181
- Medium 317
- Low 81
- Negligible 2

판정은 `FAIL-RUNTIME-USE-BLOCKED`다. image·container 준비 자체는 완료했지만,
취약점이 해소된 exact image로 다시 고정하기 전에는 시작하지 않는다.

모델 weight가 없으므로 weight hash·출처·license·악성 파일 검사는 이번 실행 대상이
없다. 승인 모델 반입 시 `LOCAL-VLLM-RUNTIME-GATE`에서 수행한다.

## 5. 검증 결과

집중시험:

- PRODUCT-AI-09·08·IMP-054·053·050 관련 38 PASS
- Ruff 집중검사 PASS
- mypy 집중검사 PASS
- `theme.js`, `guide-chat.js` Node 구문검사 PASS

전체 표준 Gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

- Pytest `562 passed`, Starlette deprecation warning 1건
- Schema `25 schemas and 48 examples validated`
- Ruff `All checks passed`
- mypy strict `261 source files`, error 0

재빌드 후 로그인 기반 실제 HTTP 사용자 흐름:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-imp054-beginner-usability.ps1
```

- 초보 사용자 경로 PASS
- 접이식 대화·출처 panel PASS
- 종료 event 즉시 갱신 PASS
- 구조화 답변·생성 indicator PASS
- keyboard·focus·반응형·theme PASS
- 검증 write 0

전체 Gate 과정에서 이전 단계의 오래된 허용 table·통합된 대화 기록 menu 기대값과
테스트 package 경계가 발견됐다. 최신 PRODUCT-AI-07/08 계약으로 회귀시험을
동기화하고 `tests`를 명시적 package로 고정한 뒤 전체 Gate를 다시 통과했다.

## 6. 재빌드·실행 확인

- API image `sha256:e43801689f9b21de5e4b3dad84494ffea476bb68bafe9f78e8c7d0f06c524c5b`
- API container image 일치, `healthy`
- Core `/health/live` `ok`
- Core `/health/ready` `ready`, PostgreSQL·Redis·AIStor·ClamAV 모두 true
- model-gateway image `sha256:b19e4a468ce18e050796dc793498b54ad69d69be1d4f01a2f6127427d379abbc`
- model-gateway `healthy`, host port 없음
- 실제 안전 공개 설정: `https://openrouter.ai/api/v1`,
  `openai/gpt-oss-120b`
- GPU vLLM container는 재배포 과정에서도 시작하지 않고 `Created` 유지

## 7. 다음 단계

다음 실행 작업은 `IMP-055` 깨끗한 Windows 11 기준 VM 제품 회귀다.

로컬 vLLM을 실제 사용하려면 별도로 다음을 모두 통과해야 한다.

1. Critical·High 수정 가능한 취약점이 해소된 exact GPU image 재고정
2. 승인 GPU·driver·CUDA 호환표
3. 승인 모델 weight 출처·license·hash·악성 파일 검사
4. 로컬 endpoint 실제 결과 설명·후속 질문·PDF 검증
5. 외부 egress 0과 성능·동시성·timeout 검증
