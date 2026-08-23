# PRODUCT-AI 결과 설명 token·화면 스트리밍 안정화 검증

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-07-26 |
| 범위 | PRODUCT-AI-09 후속 결함 수정 |
| 판정 | PASS |
| 다음 작업 | `IMP-055` 깨끗한 Windows 11 기준 VM 제품 회귀 |

## 1. 원인

실제 Collector 결과 18개와 KISA 근거를 한 번의 FAST 요청으로 보내면서 output token 상한이 1,200으로 고정돼 있었다. OpenRouter 연결과 HTTP 응답은 정상이었지만 `finish_reason=length`로 JSON이 중간에서 잘렸고, 구조 검증은 `MODEL_OUTPUT_CONTRACT_INVALID`로 안전하게 거부했다. 화면은 이 상태를 일반 연결 실패로 잘못 안내했다.

첫 수정 뒤에는 API와 모델 제한을 늘렸지만 Nginx Gateway의 공통 `proxy_read_timeout 15s`가 그대로 남아 있었다. 첫 검증 묶음이 15초를 넘으면 Gateway가 정상적인 SSE 응답을 중간에서 끊었고 Chrome은 `net::ERR_INCOMPLETE_CHUNKED_ENCODING`을 표시했다. OpenRouter·model-gateway 연결 문제가 아니라 Gateway가 장시간 결과 설명 stream을 일반 API 제한으로 종료한 것이 직접 원인이었다.

## 2. 변경

- FAST/PRECISE output token 상한: 8,000/16,000
- 모델 게이트웨이 timeout: 240초
- API 내부 모델 대기 timeout: 260초
- PC-01~18 결과 생성: 최대 6개씩 3개 묶음
- 각 묶음의 JSON·공식 판정·citation 계약 검증 후 `BATCH_COMPLETED` SSE 전송
- 브라우저는 `6/18`, `12/18`, `18/18` 진행과 검증된 항목 카드를 즉시 표시
- 모든 묶음 성공 시에만 최종 종합·항목·citation·계보 hash를 병합하고 PDF 입력 cache에 저장
- `finish_reason=length`는 `OUTPUT_TOKEN_LIMIT_REACHED`와 다시 시도 가능한 사용자 메시지로 분리
- raw JSON token 조각은 화면에 표시하지 않음
- 일반 API의 15초 제한은 유지하고 `/api/v1/result-explanations/` 경로만 `proxy_read_timeout 300s`, `proxy_send_timeout 30s` 적용
- 결과 설명 SSE는 Nginx `proxy_buffering off`, `proxy_cache off`, upstream `Connection ""`로 즉시 전달

## 3. 보안·정합성

- 규칙 엔진의 공식 PASS·FAIL·ERROR·REVIEW·N/A는 변경하지 않는다.
- 일부 묶음만 성공한 결과를 최종 완료나 PDF 문맥으로 저장하지 않는다.
- 각 묶음의 runtime·model·prompt·safety 계보가 다르면 병합을 거부한다.
- OpenRouter에는 기존 승인 범위인 시험 환경 비식별·정규화 결과와 검색된 KISA 근거만 전송한다.
- 로컬 vLLM은 계속 `PREPARED_NOT_ACTIVE`이며 이 수정으로 로컬 추론 완료 상태를 부여하지 않는다.

## 4. 검증 결과

- 실패 우선 회귀: 기존 구현에서 token·길이 종료·묶음 SSE·UI 순차 표시 4건 예상 실패 확인
- 집중 Pytest: 34 PASS
- JavaScript 문법: PASS
- Nginx 전용 회귀: 일반 API 15초 유지, 결과 설명 경로 300초·buffer/cache off PASS
- Gateway 실제 인증 경로:
  - 로그인·MFA·CSRF·same-origin을 거쳐 `http://gateway:8080` 호출
  - 6개 한 묶음 약 28초, HTTP 200, `BATCH_COMPLETED → COMPLETED`, 45,745 bytes
  - 18개 세 묶음 약 116초, HTTP 200, `BATCH_COMPLETED` 3회 후 `COMPLETED`, 145,726 bytes
  - `FAILED`·upstream timeout·premature close·incomplete chunk 0
- 전체 표준 Gate:
  - Pytest 566 PASS
  - JSON Schema 25 schemas·48 examples PASS
  - Ruff PASS
  - mypy strict 261 source files PASS
- OpenRouter connector: HTTP 200, `openai/gpt-oss-120b`, `finish_reason=stop`
- OpenRouter 실제 18개 비식별 설명:
  - batch count 3
  - batch size 6
  - status `GENERATED`
  - 설명 항목 18
  - 공식 판정 18
  - citation 18
  - final output SHA-256 `722f0a8a0941ab673a73b25f9ae4d1c4c7946995ef0d287b2cb05e6d1fac7a39`

## 5. Runtime

- API image/container: `sha256:93e43d7263424543fe616c18c73baf1a5232a23091775525d9d9bf25e8ed905d`
- model-gateway image/container: `sha256:989f528d0c078258466188436afd21f80ec0d17c775a6a9e6ce38b6daf372718`
- Gateway image/container: `sha256:e4ed7ab877ce0a2114b5abbed2bb5c19200db413f109f18888516c4d318e3d0e`
- 실행 중 Gateway `nginx -t`: PASS
- API·model-gateway·gateway: healthy
- `http://127.0.0.1:18480/health/ready`: HTTP 200
