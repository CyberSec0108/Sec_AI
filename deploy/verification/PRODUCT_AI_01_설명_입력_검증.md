# PRODUCT-AI-01 점검 결과 설명 입력 계약 검증

| 항목 | 결과 |
|---|---|
| 작업일 | 2026-07-25 |
| 구현 상태 | 완료 |
| 완료 체크 | `[x]` — 기존 IMP-040 `mypy` 오류 수정 후 전체 표준 Gate PASS |
| 다음 단계 | `PRODUCT-AI-02` 결과별 KISA 페이지·문단 검색 |

## 1. 구현 범위

PC-01~18 규칙 결과를 AI 설명 계층에 전달하기 전에 다음 값을 하나의 비식별 DTO로 고정했다.

- 실제 확인 내용과 정규화된 사실
- 확인 방법, 실행 도구, 비밀값을 제거한 확인 위치
- 규칙 엔진이 정한 불변 상태와 사용자용 자연어 판정 이유
- 개발자·관리자용 내부 이유 코드와 `TECHNICAL_ONLY` 노출 정책
- 수집 제한, 허용 조치, KISA 페이지·절 인용
- 원본 규칙 결과 hash와 explanation input canonical SHA-256

LLM은 판정 상태를 쓰거나 바꿀 수 없고 `official_finding_write_allowed=false`로 고정된다. 사용자용 projection에서는 `result_code`, `probe_id`, `adapter_id`를 제거한다.

## 2. 산출물

- `collectors/one_shot/contracts/product_ai_01_explanation_sources.json`
- `src/security_audit/application/result_explanation_input.py`
- `database/schemas/finding_explanation_input.schema.json`
- `database/schemas/examples/valid/finding_explanation_input.json`
- `database/schemas/examples/invalid/finding_explanation_input.json`
- `database/schemas/schema-catalog.json`
- `database/schemas/examples/index.json`
- `tests/unit/test_product_ai_01_explanation_input.py`
- `tests/contract/test_schema_catalog.py`

주요 재현 hash:

| 파일 | SHA-256 |
|---|---|
| source contract | `E725ADD2A86C2B3CBDE3FD7D5870EAFCEC100D1EB93917CD84EE0ECEBE4F9921` |
| JSON Schema | `E54396292BB855600267F20B451F16C048F0AF5E9F1B8BE68FA57DE1D3435F46` |
| DTO builder | `588BD960A4875276E138A646F6F8F4E02F0B12C9D1062ED06182ADEFE36DFF06` |
| unit test | `4374077DD46A6DC4CD81B01EFC980E40B37FE35CD5FD46B407638A60D43BDCE3` |

## 3. 검증 결과

### 집중 검증

- PRODUCT-AI-01 단위시험: `16 passed`
- JSON Schema catalog: 23 schemas·44 examples PASS
- Ruff 대상 파일: PASS
- mypy 대상 모듈·시험: PASS
- 동일 입력 100회: explanation input hash 1개
- PC-01~18 및 source probe exact coverage: PASS
- 판정·입력 객체 불변성: PASS
- 민감정보 필드 거부와 사용자 projection 내부 코드 제거: PASS

### 전체 표준 검증 1회

명령:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

결과:

- Docker Compose config: PASS
- Python: `3.14.6`
- Pytest: `512 passed`, 기존 Starlette deprecation warning 1건
- JSON Schema: 23 schemas·44 examples PASS
- Ruff: PASS
- mypy strict: FAIL 1건

첫 실행 실패 위치:

```text
tests/unit/test_imp040_product_launcher.py:297
"set" of "Event" does not return a value (it only ever returns None) [func-returns-value]
```

실패 코드는 기존 IMP-040 시험의 `browser_opener=lambda _: first_opened.set() or True`였다. 사용자 승인 후 반환형이 명확한 `open_first_launcher()` 함수로 최소 수정했다.

수정 후 전체 표준 Gate 재실행:

- Pytest: `512 passed`, 기존 Starlette deprecation warning 1건
- JSON Schema: 23 schemas·44 examples PASS
- Ruff: PASS
- mypy strict: 240 source files PASS

## 4. 배포·실행 확인

변경 서비스인 API만 빌드하고 `--no-deps`로 교체했다.

| 항목 | 결과 |
|---|---|
| image | `sec-ai-mvp/audit-api:0.1.0` |
| image ID | `sha256:64c9f650f5d325b308d716e9e3a24f1125f18bf0595fd2537805aa7ca6dec061` |
| container | `sec-ai-mvp-dev-api-1` |
| container image ID | 위 image ID와 일치 |
| 상태 | running·healthy |
| API `/health` | PASS |
| API `/ready` | PostgreSQL·Redis·AIStor·ClamAV 모두 `true` |
| runtime import | PASS |

PostgreSQL migration, 운영 데이터, 공식 Finding은 변경하지 않았다. Gateway·worker·model-gateway·데이터 계층 이미지는 다시 빌드하지 않았다.

## 5. 완료 판단

기존 오류 수정과 전체 Gate 재검증이 끝났으므로 `PRODUCT-AI-01`을 `[x]`로 완료 처리한다. 다음 작업은 `PRODUCT-AI-02`다.
