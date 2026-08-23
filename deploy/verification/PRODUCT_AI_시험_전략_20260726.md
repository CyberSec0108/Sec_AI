# PRODUCT-AI 단계별 검증 실행 방식

| 항목 | 결정 |
|---|---|
| 결정일 | 2026-07-26 |
| 적용 범위 | `PRODUCT-AI-04~09` |
| 목적 | 단계마다 전체 Gate와 Docker 재빌드를 반복하는 시간을 줄이면서 결함 누적을 방지 |
| 전체 Gate 실행 시점 | `PRODUCT-AI-09` 최종 제품 인수 |

## 1. 기본 방식

`PRODUCT-AI-04~08`에서는 다음 작업만 수행한다.

1. 변경 기능과 직접 관련된 소규모 Pytest
2. 변경한 계약·Schema 예시의 집중 검증
3. 필요한 수동 정적 확인
4. 단계별 검증 기록과 `구현_현황.md` 갱신

전체 Pytest, 전체 Ruff, 전체 mypy, 전체 Schema 검증과 Docker 서비스 이미지 재빌드는
매 단계에서 반복하지 않는다.

## 2. PRODUCT-AI-09 최종 검증

`PRODUCT-AI-09`에서 다음을 한 번에 수행한다.

```text
Docker Compose config
→ 전체 unit·contract Pytest
→ 전체 JSON Schema example
→ 전체 Ruff
→ 전체 mypy strict
→ 변경 서비스 이미지 재빌드
→ image/container 일치
→ Core Status·Health
→ 실제 화면·SSE·PDF·현재 OpenRouter 사용자 과업과 GPU vLLM 준비 상태
```

## 3. 즉시 확대 검증하는 예외

다음 변경은 `PRODUCT-AI-04~08`이라도 해당 단계에서 필요한 Ruff·mypy·통합시험 또는
서비스 재빌드를 수행한다.

- 외부 API 요청·응답 계약 또는 SSE wire format
- DB Schema·신규 migration·append-only·멱등성
- 인증·권한·CSRF·IDOR·감사
- 공식 판정·Finding·Audit Pack 불변성
- 개인정보·원문·실제 PC 결과의 외부 AI 전송 경계
- Docker·환경 변수·네트워크·secret
- 실제 컨테이너에서만 재현되는 장애

예외 검증은 위험 영역과 변경 서비스로 제한한다. 예외가 발생해도 전체 Gate를 기계적으로
반복하지 않고, 최종 전체 Gate는 PRODUCT-AI-09에서 다시 수행한다.

## 4. 완료 표시 기준

- `PRODUCT-AI-04~08`: 해당 단계의 집중 Gate가 통과하면 `[x]`로 표시할 수 있다.
- 실행하지 않은 전체 Gate와 Docker 재빌드는 `PRODUCT-AI-09로 이관`이라고 기록한다.
- 집중시험을 생략하거나 실패한 단계는 완료 표시하지 않는다.
- PRODUCT-AI-09 전체 Gate가 실패하면 제품 완료와 `IMP-055` 진입을 금지한다.
