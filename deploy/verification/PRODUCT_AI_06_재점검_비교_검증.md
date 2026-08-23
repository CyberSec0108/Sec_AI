# PRODUCT-AI-06 점검 이동·재점검·변화 비교 검증 기록

| 항목 | 결과 |
|---|---|
| 작업 ID | `PRODUCT-AI-06` |
| 검증일 | 2026-07-26 |
| 상태 | **PASS — 단계 완료** |
| 현재 AI Runtime | OpenRouter를 `VLLM_COMPATIBILITY_TEST_DOUBLE`로 사용 |
| 최종 AI Runtime | `LOCAL_VLLM_FULL_CONTEXT` — `PRODUCT-AI-09` 인수 대상 |
| 공식 판정 권한 | 규칙 엔진만 보유, LLM 변경 권한 없음 |
| 이전 결과 | append-only로 보존 |
| 공식 Finding·Audit Pack write | 없음 |

## 1. 완료한 사용자 흐름

```text
결과 화면에서 처음 화면으로 복귀
→ 기존 결과가 있어도 자동으로 결과 화면에 되돌아가지 않음
→ ‘내 PC 다시 점검하기’
→ 같은 job 안에 새 result ID·새 sequence 생성
→ 이전 result snapshot 보존
→ 규칙 엔진이 개선·악화·변경 없음·남은 위험 계산
→ AI가 변경 항목의 KISA 근거로 의미와 다음 행동 설명
```

재점검 전후 상태 분류는 결정론적 규칙이 수행한다. AI는 공식 상태나 변화 분류를
바꾸지 않고 사용자가 이해하기 쉬운 설명만 만든다.

## 2. 비교 계약

- 이전·현재 result ID는 서로 달라야 한다.
- 현재 version은 이전 version보다 커야 한다.
- 두 snapshot의 Control 집합과 제목이 같아야 한다.
- 상태 위험도는 `N/A·PASS < REVIEW < ERROR < FAIL` 순서로 비교한다.
- 비교 결과는 `IMPROVED`, `WORSENED`, `UNCHANGED` 중 하나다.
- `N/A ↔ PASS`처럼 위험도 단계가 같은 상태 이동은 악화로 오표시하지 않고
  `위험도 변화 없음`으로 표시한다.
- 현재 FAIL·ERROR·REVIEW는 `남아 있는 위험`으로 별도 집계한다.
- 비교 입력·출력은 canonical SHA-256으로 고정한다.
- 원시 증적, 사용자·hostname·SID, 내부 판정 이유 코드는 AI 입력에 포함하지 않는다.
- 이전 결과 수정, Finding·Audit Pack write, 실행형 AI 출력은 금지한다.

## 3. 화면과 AI 설명

결과 화면은 재점검 이후 다음을 함께 표시한다.

- 개선·악화·변경 없음·남은 위험 개수
- Control별 이전 상태와 현재 상태
- 규칙 엔진이 결정한 변화 배지
- KISA 근거 검색과 AI 생성 진행 상태
- AI 전체 변화 요약
- 개선·악화 의미, 남은 위험, 다음 행동, 설명 한계와 KISA 출처

AI가 중단되거나 근거가 부족해도 규칙 엔진 비교는 그대로 표시한다.

## 4. 검증 결과

| 검증 | 결과 |
|---|---|
| 관리자 보정 + PRODUCT-AI-06 집중 Pytest | `15 passed` |
| PRODUCT-AI-01~06 연속 회귀 | `56 passed` |
| 변경 Python Ruff | `All checks passed` |
| 변경 Python mypy | `Success: no issues found in 5 source files` |
| `product.js`, `product-results.js` Node syntax | PASS |
| 비교 JSON·SSE 계약 | lineage 검증 → KISA 검색 → AI 변화 설명 → 완료 PASS |
| 공식 규칙 상태·이전 snapshot 불변 | PASS |
| source↔API container 핵심 파일 SHA-256 | 4/4 일치 |
| API container | `healthy` |

기존 Launcher 회귀 24건 중 23건은 통과했다. Linux 개발 도구 컨테이너에서
`allow_reuse_address=False`인 loopback 포트를 즉시 다시 여는 Windows 전용 시험 1건은
Linux `TIME_WAIT` 차이로 실패했다. 이번 변경은 해당 포트 종료 코드를 수정하지 않았고,
새 Windows EXE의 native build self-check와 공급망 Gate는 통과했다.

## 5. 배포 확인

- API image: `sec-ai-mvp/audit-api:0.1.0`
- image digest:
  `sha256:2d354c36290a92723a7c50a77b18c584a066ac3106fed951f9b7059383a79ded`
- container: `sec-ai-mvp-dev-api-1`
- 상태: `healthy`
- 새 SSE:
  `/api/v1/result-explanations/comparison/stream`
- PostgreSQL, pgvector, model-gateway, gateway의 계약은 변경하지 않음

Windows 실행 파일:

- artifact:
  `runtime/imp034-artifacts/build-20260726T041357Z/SecAI-Collector-Windows-x64.exe`
- bytes: `12,672,957`
- SHA-256:
  `c072460396fa5b8d121496b93875623d3fdca9cebe4ca48b13b0bd57f3528ae4`
- embedded resources: `99`
- dependency components: `24`
- 알려진 의존성 취약점: `0`
- ClamAV: `CLEAN`
- Microsoft Defender: `CLEAN`
- release: `DEV-UNSIGNED`, 운영 배포 아님
- 이동 묶음: 생성하지 않음

## 6. 다음 Gate

다음 작업은 `PRODUCT-AI-07 — 최근 대화 통합·관리`다.

- 별도 상단 `대화 기록` 탭 제거
- 현재 KISA 질문 화면의 최근 대화 패널에 기능 통합
- 이름 변경, 삭제 취소, 보관, 이동, 고정, 검색
- 소유자·조직 범위, tombstone, 감사 이력과 미동작 버튼 0 검증

`PRODUCT-AI-09`의 실제 로컬 vLLM·외부 egress 0 최종 인수와 `IMP-055` 이후
깨끗한 Windows 11 VM·조직 서명·SmartScreen·Pilot 검증은 아직 남아 있다.
