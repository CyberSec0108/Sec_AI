# IMP-052 KISA Q&A·점검 결과 쉬운 설명 검증

| 항목 | 결과 |
|---|---|
| 상태 | **COMPLETE** |
| 검증일 | 2026-07-25 |
| 다음 작업 | `IMP-053` 실제 KISA 질문답변 챗 화면 열기 |
| 실제 챗 화면 | `PREVIEW` 유지 |
| API image | `sec-ai-mvp/audit-api:0.1.0` |
| image·container digest | `sha256:26e13e68299d980e02cf47ad16626f1687f77844444ca0e8bc07e1b642963fad` 일치 |
| 공식 Finding·Audit Pack 변경 | 0건 |

## 1. 완료한 기능

두 가지 읽기 전용 AI 모드를 하나의 안전 경계로 구현했다.

- `GUIDE_QA`: 승인된 KISA Guide 범위에서 질문 근거를 찾고 쉬운 한국어로 설명
- `FINDING_EXPLAIN`: 공식 점검 상태를 그대로 두고 이유·기준을 쉽게 설명

처리 순서는 다음과 같다.

```text
사용자 질문 또는 공식 Finding snapshot
→ 로컬 ApprovedLocalKoreanEmbedder
→ PostgreSQL 18.4 + pgvector 0.8.2 범위 제한 검색
→ page·section·paragraph·chunk hash 계보 확인
→ prompt injection·외부 전송 승인 Gate
→ OpenAI 호환 Completion 계약
→ 실행형 출력 차단
→ canonical input/output hash와 읽기 전용 결과
```

`grounded_ai_response.schema.json`을 추가해 모드·상태·인용·모델·prompt·
input/output hash와 공식 write 금지를 구조적으로 고정했다.

## 2. 실제 PostgreSQL+pgvector 검증

`database/verification/verify_imp052.py`를 재빌드한 API image에서 runtime
계정으로 실행했다. 네트워크 모델 대신 같은 Completion 계약을 구현한 로컬
결정론적 모델 대역을 사용했으며 transaction 종료 후 검증 자료를 남기지 않았다.

| 검증 | 결과 |
|---|---|
| PC-01~18 대표 질문 | 18/18 `GENERATED` |
| 정확한 Control·페이지·절·문단 인용 | 18/18 |
| 범위 밖 질문 | 4/4 `NO_EVIDENCE` |
| 근거 없음에서 모델 호출 | 0회 |
| 점검 결과 쉬운 설명 | 생성 PASS |
| prompt injection | 모델 호출 전 차단 |
| 미승인 OpenRouter 자료 전송 | 모델 호출 전 차단 |
| 모델 장애 | `MODEL_UNAVAILABLE`, Core 정본 유지 |
| DB Finding inventory | 전후 hash 일치 |
| Audit Pack 파일 | 전후 byte 일치 |
| Finding 문서 | 전후 canonical hash 일치 |

재실행:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp052-grounded-ai.ps1
```

## 3. 보안·판정 경계

- 질문과 검색 chunk는 system instruction이 아닌 불신 데이터 envelope에 넣는다.
- 명시적인 지침 무시·Finding 변경·Pack 활성화 요청은 생성 전에 차단한다.
- PowerShell·shell 코드 fence, 설정 변경 명령과 script 출력은 사용자에게 반환하지 않는다.
- 모델 입력에는 선택된 질문·Guide excerpt·exact citation과 필요한 비식별 Finding 필드만 포함한다.
- password·token·secret·credential 같은 금지 필드가 Finding에 있으면 모델 호출 전에 거부한다.
- 모델 출력에는 공식 Finding write와 Audit Pack write 권한이 항상 `false`다.
- 모델 장애는 AI 설명만 실패시키며 PC 점검·Finding·Pack을 변경하지 않는다.

현재 사용자가 승인한 범위는 KISA 원문의 내부 검색과 파생 text·chunk·embedding
저장이다. 따라서 OpenRouter 연결 자체는 유지하지만 KISA excerpt·사용자 질문의
외부 전송은 별도 승인 전까지 fail-closed다. 이번 검증에서 실제 KISA 원문,
사용자 질문 또는 Finding을 OpenRouter로 보내지 않았다.

## 4. 전체 검증

```text
Docker Compose config: PASS
Python: 3.14.6
Pytest: 479 passed
Known warning: Starlette TestClient deprecation 1건
Schema: 22 schemas / 42 examples PASS
Ruff: PASS
mypy strict: 235 source files PASS
Gateway /health/live: HTTP 200
Gateway /health/ready: HTTP 200
Core: 10개 healthy
pgAdmin: 127.0.0.1:18490 loopback 관리 profile 실행
```

## 5. 다음 단계

`IMP-053`에서 검증된 대화·검색·답변·출처 계약을 실제 입력창과 대화 기록
화면에 연결한다. 외부 전송 승인이 없으면 원격 생성은 계속 차단하고, 승인된
전송 정책 또는 local vLLM이 준비된 범위만 `LIVE`로 전환한다. 운영 OIDC,
공식 Pack 변경, 원문 재배포와 이동 묶음은 이번 단계 범위가 아니다.
