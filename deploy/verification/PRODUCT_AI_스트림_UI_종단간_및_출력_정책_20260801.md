# 점검 결과 AI 실제 UI E2E·출력 정책 보완 검증

> 후속 상태: 이 문서에서 남긴 plain text Markdown 가독성 Gap은 2026-08-02 `MARKDOWN-01~03`에서 해결했다. 제한형 AST renderer·sanitizer·XSS/접근성 Gate는 [`MARKDOWN_01_03_제한형_렌더러_검증_20260802.md`](MARKDOWN_01_03_제한형_렌더러_검증_20260802.md)를 따른다. 아래 내용은 2026-08-01 당시의 검증 이력이다.

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-08-01 |
| 범위 | DEV-LOCAL 로그인·두 번째 인증→별도 AI 분석 화면→PC-01~18 token stream→AI 종합 설명 |
| 판정 | 현재 개발 환경 PASS |
| 제외 | clean Windows VM, 운영 코드서명, 실제 로컬 vLLM, 운영 개인정보 전송 승인 |

## 1. 문제

별도 `/ui/ai-analysis` 화면에서 OpenRouter 요청 활동은 보였지만 화면은 `0 / 18`에 머물고 `AI 설명 입력 또는 출력 안전 계약을 확인하지 못했습니다.`라고 표시했다.

원인은 모델 연결 실패가 아니라 일부 KISA 검색 결과의 상태와 문자열 기반 출력 검사 실패를 하나의 일반 오류 문구로 합쳐 표시한 것이었다. 검색 위치가 부족한 항목도 모델 호출 전체를 거부했고, 실제로는 답변이 가능한 입력까지 같은 메시지로 차단했다.

## 2. 변경

### 2.1 서버

- PC-01~18 coverage, Control 순서, canonical explanation input, 공식 상태, citation 구조와 prompt injection 입력 검증은 유지했다.
- KISA paragraph가 비어 있는 항목은 근거를 추정하지 않고 `근거 위치를 추가로 확인해야 함`으로 설명한다.
- 문자열 패턴 기반 모델 출력 차단·재시도·fallback 분기를 제거했다.
- OpenRouter upstream `content_delta`를 API가 새로 조합한 문장으로 대체하지 않고 즉시 SSE로 전달한다.
- 규칙 엔진 공식 상태와 상세 결과는 모델 stream과 계속 분리한다.

### 2.2 브라우저

- `CONTROL_DELTA`와 `SUMMARY_DELTA`를 같은 화면의 `textContent`에 즉시 누적한다.
- `textContent` safe sink를 사용하므로 모델 Markdown/HTML을 실행하지 않는다.
- KISA page를 확인할 수 없는 경우 citation을 꾸며내지 않는다.
- 재시도·fallback 전용 event handler를 제거했다.

현재 Markdown 강조 문법이 plain text로 보이는 가독성 Gap은 별도 발전 계획의 `MARKDOWN-01~03`에서 제한형 parser·sanitizer로 해결한다.

## 3. 집중 검증

변경 범위 집중 검증 결과:

- `tests/unit/test_product_ai_token_stream.py`: 3 PASS
- 변경 Python 파일 Ruff: PASS
- Python syntax: PASS
- `apps/web/static/app/result-ai-analysis.js` JavaScript syntax: PASS
- 이전 오류 문구 source 잔존: 0

전체 Gate는 `IMP-055` clean VM 제품 회귀에서 다시 실행한다.

## 4. 실제 Chrome UI E2E

API/CLI 응답을 성공 판정으로 사용하지 않고 실제 hidden Chrome과 DevTools Protocol로 다음 사용자 흐름을 수행했다.

1. `http://localhost:18480/auth/login?next=/ui/ai-analysis` 이동
2. `local-owner` 사용자 이름과 보호 파일의 개발 비밀번호를 로그인 form에 입력
3. `/auth/mfa`에서 보호 파일의 갱신된 인증 코드 입력
4. 로그인 session을 유지한 채 `/ui/ai-analysis` 이동
5. 비식별 18개 시험 결과를 브라우저 session storage에 넣고 화면 reload
6. PC-01의 첫 80자 이상 token이 같은 화면에 나타나는 순간 캡처
7. PC-01 완료 후 PC-02가 시작되는 상태 확인
8. 브라우저를 유지해 PC-18까지 순차 완료 확인
9. AI 종합 설명 `SUMMARY_COMPLETED`와 최종 `ANALYSIS_COMPLETED` 확인

최종 UI 상태:

```text
status: 18개 항목과 전체 종합 설명을 완료했습니다.
count: 18 / 18
completed_controls: 18
```

소요 시간은 약 254초였다. 실제 사용자·PC 식별정보와 원본 증적은 시험 입력에 포함하지 않았다.

## 5. 캡처 Evidence

| 파일 | SHA-256 | 확인 내용 |
|---|---|---|
| `runtime/verification/ai-stream-live-20260801.png` | `24856AC64EA6E5A2499A73A2F7B8F9492A762982D9E20F521EF192BAF321C166` | PC-01 설명 token이 같은 화면에 생성 중 표시 |
| `runtime/verification/ai-stream-all-complete-20260801.png` | `2FEA03DC39EE104E227D7645FAAA022DD6956B38E02CA766A482F26BAB57F475` | PC-18 완료와 AI 종합 설명 표시 |

캡처는 실제 시험 화면이며 운영 증적이나 공식 Finding이 아니다.

## 6. 배포 정합성

| 항목 | 값 |
|---|---|
| container | `sec-ai-mvp-dev-api-1` |
| image tag | `sec-ai-mvp/audit-api:0.1.0` |
| image ID | `sha256:2c3712bbddc56443abf2bbe3c7e427de33daf7da01732531977e73c416df7b11` |
| container image ID | `sha256:2c3712bbddc56443abf2bbe3c7e427de33daf7da01732531977e73c416df7b11` |
| 상태 | healthy, image/container 일치 |

## 7. 남은 위험

- Markdown `**`가 현재 그대로 보인다. raw HTML 삽입이 아닌 제한형 Markdown과 XSS 회귀가 필요하다.
- 현재 token prompt는 KISA·실제 확인값 중심이다. 모델 일반 지식의 적극 활용은 source class와 표시 계약을 추가한 뒤 활성화해야 한다.
- 전용 문자열 출력 차단은 제거됐으므로 Markdown renderer를 추가할 때 sanitizer·CSP·Trusted Types·공격 corpus Gate가 필수다.
- OpenRouter는 시험 대역이다. 최종 제품은 로컬 vLLM과 외부 egress 0을 별도 인수해야 한다.
- 이 시험은 비식별 UI 흐름 시험이며 clean Windows Collector→실제 결과 전체 제품 회귀를 대신하지 않는다.

## 8. 결론

현재 개발 환경에서 로그인·인증을 포함한 실제 UI의 PC-01~18 순차 token stream과 마지막 AI 종합 설명이 완료됐다. 기존 오류 문구를 제거했지만 공식 판정·입력 검증·prompt injection 차단·write 권한 금지와 plain text safe sink는 유지했다. 다음 제품 회귀는 `IMP-055`, 표시 개선은 `MARKDOWN-01~03`이다.
