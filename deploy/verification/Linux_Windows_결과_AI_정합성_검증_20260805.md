# Linux·Windows 결과/AI 정합성 검증 (2026-08-05)

## 1. 목적과 판단 기준

- 대화에 첨부된 화면과 13개 요구사항을 현재 제품 코드에 반영한다.
- 상태 문서는 전체 파악용 참고자료로만 사용하고, 현재 코드·시험·실행 서비스 동작을 우선한다.
- Linux와 Windows의 공식 DRAFT 판정은 규칙 코드만 유지한다. AI는 판정을 만들거나 바꾸지 않는다.
- 수집 오류·해석 불능을 임의 PASS로 바꾸지 않는다. Linux의 기존 `REVIEW` 저장값은 사용자 화면에서 별도 `기준 확인 필요` 분류로 노출하지 않고 `확인 필요`에 포함한다.

## 2. 요구사항별 반영 결과

| 번호 | 반영 결과 |
|---|---|
| 1 | Linux 시작 화면 하단을 Windows와 같은 67개 항목 진행 목록·현재 확인 항목·완료/진행/대기 요약으로 변경했다. |
| 2 | Linux 결과 카드를 Windows와 같은 4개 필드(확인 항목·실제값·KISA 기준·판정 이유)와 AI 설명·출처 순서로 통일했다. 별도 다음 행동·용어·기술 정보 접이식 영역은 카드에서 제거하고 결과만/AI만/통합 보기와 추가 질문 경로는 유지했다. |
| 3 | 양호·취약·확인 필요 배지의 크기·굵기·색을 Windows 통합 결과 CSS와 동일하게 사용했다. |
| 4 | 모델이 `[1] 설명`처럼 반환해도 제한형 Markdown 렌더링 직전에 `설명.[1]` 형태로 옮긴다. Windows·Linux와 별도/통합 화면에 동일 적용했다. |
| 5 | AI 표시 출처에서 규칙 엔진을 제외했다. 공식 판정은 결과 사실로만 유지하며 AI 입력에서는 `rule_status`, `status_authority`, `judgement_explanation`을 제거했다. |
| 6 | SSH·PAM·SUID·SGID·UMASK·sudoers처럼 필요한 용어는 별도 카드 영역을 만들지 않고 AI 설명 안에서만 짧게 풀이하도록 했다. |
| 7 | Windows·Linux AI 출처를 `[1] 실제 확인값`, `[2] KISA 근거`, `[3] AI 일반 보안지식`으로 통일했다. PDF의 AI 출처도 같은 순서로 변경했다. |
| 8 | 항목·종합·전체 완료, 취소, 실패 경로에서 `ai-stream-caret`를 제거한다. 완료 뒤 커서가 남지 않는다. |
| 9 | 항목 설명을 `1. 왜 중요한가요?`, `2. 내 PC/이 서버 결과의 의미`, `3. 다음에 할 일`, `4. 용어 간단 설명`으로 구성했다. 모델이 번호를 누락해도 화면 변환에서 번호를 복원한다. |
| 10 | Windows와 Linux 모두 실제 확인값·KISA 근거·AI 일반 보안지식을 분리한 입력/출처 계약을 사용한다. |
| 11 | 위험 원리·다른 설정과의 관계·안전한 조치 순서·변경 전 주의·재점검을 포함하도록 항목별 출력 한도와 프롬프트를 보강했다. |
| 12 | Linux에 KISA·SecAI 안전 기본값을 자동 적용하고 수치·승인 계정·허용 포트·SUID 경로를 화면에서 수정/초기화/로컬 보관할 수 있게 했다. 입력은 구조화 값만 허용하고 명령형 문자열은 거부한다. |
| 13 | 결과 요약, 상태 표현, 통합 카드, 제한형 Markdown, 출처 패널, PDF 용어를 Windows 흐름과 교차 점검했다. |

## 3. 안전 경계

- 기준 편집은 숫자·계정명·포트·절대 경로 allowlist만 받는다. raw command·정규식·스크립트·SQL 입력은 받지 않는다.
- 적용 기준값과 SHA-256을 결과 snapshot에 포함해 실행 시점 기준을 보존한다.
- 사용자 기준은 KISA 공식 결과를 덮어쓰지 않고 Linux `2026-DRAFT` 개발 판정에만 사용한다.
- `ERROR`와 해석 불능 상태는 양호로 승격하지 않는다. 별도 사용자 분류만 `확인 필요`로 통합했다.
- 제한형 Markdown AST·허용 출처 번호·plain text fail-safe 계약을 유지했다.

## 4. 검증 결과

### 통과

- 집중 Pytest: `73 passed`, Starlette deprecation warning 1건
- 변경 Python Ruff: `All checks passed`
- 변경 Python mypy strict: `Success: no issues found in 14 source files`
- JavaScript syntax: `linux-scan.js`, `linux-results.js`, `linux-ai.js`, `result-ai-analysis.js`, `product-results-integrated.js`, `restricted-markdown.js` 모두 PASS
- 제한형 Markdown Node 계약: AST allowlist·XSS·링크·출처·길이 제한 `PASS`
- API 실행 소스 확인: Linux 통합 카드·문장 뒤 출처 변환·커서 정리·`secai.result-knowledge.v2` 반영 확인
- Core Health: API `ok`, PostgreSQL·Redis·AIStor·ClamAV 의존성 `ready`, Gateway/API container `healthy`

### 전체 Gate에서 확인한 작업 범위 밖 불일치

- 전체 Pytest: `692 collected`, `679 passed`, `13 failed`. 이번 변경 영향이었던 제한형 Markdown 호출 계약 1건은 수정 후 집중시험에서 통과했다. 나머지 12건은 기존 UI 문구 기대값, DB table/Schema 개수 기대값, 시험용 secret 미제공, `test_imp052_grounded_ai.py`의 정의되지 않은 지역변수 등 현재 작업 파일 밖 불일치다.
- JSON Schema: `valid/finding_explanation_input.json`의 `evidence_trace` 누락으로 기존 1건 실패.
- 전체 Ruff: 현재 작업 밖 import 정렬 4건과 `test_imp052_grounded_ai.py` 정의되지 않은 이름 5건으로 실패. 변경 파일 집중 Ruff는 통과했다.
- 전체 mypy: 현재 작업 밖 3개 파일의 8건으로 실패. 변경 파일 집중 mypy는 통과했다.

위 불일치는 사용자 요청 범위를 넘겨 임의 수정하지 않았다.

## 5. 남은 실제 환경 확인

- Ubuntu/Rocky snapshot을 실제로 다시 실행해 67개 진행 표시, 사용자 수정 기준 snapshot, 결과 통합 카드와 OpenRouter 67개 생성 완료 후 커서 제거를 브라우저에서 최종 확인해야 한다.
- 이 확인은 기존 계획의 Linux 정상/취약 snapshot 반복 재현성 Gate와 함께 수행한다.

## 6. Linux 점검 시작 오류 Hotfix

- 증상: 점검 시작 직후 `0 / 67`에서 `LINUX_DISTRIBUTION_MISMATCH`로 종료됐다.
- 실제 확인: `192.168.110.146`은 Ubuntu 24.04.4, `192.168.110.148`은 Rocky Linux 9.8로 대상 매핑과 일치했다.
- 원인: `/etc/os-release` 수집값이 일시적으로 없을 때도 실제 배포판 불일치와 같은 오류 코드로 처리했다.
- 수정: 사전 수집을 최대 2회 재시도하고, 수집 실패·미지원 배포판·실제 불일치를 서로 다른 오류로 분리했다. Enum 비교도 identity 대신 값 비교를 사용한다.
- UI: 재시도 중인 상태를 표시하고, 실패·취소 뒤 입력과 시작 버튼 및 67개 진행 상태를 복구해 새로고침 없이 다시 실행할 수 있게 했다.
- 회귀검증: Linux 관련 Pytest `26 passed`, Ruff PASS, mypy 4파일 PASS, `linux-scan.js` syntax PASS.
- 실제 사전 확인: Ubuntu `UBUNTU_24_04 {}`, Rocky `ROCKY_9 {}`로 양쪽 모두 수집 실패 없이 통과했다.
- Runtime: API·Gateway healthy, PostgreSQL·Redis·AIStor·ClamAV ready.

## 7. 현재 Markdown 문서 동기화

사용자 지시에 따라 Markdown을 현재 상태의 절대 정본으로 가정하지 않고 코드·시험·
Runtime 동작과 대조했다. 과거 ADR과 당시 verification 기록은 승인·이력 보존을 위해
수정하지 않고, 현재 상태를 설명하는 다음 문서를 갱신했다.

- `AGENTS.md`, `README.md`, `구현_현황.md`
- `docs/README.md`, `docs/guides/README.md`
- `docs/guides/KISA_2026_UNIX_Linux_점검_안내.md`
- `docs/guides/사용자_정의_점검기준_안내.md`
- `docs/guides/초보자_사용_안내.md`
- `docs/guides/웹_UI_문구_수정_및_반영_안내.md`
- `docs/plans/README.md`
- `docs/plans/IMP062_이후_제품_확장_체크리스트.md`
- `docs/plans/플랫폼_확장_및_보조_조치_계획.md`
- `guides/README.md`, `audit_packs/kisa_2026_unix/README.md`

동기화 내용:

- Linux가 향후 계획이라는 오래된 문구를 Ubuntu/Rocky 개발 구현·남은 운영 Gate로 분리
- `REVIEW` 내부 상태 보존과 사용자 `확인 필요` 통합 표현 구분
- Linux 안전 기본값·편집/초기화·서버 재검증·실행 snapshot/hash 반영
- `secai.result-knowledge.v2`의 3개 AI 직접 출처, 문장 뒤 인용, 번호형 설명,
  규칙 엔진 제외와 완료 커서 제거 반영
- Linux 배포판 사전 확인 재시도·오류 분리·실패 후 재시작 반영
- Windows Profile/Linux 실행별 기준과 아직 남은 범용 무코드 Builder Gate 구분
- Guide Catalog 내부 검색 승인, Mapping/Audit Pack DRAFT와 전체 분류 검색 benchmark를 분리

문서 검증:

- `rg --files -g '*.md'`로 확인 가능한 Markdown 139개를 대상으로 로컬 상대 링크를 검사했다.
- 로컬 링크 337개 중 존재하지 않는 대상은 `0`개였다.
- 현재 문서에서 오래된 `secai.result-knowledge.v1` 직접 표시, 4개 AI 출처,
  Linux/Markdown 미구현 표현을 검색해 남은 현재 문서 불일치가 없음을 확인했다.
- v1 표현이 남은 ADR 17·18과 `KNOWLEDGE_01_03` 검증 문서는 당시 승인·검증 이력이며
  현재 문서에서 v2 보완 기록을 명시적으로 연결했다.

## 8. Linux 진행·Windows형 결과 UI·AI 전환 후속 수정

### 원인

- Linux 실행기는 42개 Probe를 모두 수집한 다음 U-01~U-67 판정을 시작한다. 기존 화면은
  `CONTROL_COMPLETED`만 항목 진행 상태에 반영해 `13 / 42`처럼 수집이 진행돼도 67개
  항목이 전부 `대기`로 남았다.
- Linux 결과 상단 작업을 한 줄 toolbar에 모아 Windows 결과의 점검 시각·PDF·재점검·
  결과 보기 계층과 달랐고, 상태 요약은 숫자만 표시해 클릭 필터가 없었다.
- Linux AI는 67개 전체 요약을 먼저 생성한다. 모델이 정상적인 요약 delta를 모두 보낸 뒤
  `finish_reason=length`를 반환하면 `OUTPUT_TOKEN_LIMIT_REACHED`가 전체 stream 실패로
  전파돼 U-01 항목별 생성으로 넘어가지 않았다.

### 수정

- Probe마다 `affected_control_ids`와 모든 의존 Probe가 끝난 `ready_control_ids`를 이벤트에
  포함했다. 화면은 이를 `자료 수집 중`과 `자료 수집 완료 · 판정 대기`로 즉시 표시하며,
  실제 판정 뒤에만 `확인 완료`로 바꾼다.
- Linux 결과를 Windows와 같은 순서인 상태 요약 → 점검 시각/작업 → PDF → 기본 닫힘
  재점검 → 항목별 결과/AI 전환 → AI 종합 → 카드로 재배치했다. 세 보기 버튼은 동일 폭
  Grid를 사용하고 좁은 화면에서는 작업 버튼이 겹치지 않게 한 열로 줄어든다.
- Linux 상태 요약 다섯 칸을 실제 카드 필터 버튼으로 연결했다. Windows 상태 요약에도
  Linux와 같은 양호(초록)·취약(빨강)·수집 오류(주황)·기준 확인(파랑) 숫자색을 적용했다.
- AI 요약 실패를 항목 생성과 분리하고 항목 한 건 실패도 다음 항목으로 진행한다. 제공자
  연결 실패만 3회 연속일 때 반복 호출을 중단한다. stream이 terminal event 없이 끊기면
  화면에 안전한 재시도 안내를 표시하고 이미 생성된 내용은 보존한다.
- 사용자 확인에 따라 요약 입력을 우선 항목 12개로 줄이지 않았다. U-01~U-67 전체 입력과
  기존 FAST/PRECISE 출력 예산 `4,000 / 5,600`을 그대로 유지하며, 이미 표시된 정상 요약은
  `length` 종료에서도 덮어쓰지 않고 항목별 생성으로 전환한다.

### 검증

- 집중 Pytest: `17 passed`
  - 67개 전체 요약 입력·기존 출력 예산 보존
  - 정상 요약 delta 뒤 `OUTPUT_TOKEN_LIMIT_REACHED`가 발생해도 `CONTROL_STARTED`와
    `CONTROL_COMPLETED`가 각각 67건이고 마지막 `ANALYSIS_COMPLETED`가 발생
  - Probe→U 항목 매핑, Linux/Windows 공통 통계색, 결과 필터·레이아웃 계약
- 실제 Ubuntu 24.04 읽기 전용 실행:
  - run `1f77f2d4-aab1-41e1-acf8-f18c595b03f8`
  - 약 165초, `affected_control_ids`·`ready_control_ids` 실제 수신
  - `CONTROL_COMPLETED 67`, 저장 Control `67`, 최종 `COMPLETED`
- 로그인된 최신 Linux 결과 페이지: HTTP `200`, Windows형 레이아웃 계약 `5 / 5`
- 변경 Ruff: `All checks passed`
- 변경 Python mypy: `Success: no issues found in 4 source files`
- JavaScript syntax: `linux-scan.js`, `linux-results.js` PASS
- Core Health: API `ok`, PostgreSQL·Redis·AIStor·ClamAV `ready`
- API image/container digest 일치:
  `sha256:e1e01170e629e7f606195b8dbf07b85fc7f2c28751d39ec6513f54498e4ed1c9`

추가로 넓혀 실행한 `test_imp040_product_ui.py`의 기존 2건은 dev-tools 시험 컨테이너에
`/run/secrets/demo_csrf_token`이 제공되지 않아 실패했다. 이번 변경 파일과 관련된 17건은
분리 실행에서 모두 통과했고, 실제 인증 화면과 Linux 결과 페이지는 실행 서비스에서
정상 응답을 확인했다.

## 9. Linux V4 AI 캐시 중단·Windows 카드 동등성 Hotfix

### 실제 원인

- 종합 설명은 모델에서 정상 생성됐지만 이를 `V4:SUMMARY`로 저장하는 순간 PostgreSQL의
  기존 `linux_audit_ai_outputs_output_key_check`가 `SUMMARY`와 `U-00~U-99` 형식만
  허용해 `IntegrityError`가 발생했다.
- 이 저장 예외가 SSE 생성기 밖으로 전파되어 사용자가 중단하지 않았는데도
  `SUMMARY_COMPLETED`와 첫 `CONTROL_STARTED` 전에 연결이 닫혔다. 따라서 화면은 생성된
  종합 설명을 보존하면서도 `0 / 67`과 조기 종료 안내를 표시했다.

### 수정

- 신규 migration `0021_linux_ai_v4_keys`에서 기존 무버전 캐시를 보존하면서
  `V4:SUMMARY`와 `V4:U-01~U-67`을 명시적으로 허용했다. 기존 migration은 수정하지 않았다.
- AI 캐시 조회·저장을 best-effort 경계로 분리했다. DB 캐시가 일시적으로 실패해도 이미
  생성한 token은 사용자에게 전달하고 다음 항목으로 진행한다. 로그에는 run/key/예외 종류만
  남기며 생성된 설명 본문은 남기지 않는다.
- Linux 결과 카드에서 Windows에 없는 `다음 행동`, 정적 `용어 간단 설명`, `확인 방법과
  기술 정보` 영역을 제거했다. 결과 영역은 Windows와 동일하게 4개 필드만 2열 Grid로
  표시하고 그 아래 `AI 상세 설명`, 마지막 `출처 보기` 순서를 유지한다.
- 두 결과/AI 영역에 Windows와 같은 접근성 label을 부여했다. 서버에 특화된 문구만
  `내 서버에서 확인한 값`으로 유지한다.

### 검증

- TDD 초기 확인: 카드 계약 2건, 강제 `IntegrityError` 스트림 1건, migration 부재 1건이
  예상한 이유로 실패했다.
- 집중 Pytest: `13 passed`
  - 캐시 쓰기가 모든 요청에서 실패해도 `SUMMARY_COMPLETED`, 67개 `CONTROL_STARTED`,
    67개 `CONTROL_COMPLETED`, 마지막 `ANALYSIS_COMPLETED` 발생
  - 카드의 `addFact` 호출 4개와 Windows 순서, 제거 영역 부재 확인
  - V4 키 migration chain·제약 이름·범위 확인
- PostgreSQL:
  - Alembic head `0021_linux_ai_v4_keys`
  - 기존 캐시 `71`건 보존
  - rollback transaction에서 `V4:SUMMARY` 실제 INSERT 성공, rollback 뒤 V4 시험자료 `0`건
  - 첫 적용에서 Alembic 이름 규칙 불일치가 발생했으나 transactional DDL로 전부 rollback됐고,
    실제 constraint 이름을 `op.f`로 고정한 뒤 정상 적용했다.
- Ruff: `All checks passed`
- strict mypy: `Success: no issues found in 146 source files`
- JavaScript syntax: `linux-results.js` PASS
- API image/container: `sha256:222a3ef7b39623f956e59048880204cd0cb04d95a20c6720dc8b64ceacfea27f`,
  health `healthy`, `/health/ready` 의존성 4개 모두 `true`
