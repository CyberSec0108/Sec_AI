# AI 프롬프트 Web 관리·검증·적용 계획

## 현재 상태

Windows·Linux·Switch 결과 설명 prompt는 source의 versioned service 계약으로 관리합니다. `.env`는 모델 주소·timeout·기능 toggle 같은 환경값에 적합하지만 여러 줄 prompt 본문, manifest와 승인 이력을 관리하기에는 적합하지 않습니다.

관리자가 Web에서 prompt를 수정·검증·승인·적용·복원하는 기능은 아직 제공하지 않습니다.

## 목표

`계정정보 → 관리자 운영 기능`에 `AI 설명 프롬프트 관리`를 추가합니다.

관리자는 다음만 할 수 있습니다.

1. 플랫폼과 prompt 종류 선택
2. 기존 version을 복제해 `DRAFT` 작성
3. Markdown·placeholder·manifest 검증
4. 합성 결과로 미리보기
5. 승인 요청
6. 승인 역할이 게시
7. 클릭으로 활성 version 전환 또는 이전 version 복원

## 저장 계약

prompt 본문과 manifest를 분리합니다.

필수 manifest 예:

- prompt ID와 semantic version
- 플랫폼: Windows/Linux/Switch
- 용도: 종합/항목/후속 질문
- 허용 placeholder 목록
- 최대 입력·출력 크기
- 출력 Schema·금지 문구 version
- 작성자·검토자·승인자·시각
- content SHA-256와 상태

private key, API key와 실제 점검 원문을 prompt 저장소에 넣지 않습니다.

## 검증 단계

### PROMPT-ADMIN-01 문법

- UTF-8, 길이, 필수 section
- 알 수 없는 placeholder 거부
- HTML·script·임의 tool 호출 지시 거부
- 공식 판정 변경·명령 실행·secret 요구 문구 거부

### PROMPT-ADMIN-02 manifest

- JSON Schema와 semantic version
- 본문 hash 일치
- 플랫폼·용도·출력 계약 일치
- 기존 승인 version 덮어쓰기 금지

### PROMPT-ADMIN-03 합성 미리보기

- PASS/FAIL/REVIEW/ERROR/N/A fixture
- 부분 증적·한글·긴 값·prompt injection 문장
- 공식 상태 개수 보존
- citation·제한 Markdown·XSS 검사

### PROMPT-ADMIN-04 승인·적용

- 작성자와 승인자 분리
- 재인증·CSRF·RBAC
- append-only 승인·적용 감사
- 실행 시 활성 version/hash snapshot
- 진행 중 생성은 시작 version 유지

### PROMPT-ADMIN-05 복원

- 이전 승인 version 선택
- 새 활성화 이벤트 추가
- 기존 결과·AI cache를 자동 재생성하지 않음
- 새 생성 요청부터 적용

## 유지할 경계

- prompt가 공식 판정을 만들거나 변경하지 않습니다.
- 일반 사용자가 prompt를 편집할 수 없습니다.
- 검증 실패 DRAFT는 적용 버튼을 활성화하지 않습니다.
- AI가 만든 prompt 수정안은 실행 불가능한 제안입니다.
- 적용 도구가 shell, migration 또는 배포 명령을 임의 실행하지 않습니다.

## 완료 기준

- 세 플랫폼 종합·항목 stream 회귀를 통과합니다.
- 재시작 없이 활성 version 조회가 일관되고 실패 시 이전 version을 유지합니다.
- 누가 무엇을 검토·승인·적용했는지 감사할 수 있습니다.
- 기존 결과와 AI 설명 cache가 자동으로 리셋되지 않습니다.
