# 결과 중심 AI 제품 로드맵 재기준화 기록

검토일: 2026-07-25

## 1. 확인한 제품 문제

현재 구현은 Collector 수집, 규칙 판정, KISA RAG와 대화 화면의 개별 기술 Gate를 통과했다. 그러나 실제 점검 결과가 LLM 설명의 중심 입력으로 충분히 연결되지 않아 다음 최초 제품 목표를 완료하지 못했다.

```text
점검 버튼
→ 내 PC 내용 수집
→ 규칙으로 안전 여부 판정
→ KISA 근거를 이용한 AI 설명
```

`IMP-052~054`의 완료 이력은 해당 시점의 보안·계약·화면 검증 결과로 보존한다. 이 이력을 AI PC 보안 점검 제품 전체 완료로 확대 해석하지 않는다.

## 2. 승인한 새 기준선

- ADR 18을 추가해 공식 판정과 AI 설명의 권한, explanation input/output, 근거 우선순위와 사용자 정보구조를 고정했다.
- `PRODUCT-AI-01~09`를 `IMP-055` clean VM보다 먼저 수행한다.
- 판정 이유 코드는 PowerShell 명령이나 실제 확인값이 아니라 개발자·관리자 추적용 내부 식별자로 관리한다.
- 일반 사용자에게는 실제 확인 내용·확인 방법·자연어 판정 이유를 제공하고 내부 코드는 기술 정보로 분리한다.
- 동일한 불변 결과 snapshot에서 사용자용 PDF와 역할 제한 기술 검증용 PDF를 생성한다.
- 일반 사용자 상단 메뉴는 `PC 점검`, `점검 결과`, `KISA AI 상담`을 기본으로 한다.
- 별도 `대화 기록` 상단 메뉴는 상담 화면의 최근 대화 panel로 통합한다.
- theme은 해·달 icon, 대화·출처 panel은 접근 가능한 icon drawer로 전환한다.
- 최근 대화에 이름 변경·삭제 취소·보관·이동·고정·검색을 제공한다.

## 3. 동기화 문서

| 문서 | 반영 내용 |
|---|---|
| `docs/adr/18.ADR_결과_중심_AI_PC_보안_도우미.md` | 제품 목표·권한·계약·UI·대화 관리·구현 순서 |
| `docs/adr/13.MVP_구현_시작_계획.md` | VM 전 제품 정합성 보완 단계 추가 |
| `docs/adr/README.md` | ADR 18 Index·변경관리·SHA-256 기준선 |
| `다음_I_J_단계_계획.md` | 다음 작업을 `PRODUCT-AI-01`로 유지하고 설명 추적정보·PDF를 포함한 9개 Gate로 개정 |
| `대화_RAG_제품_계획.md` | 결과 중심 AI 흐름·탐색·대화 관리·완료 기준 개정 |
| `구현_현황.md` | 제품 완료 보류·미완료 체크리스트·다음 작업 동기화 |

## 4. 바로 다음 작업

`PRODUCT-AI-01`에서 PC-01~18 결과를 다음 비식별 explanation input으로 변환한다.

- 실제 확인 내용
- 확인 방법
- 승인 실행 도구
- 비밀값을 제외한 확인 위치
- 규칙 엔진의 불변 판정
- 사용자용 자연어 판정 이유
- 개발자·관리자 추적용 내부 판정 이유 코드
- 수집 제한
- KISA guide version·page·section·chunk hash
- 허용된 사용자·관리자 조치
- canonical input hash

민감정보 포함 0, Control coverage 18/18과 규칙 상태 불변을 먼저 검증한다. `PASSWORD_COMPLEXITY_NOT_OBSERVED` 같은 내부 코드는 명령이나 실제값이 아니며 일반 사용자에게 단독 노출하지 않는다. 이 계약이 통과하기 전에 AI 설명 UI를 완료 처리하지 않는다.

`PRODUCT-AI-04`에서는 결과 화면에 `무엇을 확인했나요`와 `확인 방법`을 빠뜨리지 않는다. `PRODUCT-AI-08`에서는 사용자용 PDF와 기술 검증용 PDF의 내용 분리, 자산·역할 권한, CSRF·IDOR, 생성·다운로드 감사, report hash와 append-only 이력을 검증한다. 기존 최종 제품 인수는 `PRODUCT-AI-09`로 이동한다.

## 5. 검증 범위

이번 변경은 ADR·계획·진행 문서 동기화이며 application code, database, Docker image와 container를 변경하지 않았다. 따라서 code test와 배포는 수행하지 않았다. Markdown 경로·작업 ID `PRODUCT-AI-01~09`·다음 단계·판정 이유 코드 노출 경계·PDF Gate의 상호 일치만 확인한다.

## 6. 문서 검증 결과

- ADR 18, 단계 계획, 제품 계획, 구현 상태에 `PRODUCT-AI-01~09`가 모두 존재하고 이전 `PRODUCT-AI-01~08` 범위 표기가 남지 않음: `PASS`
- ADR 13·18의 변경 후 SHA-256과 `docs/adr/README.md` 기준선 일치: `PASS`
- 단계 계획·제품 계획·구현 상태의 상대 Markdown link 대상 존재: `PASS`
- application code·database·Docker image·container 변경: 없음
- 배포 실행: 문서 전용 변경이므로 해당 없음
