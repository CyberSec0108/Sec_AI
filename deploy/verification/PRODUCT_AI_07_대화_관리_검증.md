# PRODUCT-AI-07 최근 대화 통합·관리 검증

검증일: 2026-07-26  
결과: **PASS**

## 구현 결과

- 상단의 중복 `대화 기록` 메뉴와 제품 기능 카드를 제거하고, KISA 질문 화면의 `최근 대화` 패널로 통합했다.
- 대화 제목 검색과 `사용 중/보관/전체` 목록 전환을 추가했다.
- 각 대화에서 이름 변경, 폴더 이동, 고정/해제, 보관/복원, 삭제와 30초 이내 삭제 취소를 수행할 수 있다.
- 삭제는 물리 `DELETE`가 아니라 `TOMBSTONED` 상태로 전환한다. 삭제 취소 시 삭제 전 `ACTIVE` 또는 `ARCHIVED` 상태를 복구한다.
- 보관 대화에는 새 질문을 추가하지 못하게 기존 `CHAT_THREAD_NOT_ACTIVE` 계약을 화면에도 반영했다.

## 데이터·보안 계약

- 신규 migration head: `0011_product_ai_07`
- `chat_threads` 관리 필드:
  - `is_pinned`
  - `folder_name`
  - `status_before_tombstone`
- `chat_thread_management_events`는 이름 변경·고정·이동·보관·삭제·복원을 append-only JSONB 감사 이력으로 저장한다.
- 대화와 감사 이력 모두 조직 ID와 소유자 ID를 사용하는 PostgreSQL `FORCE ROW LEVEL SECURITY`를 유지한다.
- `secai_runtime`에는 `chat_threads` 물리 삭제 권한을 부여하지 않았다.
- 검색 문자열은 길이와 제어 문자를 검증하고 SQLAlchemy parameter binding과 escaped `contains`를 사용한다.
- 모든 변경 API는 인증 사용자 범위와 브라우저 CSRF를 확인한다.

## 검증 결과

| 검증 | 결과 |
|---|---|
| PRODUCT-AI-07 + IMP-053 집중 Pytest | 11 PASS |
| PRODUCT-AI-01~07 회귀 Pytest | 58 PASS, 기존 Starlette deprecation warning 1건 |
| 변경 Python Ruff | PASS |
| 변경 `src`·`apps`·unit test mypy strict | PASS |
| `guide-chat.js` Node 문법 검사 | PASS |
| 실제 PostgreSQL 관리 동작 | 이름 변경·고정·이동·보관/복원·검색·삭제/취소 PASS |
| 타 소유자 접근 | `CHAT_SCOPE_DENIED` PASS |
| 관리 감사 이력 | 7개 동작, 7개 append-only 이벤트 PASS |
| 기존 메시지 불변 | content SHA-256 불변 PASS |
| 검증 데이터 rollback | 잔존 0건 |
| 로그인 UI·검색 API | PASS |
| 중복 상단 대화 기록 | 0개 |

재현 명령:

```powershell
.\tools\verify-product-ai-07.ps1
```

## 배포 확인

- API image/container:
  `sha256:ed5495bdc252b5b1652440369f53d2d309fe8a1b49a3cd0e1f6e86ea7ba62853`
- API health: `healthy`
- Gateway health: `healthy`
- Alembic: `0011_product_ai_07 (head)`
- 기존 PostgreSQL 대화·점검 데이터는 보존했다.

## 다음 작업

`PRODUCT-AI-08 — 사용자용·기술 검증용 PDF와 AI 모델 활용 명세`를 진행한다. 동일한 불변 결과 snapshot에서 두 보고서를 만들고, 사용자용 PDF에는 내부 코드와 민감정보를 제외하며 기술 검증용 PDF에는 규칙·증적·AI 모델 계보와 보고서 hash/version을 기록한다.
