# 가이드 질의 질문 범위 UI 제거 검증

## 1. 요청

가이드 질의 화면 오른쪽 상단의 다음 표시 영역을 제거한다.

- `질문 범위`
- `통합 보안 가이드 검색 (8종)`
- 관련 문서 자동 검색 안내 문구

## 2. 변경 경계

- 사용자에게 보이는 범위 표시 카드만 제거했다.
- 내부 `guide-select`는 hidden input으로 유지했다.
- `/api/v1/chat/guides`의 승인 Catalog 조회와 통합 8종 검색 범위는 유지했다.
- 질문, pgvector 검색, LLM stream, 출처 인용, 점검 판정 불변 계약은 변경하지 않았다.
- 제거된 요소 전용 JavaScript와 CSS는 함께 삭제했다.

## 3. TDD

수정 전 새 UI 계약 시험이 `질문 범위` 표시를 발견해 실패하는 것을 확인했다. 수정 후 hidden 통합 범위는 존재하고 사용자 표시 문구와 관련 DOM·JavaScript 함수가 없는지 검증했다.

## 4. 검증 결과

```text
단일 UI 계약: 1 passed
가이드 채팅·인용·제한 Markdown 회귀: 32 passed, 1 warning
guide-chat.js node --check: PASS
API image/container: sha256:4c08b5c735546b56775f3f1af3feb104db93f26fd03276cf09fcc842dcc0755b 일치
Core health: healthy, ready (PostgreSQL·Redis·AIStor·ClamAV true)
실행 container template: hidden_scope=true, visible_scope_label=false, visible_scope_title=false
```

회귀 시험은 `test_public_guide_chat.py`, `test_imp053_live_guide_chat.py`, `test_guide_chat_citation_alignment.py`, `test_markdown_01_03_restricted_renderer.py`를 포함한다. 경고 1건은 기존 Starlette TestClient deprecation warning이다.

## 5. 결과

가이드 질의 상단에는 왼쪽 `가이드 질의` 제목만 남는다. 통합 검색은 화면에 별도 범위 카드를 표시하지 않고 기존과 동일하게 승인된 8종 문서를 대상으로 동작한다.
