# 가이드 질의·RAG 구현 현황과 남은 계획

## 현재 구현

사용자는 문서를 하나씩 선택하지 않고 질문합니다. 시스템이 승인된 KISA 직접 근거 1종과 공공기관 보완 문서 7종에서 관련 문단을 찾고, LLM이 이를 종합해 stream으로 답합니다.

- PostgreSQL·pgvector 정본
- BGE-M3 1024차원 embedding과 `bge-reranker-v2-m3`
- 32차원 legacy rollback generation 병행
- Catalog `APPROVED` 문서만 검색
- thread 생성·제목·pin·folder·archive·tombstone·undo
- 생성 시작·중단·재시도와 token stream
- 제한 Markdown과 허용 URL·XSS 방어
- 실제 사용 문서명·쪽 citation
- 조직·owner scope와 RLS
- 외부 모델에는 승인된 비식별 검색 문단만 전송

화면에서 `질문 범위` 선택 UI는 제거했지만 내부 통합 scope와 Catalog 필터는 유지합니다.

## 반드시 유지할 분리

| 영역 | 권한 |
|---|---|
| Guide Catalog | 검색에 사용할 문서 승인 |
| Audit Pack | 공식 점검 판정 기준 승인 |
| RAG·LLM | 질문에 대한 설명과 근거 제시 |
| 규칙 엔진 | Windows·Linux·Switch 상태 결정 |

가이드 답변이 공식 판정, 기준 snapshot 또는 Finding을 변경하지 않습니다.

## 남은 단계

### RAG-QUALITY-01 정식 benchmark

- Windows·Linux·Switch·AI·공급망별 대표 질문 세트
- 정답 문서·쪽·필수 핵심어와 금지 답변
- recall@k, citation precision, groundedness, latency
- legacy generation과 BGE-M3 비교
- 한글 복합어·표·목차·OCR 오류 회귀

### RAG-OPS-02 관리자 문서 반입

- PDF 격리 업로드와 악성코드·크기·MIME 검사
- 문서 메타데이터·이용조건·hash 확인
- 첫/마지막 쪽 자동 제안과 사람 검토
- 추출·Page Map·chunk·embedding dry-run
- 게시·검색 제외·복원·새 version

### RAG-RUNTIME-03 로컬 전환

- 승인 모델·GPU·image digest·context 길이
- 외부 egress 0과 model gateway 호환
- 출력 검증·timeout·중단·fallback
- 동일 benchmark 회귀

## 완료 기준

- 질문마다 실제 근거 문서와 쪽을 재현할 수 있습니다.
- 검색 결과나 PDF 안의 지시문을 시스템 지침으로 실행하지 않습니다.
- 타 조직 비공개 문서가 검색·citation·모델 입력에 나타나지 않습니다.
- 모델 장애가 대화·점검 결과 정본을 손상하지 않습니다.
