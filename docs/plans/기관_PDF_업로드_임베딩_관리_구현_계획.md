# 기관 PDF 업로드·임베딩 관리 구현 계획

## 현재 상태

승인된 공공기관 PDF 8종의 Catalog·추출·Page Map·embedding·통합 검색은 개발 환경에서 동작합니다. 관리자가 웹에서 새 PDF를 업로드하고 검토·게시·검색 제외·복원하는 기능은 아직 제공하지 않습니다.

## 목표 사용자 흐름

```text
관리자 PDF 업로드
→ 격리 저장·악성코드/MIME/크기 검사
→ SHA-256·중복 확인
→ 기관·제목·version·이용조건 입력
→ 첫 2쪽·마지막 2쪽 자동 제안
→ 전체 text·Page Map 추출 미리보기
→ chunk·embedding dry-run
→ 검색 품질 검토
→ 승인자 게시
→ 새 generation 활성화
```

## 단계

### GUIDE-ADMIN-01 업로드 격리

- PDF만 허용하고 확장자와 실제 MIME을 함께 확인
- 크기·쪽수·압축 폭탄·암호화 PDF 제한
- 원본 파일명 대신 서버 생성 ID 사용
- 임시 격리 위치와 timeout·악성코드 검사
- 원문 hash 중복과 기존 version 확인

### GUIDE-ADMIN-02 메타데이터 검토

- 기관, 정식 제목, 발행·개정일, version
- 공식 원문 URL과 이용조건
- 공개/조직 scope
- `DRAFT/REVIEW/APPROVED/RETIRED` 상태
- Guide 승인과 Audit Pack 승인을 분리

### GUIDE-ADMIN-03 추출·Page Map

- 첫 2쪽과 마지막 2쪽에서 표지·목차·발행정보 자동 제안
- 사람 검토 전 확정 금지
- 전체 쪽 text·표·OCR 상태 표시
- chunk가 원본 쪽으로 되돌아갈 수 있는 Page Map
- secret·개인정보·지시문 패턴 경고

### GUIDE-ADMIN-04 임베딩 dry-run

- BGE-M3 1024차원 별도 generation 생성
- 대표 질문으로 top-k·rerank·citation 미리보기
- 기존 활성 generation을 변경하지 않음
- 실패하면 전체 generation 폐기

### GUIDE-ADMIN-05 게시·복원

- 승인 역할과 CSRF·재인증
- 게시 이벤트 append-only 감사
- 검색 제외는 원본 삭제가 아닌 Catalog 상태 변경
- 이전 generation 즉시 rollback
- 새 질문만 새 generation을 사용하고 기존 대화 citation 보존

## API·보안 경계

- 외부 DTO는 추가 필드 금지와 길이·enum 검증을 적용합니다.
- 파일 경로를 사용자 입력으로 만들지 않습니다.
- PDF text의 지시문을 시스템 prompt로 사용하지 않습니다.
- 모델 출력으로 승인 상태를 바꾸지 않습니다.
- 조직 비공개 원문은 외부 모델로 보내지 않습니다.
- 기존 migration을 수정하지 않고 새 migration을 사용합니다.

## 완료 기준

- 악성·중복·손상·암호화·과대 PDF가 안전하게 거부됩니다.
- 모든 citation이 원본 PDF의 정확한 쪽으로 이동합니다.
- 승인 전 문서는 일반 검색에 나타나지 않습니다.
- 검색 제외·복원·generation rollback이 과거 대화를 손상하지 않습니다.
- 타 조직 문서가 검색·다운로드·모델 입력에 노출되지 않습니다.
