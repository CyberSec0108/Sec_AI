# Alembic migration rules

- 기존 revision은 수정하지 않는다. 변경은 항상 새 revision으로 추가한다.
- `finding_versions`는 append-only 정본이며 UPDATE, DELETE, TRUNCATE를 허용하지 않는다.
- `finding_current`는 현재 버전을 가리키는 별도 projection이다.
- migration URL은 환경 변수와 Docker secret file에서 조립하며 파일에 저장하지 않는다.
