# IMP-026 전체 Pack Fixture Coverage

`coverage.json`은 PC-01~18 통합 회귀에서 읽을 합성 Fixture 위치와 기대 개수를 고정한다.

- 실제 PC 자료, 사용자명과 조직 자료를 포함하지 않는다.
- Pack의 모든 Control은 정확히 한 번 포함되어야 한다.
- `fixture_refs`의 `pass`, `fail`, `error`와 선택적인 `review`, `not_applicable`은 같은 Control의 실제 합성 사례를 가리켜야 한다.
- 전체 92개 사례의 기대 결과와 실제 규칙 결과가 모두 같아야 한다.
- 전체 결과를 100회 다시 만들었을 때 RFC 8785 canonical SHA-256이 하나여야 한다.
- Pack은 계속 `DRAFT`이며 이 Coverage 통과는 운영 승인을 뜻하지 않는다.
