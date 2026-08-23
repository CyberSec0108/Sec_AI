# `audit_packs` 영역 코딩 에이전트 지침

적용 범위는 Audit Pack, Fixture, Adapter Catalog, 기준 snapshot이다. 루트 지침,
[`README.md`](README.md), ADR 15·20을 먼저 읽는다.

## 1. 현재 승인 경계

- `kisa_2026_pc`의 현재 Pack은 개발용 `DRAFT`다.
- `kisa_2026_unix`는 개발 경계 문서이며 운영 승인 Pack이 아니다.
- Aruba N-01~N-38 benchmark와 UI 결과도 운영 공식 Pack·Finding이 아니다.
- Guide Catalog의 `APPROVED`는 원문 검색 승인이지 Audit Pack 실행 승인이 아니다.

Pack의 `status`, version, content hash, signature를 문서 표현만으로 승격하지 않는다.

## 2. Pack 변경 순서

1. 정확한 가이드 page·section·Control Source Mapping을 확인한다.
2. `database/schemas/audit_pack.schema.json`과 관련 계약을 확인한다.
3. 정상·취약·경계·권한 부족·수집 오류 Fixture와 기대값을 먼저 추가한다.
4. 기존 fact로 판정 가능한지 확인한다. 부족하면 Collector 변경을 별도 범위로 분리한다.
5. allowlisted rule registry를 추가·수정한다.
6. 전체 Pack coverage, false PASS 0, 동일 입력 100회 결정론을 검증한다.
7. version과 canonical content hash를 갱신한다.
8. 사람 검토·서명·폐기 Gate가 없으면 계속 `DRAFT`로 둔다.

## 3. 금지 사항

- 기존 version 파일을 소급 수정하거나 과거 Finding 참조 hash를 바꾸지 않는다.
- 수집되지 않은 사실을 expected 값으로 채워 `PASS`를 만들지 않는다.
- 권한 부족·미지원·parser 오류를 `FAIL`로 바꾸지 않는다.
- LLM 제안 rule·mapping·Fixture를 자동 등록하지 않는다.
- 일반 사용자에게 raw command, JSON rule, Python 표현식, SQL을 입력받지 않는다.
- 개인/조직 기준으로 KISA 결과를 덮어쓰지 않는다. 병렬 참고 결과로만 표시한다.

## 4. 파일 역할

- `src/pack-<version>.json`: version별 불변 Pack source
- `src/pack.json`: 현재 개발 Pack 진입점. 참조 방식과 hash를 먼저 확인
- `fixtures`: input·expected와 Control군별 합성 회귀
- `adapter_catalogs`: 제품 fact가 Control에 제공하는 범위
- `reference_snapshots`: 제조사 기준일·지원 수명 같은 외부 기준 snapshot

Schema·Pack을 바꾸면 valid/invalid 예제, rule 시험, full pack coverage와 관련 검증 기록을
함께 갱신한다.

