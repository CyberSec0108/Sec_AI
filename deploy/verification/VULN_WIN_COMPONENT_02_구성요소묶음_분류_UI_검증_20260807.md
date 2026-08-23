# Windows 취약점 구성요소 묶음·분류 UI 검증

| 항목 | 값 |
|---|---|
| 검증일 | 2026-08-07 |
| 범위 | Windows 알려진 취약점 결과의 구성요소별 묶음, 종류·발견 범위 분류, 자동 비교 제외 사유 |
| 상태 | 개발 소스와 집중 단위시험 `PASS`; 실제 배포 image·브라우저 육안 E2E는 미실행 |

## 1. 해결한 문제

- 공개 취약점 후보를 CVE 한 건마다 같은 크기의 카드로 나열하던 구조를 구성요소 단위로 묶었다.
- 영향 가능 구성요소 수와 공개 취약점 참고자료 수를 분리했다.
- Windows OS, Python, Node.js, Java 필터와 구성요소·CVE 검색을 추가했다.
- 접힌 구성요소의 개별 CVE DOM은 사용자가 처음 펼칠 때 생성해 대량 후보의 초기 화면 부하를 줄였다.
- `추가 식별 필요`를 `자동 비교 제외`로 바꾸고 Windows 프로그램 제품 매핑, Windows
  업데이트 증적, 공개자료 비교 오류를 서로 다른 사유로 표시한다.
- 후보에 `component_type`, 발견 `scope`, 수집 원천을 보강했다. 기존 append-only cache
  항목도 현재 인벤토리로 표시 분류만 보강하며 저장된 snapshot은 수정하지 않는다.
- 같은 package/version의 OSV 자료가 공통 CVE alias를 제공하면 CVE를 대표 번호로 사용하고
  GHSA·PYSEC 등 나머지 번호를 다른 식별번호로 보존한다.

## 2. 유지한 안전 경계

- 공개자료 exact package/version 일치는 계속 영향 가능성 후보이며 공식 취약 판정이 아니다.
- 후보 0건 또는 자동 비교 제외 0건을 안전 판정으로 바꾸지 않는다.
- 일반 Windows 프로그램을 문자열 유사도로 CPE에 자동 매핑하지 않는다.
- `LOCAL_CACHE` 발견은 실제 사용 중인 라이브러리로 확정하지 않고 사용 여부 확인 안내를 표시한다.
- 원본 후보는 삭제하지 않고 구성요소 상세 안에 보존한다.
- AI는 사용자가 후보 한 건을 요청할 때만 기존 비식별 공개 projection을 받으며 판정을 변경하지 않는다.

## 3. 검증 결과

```text
docker compose --project-directory C:\Users\Hala\Desktop\Sec_AI \
  -f deploy/compose/compose.yml -f deploy/compose/compose.dev.yml \
  run --rm dev-tools -m pytest \
  tests/unit/test_known_vulnerability_check.py \
  tests/unit/test_windows_component_vulnerability_check.py -q

23 passed, 1 existing Starlette deprecation warning
```

최종 소스 상태에서 `test_windows_component_vulnerability_check.py` 14건을 다시 실행해 모두
통과했다. 두 파일을 함께 다시 수집하는 시도는 같은 작업공간에 동시에 추가된
`apps/api/linux_asset_management.py`의 FastAPI response type 오류에서 중단됐다. 이 오류는
취약점 route나 본 변경 파일을 실행하기 전에 `apps.api.main` import 단계에서 발생했으며 본
작업에서는 동시 사용자 변경을 수정하지 않았다.

```text
docker compose ... run --rm dev-tools -m ruff check \
  src/security_audit/application/component_vulnerability_check.py \
  src/security_audit/application/known_vulnerability_check.py \
  apps/api/vulnerability_check.py \
  tests/unit/test_windows_component_vulnerability_check.py

All checks passed!
```

```text
docker compose ... run --rm dev-tools -m mypy \
  src/security_audit/application/component_vulnerability_check.py \
  src/security_audit/application/known_vulnerability_check.py \
  apps/api/vulnerability_check.py

Success: no issues found in 3 source files
```

```text
node --check apps/web/static/app/vulnerability-check.js

PASS
```

## 4. 남은 범위

- 제조사 권고·VEX·KEV 기반 확정 적용성과 실제 악용 우선순위
- 생태계별 version range를 검증한 공통 수정 버전 계산
- 일반 Windows 프로그램의 검토된 CPE alias registry
- 실제 748건 수준 응답을 사용한 브라우저 성능·접근성·모바일 육안 E2E
- 사용자·기술 검증 PDF와 persistent 조치 상태
