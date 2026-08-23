# Windows 구성요소 알려진 취약점 후보·한국어 AI 검증

| 항목 | 결과 |
|---|---|
| 상태 | **PASS — DEV-LOCAL 후보 비교 및 결과 보존** |
| 범위 | Windows 11, 설치 프로그램·AppX·KB·Python·Node.js·Java 인벤토리 |
| 공개 자료 | Windows NVD exact CPE, PyPI/npm/Maven OSV exact package/version |
| 결과 권한 | 공개자료 영향 가능성 후보만 표시, 공식 Finding 생성·변경 없음 |
| 기준일 | 2026-08-06 |

## 1. 구현 결과

- Windows Collector는 고정된 읽기 전용 원천에서 구성요소 이름과 버전만 수집한다.
- 중앙 API는 Python·Node.js·Java 패키지의 exact 이름·버전을 OSV `querybatch`와 비교한다.
- 정확히 일치한 후보는 한국어 제목, 구성요소·확인 버전, 제공 기관, 공개일·최종 수정일,
  CVSS 점수와 영문 원문 링크를 포함한 카드로 표시한다.
- 사용자가 요청한 후보 한 건만 내부 모델 게이트웨이에 전달해 쉬운 한국어 설명을 만든다.
- 일반 프로그램·AppX·KB는 검토된 CPE 또는 Microsoft 권고 적용성 계약이 없으면 임의로
  매칭하지 않고 `추가 식별 필요`로 유지한다.

## 2. 후보 1건만 표시된 결함과 수정

실제 화면에서 프로그램 165개, KB 40개, Python 340개, Node.js·Java 7개를 수집했지만
Windows 후보 1건만 표시됐다. 원인은 수집 누락이 아니라 OSV 결과 보강 단계였다.

1. OSV `querybatch`의 exact package/version 후보가 100개를 넘으면 전체 package 비교를
   `SOURCE_ERROR`로 폐기했다.
2. 후보 한 건의 공개일·CVSS·설명 상세 조회가 실패해도 전체 package 비교를 폐기했다.
3. 이때 화면은 `추가 식별 필요 552`로 표시하면서 Windows 후보 1건을 전체 후보처럼
   설명할 수 있었다.

수정 후에는 `querybatch`에서 확인한 exact 후보를 전부 보존한다. 상세 정보는 최대 100개의
고유 후보부터 병렬 보강하며, 상한 초과 또는 개별 상세 조회 실패 후보도 삭제하지 않는다.
해당 후보는 `점수 산정 전`·상세 확인 필요 상태로 표시한다. batch 자체가 실패한 경우에만
package 비교를 사용할 수 없는 상태로 처리하고, 결과 문구와 기술 상세에서 이를 명시한다.

## 3. 검증 결과

| 검증 | 결과 |
|---|---|
| 상세 보강 상한 초과 시 exact 후보 보존 | PASS |
| 개별 OSV 상세 HTTP 실패 시 exact 후보 보존 | PASS |
| Windows OS·설치 구성요소 집중 회귀 | **21 PASS** |
| Ruff 변경 파일 | PASS |
| mypy strict 운영 소스 3개 | PASS |
| JavaScript `node --check` | PASS |
| API `/health`, `/ready` | PASS, PostgreSQL·Redis·AIStor·ClamAV 정상 |
| 실행 API image 정합성 | `sha256:b3be0cb515091f1bdb544a2c82a7d24618123c01d128025d422605b090d319ba` 일치 |

전체 테스트 파일을 직접 mypy 대상으로 지정하면 해당 파일에 이미 존재하던 광범위한
`JsonValue` narrowing 오류가 보고된다. 이번 변경의 운영 소스 3개 strict mypy는 통과했고,
신규 동작은 Pytest로 검증했다.

## 4. 남은 경계

- 일반 Windows 프로그램·AppX·KB의 제조사 확정 매칭은 아직 구현되지 않았다.
- Microsoft 보안 권고의 affected/fixed build·KB 적용성 확인 전에는 확정 취약 판정이 아니다.
- 후보가 0건이어도 안전 또는 알려진 취약점 없음으로 확정하지 않는다.
- 폐쇄망용 서명 Offline Feed Bundle과 Linux·Switch 확대는 후속 Gate다.

