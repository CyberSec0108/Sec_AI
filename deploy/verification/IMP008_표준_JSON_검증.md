# IMP-008 Canonical JSON·SHA-256 검증 기록

| 항목 | 결과 |
|---|---|
| 구현 ID | `IMP-008` |
| Runtime | CPython `3.14.6`, `linux/amd64` |
| Canonicalization | RFC 8785 JCS |
| 구현 package | `rfc8785==0.1.4`, Apache-2.0, 순수 Python·외부 의존성 없음 |
| 상태 | `PASS` |

## 구현 범위

- JSON 값을 RFC 8785 JCS UTF-8 byte로 변환한다.
- canonical byte의 lowercase SHA-256을 계산한다.
- Manifest `authorization`, Audit Pack `approval`처럼 승인된 최상위 envelope field를 제외하고 hash할 수 있다.
- 입력 dictionary를 수정하지 않는다.
- 표현 불가능한 값은 일반 JSON으로 조용히 변환하지 않고 오류로 거부한다.

구현 파일은 `src/security_audit/common/canonical_json.py`이며, 표시용 JSON이나 원본 archive byte를 이 함수로 hash하지 않는다.

## 공급망 잠금

`requirements/base.in`에 `rfc8785==0.1.4`를 직접 선언했다. 다음 Linux lock을 승인된 Python 3.14.6 base image와 `pip-tools 7.6.0`으로 다시 생성했다.

- `api.lock`
- `worker.lock`
- `ingestion.lock`
- `dev.lock`

초기 lock diff에서는 `rfc8785 0.1.4`만 추가됐다. 이어서 전체 `pip-audit --strict`에서 기존 `cryptography 47.0.0`의 `GHSA-537c-gmf6-5ccf`가 발견되어 공식 수정본 `48.0.1`로 별도 보안 보정했다. Wheel과 source distribution SHA-256은 `requirements/verification/rfc8785-lock.json` 및 각 lock에 기록했다. Collector lock은 실제 Windows Collector 구현 단계에서 같은 vector를 Windows CPython 3.14.6으로 확인한 뒤 반영한다.

## 자동 시험 결과

| 시험 | 결과 |
|---|---|
| RFC 8785 section 3 canonical byte vector | PASS |
| 고정 SHA-256 `2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb` | PASS |
| UTF-16 property ordering vector | PASS |
| property 입력 순서 변경 시 동일 hash | PASS |
| 제외 envelope field 변경 시 동일 hash | PASS |
| 원본 dictionary 비변경 | PASS |
| NaN·±Infinity 거부 | PASS |
| IEEE-754 안전 범위 밖 integer 거부 | PASS |
| Pytest | 9 passed |
| Ruff | PASS |
| mypy strict | PASS |
| `pip-audit 2.10.1 --strict` (수정 이미지) | PASS: known vulnerability 0건 |

표준 근거는 [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html), 구현 artifact 근거는 [PyPI rfc8785 0.1.4](https://pypi.org/project/rfc8785/0.1.4/)다.

## 다음 작업

`IMP-009`에서 strict JSON loader의 duplicate property 방어와 archive path·size·file count·compression ratio·hash validation을 구현한다. JSON Schema 검증은 canonicalization이나 package 보안 검사를 대신하지 않는다.
