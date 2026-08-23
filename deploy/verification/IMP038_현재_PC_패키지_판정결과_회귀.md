# IMP-038 현재 OS Package → Finding 회귀 검증

## 결론

`IMP-038`은 2026-07-23 현재 Windows 11 개발 PC에서 완료했다.

- 실제 읽기 전용 수집 자료를 임시 Package로 조립했다.
- `FullPackageValidator → EvidenceNormalizer → Rule Registry → FindingBuilder` 순서로 처리했다.
- PC-01~18 결과 18건과 스키마 유효한 개발용 `DRAFT` Finding 18건을 만들었다.
- 동일 Finding을 항목별 100회 재처리해 `CREATE 18`, `RETURN_EXISTING 1,782`, 중복 0건을 확인했다.
- 수집 실패·권한 부족·조직 기준 미등록·사용자 범위 미확인을 양호로 바꾸지 않았다.
- 공식 Finding, 원시 설정값, SID, 저장 장치 식별자와 이동 묶음은 저장하지 않았다.

## 실제 결과

| 구분 | 결과 |
|---|---:|
| 전체 | 18 |
| 양호 | 3 |
| 취약 | 1 |
| 정보 수집 오류 | 10 |
| 기준 확인 필요 | 4 |
| 해당 없음 | 0 |
| 잘못된 양호 판정 | 0 |

주요 보수적 판정:

- PC-07 저장 장치 조회가 이번 실행에서 권한 부족이었으므로 `ERROR`로 유지했다.
- IMP-037 관리자 수집은 원시값을 저장하지 않는 계약이므로, 값이 남아 있지 않은 PC-08도 양호로 추정하지 않고 `ERROR`로 처리했다.
- PC-09는 현재 사용자 설정만 확인됐고 조직 전체 사용자 범위가 확인되지 않아 `REVIEW`다.
- PC-16은 화면보호기 대기시간을 읽지 못해 예외 중단이나 양호가 아닌 `ERROR`다.
- PC-17은 자동실행 차단 설정이 기준에 미달해 `FAIL`이다.

## 합성 사례와 현재 PC 비교

합성 Fixture 92개는 PASS·FAIL·ERROR·REVIEW·N/A 경계를 모두 시험하기 위한 사례 모음이고, 현재 PC 결과 18개는 각 Control의 단일 실측 결과다. 입력 목적과 분포가 달라 합격률로 직접 비교하지 않는다.

## 안전·개인정보

- 실행 전후 설정 snapshot SHA-256 동일, 설정 변경 0건
- 읽기 전용 실행
- 자동 UAC 없음
- 개발 PC이며 clean VM 검증 아님
- Audit Pack `0.6.0` 상태 `DRAFT`
- 공식 Finding 생성 0건
- 원시값·SID·volume 식별자 영구 저장 0건
- portable/이동 묶음 생성 0건

## 검증

```text
tools\verify-imp038-current-host.ps1
PASS
Package validated: true
Normalized evidence: 20
Rule decisions / DRAFT Findings: 18 / 18
False PASS / duplicate Finding: 0 / 0
```

```text
tools\dev.ps1 -Action All
Pytest: 340 passed, Starlette deprecation warning 1
Schema: 9 schemas, 16 examples PASS
Ruff: PASS
mypy: 168 source files PASS
```

재빌드·실행 확인:

- `audit-api`, `audit-worker`, `audit-scheduler`를 현재 source로 재빌드·교체
- image ID: API `d6ee78c0eecd`, worker `f2ba1aa0be1b`, scheduler `cb3a6d6abf28`
- Core 8개 컨테이너 `healthy`
- `http://127.0.0.1:18480/ui/windows-evaluation` HTTP 200
- API 응답: IMP-038, DRAFT Finding 18, false PASS 0, duplicate 0

## 다음 단계

다음은 `IMP-039 — 현재 OS 제출·서명 공격시험`이다. 변조, 만료, nonce 재사용, replay, 다른 Asset, 잘못된 서명이 저장·판정으로 진입하지 못하는지 검증한다.
