# KISA PC 합성 Fixture

기존 PC-07 17개 사례와 함께 `account_policy/cases.json`의 PC-01~03 10개 사례, `service_management/cases.json`의 PC-04~06·08~09 20개 사례, `patch_lifecycle/cases.json`의 PC-10~11 12개 사례, `endpoint_protection/cases.json`의 PC-12~15 18개 사례, `user_media_remote/cases.json`의 PC-16~18 15개 사례를 관리한다. 각 파일은 실제 기관·사용자·장비 식별정보가 없는 합성 자료다.

`full_pack/coverage.json`은 위 92개 사례를 최종 `0.6.0 DRAFT` Pack과 연결하는 IMP-026 통합 계약이다. PC-01~18 누락·중복, Pack의 Fixture 참조 불일치, 기대 결과와 실제 규칙 결과의 차이, 100회 반복 결과 지문 차이를 모두 실패로 처리한다.

Endpoint Protection 사례는 자동 로그인 암호 내용을 포함하지 않는다. PC-13~15의 제품 정보는 DRAFT Adapter Catalog와 맞춘 합성값이며, 합성 타사 방화벽은 대체 제품 분기시험 전용이다. 미지원 제품과 Defender 수동 모드는 `REVIEW`, 수집 실패는 `ERROR`로 고정한다.

PC-16~18 사례는 사용자명 없이 형식 시험용 합성 SID만 사용한다. PC-17의 내부 절차 ID도 합성값이다. Quick Assist와 원격 데스크톱은 PC-18 Windows Remote Assistance와 구분한다.

| 항목 | 값 |
|---|---|
| 구현 단계 | `IMP-012` |
| Fixture set version | `1.0.0` |
| Control | `PC-07` |
| Case 수 | 17 |
| 데이터 | 완전 합성, 실제 기관·사용자·파일 정보 없음 |
| Pack | `0.1.0` DRAFT |
| 기술 검증 | 8 Fixture·11 Rule Engine·6 Builder·5 Idempotency test·전체 133 Pytest PASS |
| 기대값 상태 | `PC07-FX-D01~D09` 승인 완료 |

## 1. 역할

이 Fixture는 PC-07 판정 코드를 만들기 전에 정상, 위반, 수집 오류와 예외 상황의 정답을 고정한다. 실제 Windows 수집 자료가 아니며 운영 증적으로 사용할 수 없다.

```text
pc07/input/*.json
  → 합성 normalized evidence 문서 집합

pc07/expected/*.json
  → IMP-015 규칙 엔진과 IMP-016 Finding Builder가 재현하는 decision projection

index.json
  → case ID·경로·RFC 8785 canonical SHA-256 연결
```

## 2. 기존 Schema와 Fixture envelope의 경계

`input/*.json`의 `evidence` 배열 각 항목은 `normalized_evidence.schema.json`을 통과한다. 입력 파일 전체는 여러 증적을 한 시험 case로 묶는 테스트 전용 envelope이므로 운영 API document Schema가 아니다.

`expected/*.json`은 상태·result code·평가·제외·위반 volume을 고정한 테스트 oracle이다. IMP-016은 이를 변경하지 않고 실행 중 Schema-valid Finding을 생성하며, actual/expected·citation·input/output hash는 Builder 집중시험에서 검증한다.

## 3. Hash 계약

`index.json`은 각 input과 expected JSON을 parsing한 뒤 RFC 8785 JCS로 canonicalize한 SHA-256을 기록한다. 화면 표시용 indentation, property 순서와 줄바꿈은 hash 의미에 영향을 주지 않는다.

```text
input_sha256    = SHA-256(JCS(parsed input JSON))
expected_sha256 = SHA-256(JCS(parsed expected JSON))
```

Fixture set `index.json` canonical SHA-256:

```text
74c7098bb08e63580bc10bfe99f514fb92341e256d6c7f21be503f7befb513e0
```

## 4. Case 분류

| 분류 | Case | 기대 상태 |
|---|---|---|
| 기본 | `pc07-pass` | PASS |
| 비-NTFS | `pc07-fail-fat32`, `pc07-fail-exfat` | FAIL |
| 수집·완전성 | `pc07-error-collection`, `pc07-error-filesystem-unknown`, `pc07-error-no-evaluated-volume` | ERROR |
| 정상 제외 | `pc07-excluded-efi`, `pc07-excluded-recovery` | PASS |
| ReFS | `pc07-edge-refs` | FAIL |
| VHD | `pc07-edge-vhd-ntfs`, `pc07-edge-vhd-fat32`, `pc07-edge-vhd-detached` | PASS/FAIL/PASS |
| Storage Spaces | `pc07-edge-storage-spaces-ntfs`, `pc07-edge-storage-spaces-refs` | PASS/FAIL |
| BitLocker | `pc07-edge-bitlocker-ntfs`, `pc07-edge-bitlocker-locked` | PASS/ERROR |
| mount folder | `pc07-edge-mounted-folder` | PASS |

ReFS의 `FAIL`은 ReFS가 취약하다는 뜻이 아니다. 승인된 KISA PC-07의 `NTFS` 일치 조건을 충족하지 않는다는 의미이며 `REFS_KISA_NTFS_CONDITION_MISMATCH`로 구분한다.

## 5. 재실행 가능한 시험

집중시험:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Test
```

Fixture 전용 시험 파일:

```text
tests/contract/test_pc07_fixtures.py
tests/unit/test_pc07_rule_engine.py
```

시험은 다음을 확인한다.

- 정확히 17개 case 존재
- strict UTF-8 JSON, 중복 key·BOM 거부
- evidence 항목의 normalized evidence Schema 통과
- index canonical hash 일치
- 승인된 상태·result code·제외 이유 일치
- 안정 ID·정렬·집합 관계
- 실제 사용자·조직·파일·secret field 부재
- DRAFT Pack의 기본 fixture reference 존재

## 6. 승인과 다음 단계

사용자는 17개 case와 `PC07-FX-D01~D09` 기대값을 승인했다. IMP-015 rule operator와 IMP-016 Finding Builder는 이 Fixture 전체를 통과한다. IMP-017은 대표 PASS input을 evidence 순서·실행 시각을 바꿔 100회 replay하고 하나의 Finding identity만 허용함을 확인했다. 다음 IMP-018은 이 pure 계약을 PostgreSQL 원자적 unique constraint로 강제한다.
