# KISA 2026 PC 점검 기준 묶음

이 디렉터리는 2026 KISA `07. PC`의 실행 가능한 점검 기준 묶음(Audit Pack), 테스트 사례(Fixture)와 배포 생성물을 분리해 관리한다.

## 현재 상태

| 항목 | 상태 |
|---|---|
| 구현 단계 | `IMP-027` 단계 G 전체 시연·Gap review 완료 |
| 최신 테스트 범위 | `PC-01~18` |
| 최신 버전 | `0.6.0` |
| 승인 상태 | 검토 중 `(DRAFT)` |
| 계정 정책 테스트 사례 | 10개, 양호·취약·확인 필요·기준 확인 필요 |
| 서비스 관리 테스트 사례 | 신규 20개, 양호·취약·확인 필요·기준 확인 필요·해당 없음 |
| 패치·지원 수명 테스트 사례 | 신규 12개, 양호·취약·확인 필요 |
| 로그인·Endpoint 보호 사례 | 신규 18개, 양호·취약·확인 필요·기준 확인 필요 |
| 사용자·미디어·원격지원 사례 | 신규 15개, 양호·취약·확인 필요·기준 확인 필요 |
| PC-07 테스트 사례 | 기존 17개와 `0.1.0` 그대로 보존 |
| 전체 통합 Coverage | 18개 Control·92개 합성 사례·100회 결정론 회귀 |
| 단계 G 인수 | 8개 검사 PASS, false PASS 0건, 보류 Gap 5건 |

`src/pack-0.6.0.json`은 PC-01~18을 묶은 최신 개발용 기준이다. Pack과 Endpoint Protection Adapter Catalog 모두 `DRAFT`이며 합성시험에서만 사용한다. 이전 Pack은 과거 시연 재현을 위해 변경하지 않는다. 실제 승인자와 서명이 없으므로 운영 승인 상태로 표시하면 안 된다.

## 디렉터리 역할

```text
kisa_2026_pc/
├─ README.md
├─ src/
│  ├─ pack.json          # 기존 PC-07 0.1.0 재현 기준
│  ├─ pack-0.2.0.json    # PC-01~03과 PC-07 개발 기준
│  ├─ pack-0.3.0.json    # PC-01~09 개발 기준
│  ├─ pack-0.4.0.json    # PC-01~11 개발 기준
│  ├─ pack-0.5.0.json    # PC-01~15 개발 기준
│  ├─ pack-0.6.0.json    # PC-01~18 개발 기준
│  └─ controls/          # PC-01~18 확대 시 source 분리 예정
├─ adapter_catalogs/     # 제품별 정확한 상태 매핑과 지원 범위
├─ fixtures/             # 개인정보가 없는 테스트 입력·기대 결과
├─ reference_snapshots/  # 서명·승인 전 DRAFT 외부 기준 스냅샷
└─ build/                # 검증·서명된 생성물만 배치
```

`build/`에는 source를 수동 복사하지 않는다. 이후 builder가 canonical build를 생성하고 source hash, build hash와 서명을 기록한다.

## 현재 검증 파일

다음 시험이 버전별 기준 파일과 테스트 사례를 직접 검사한다.

```text
tests/contract/test_pc07_audit_pack.py
tests/contract/test_pc07_fixtures.py
tests/unit/test_pc07_rule_engine.py
tests/contract/test_imp021_account_policy_pack.py
tests/unit/test_imp021_account_policy_rule.py
tests/unit/test_imp021_account_policy_ui.py
tests/contract/test_imp022_service_management_pack.py
tests/unit/test_imp022_service_management_rule.py
tests/unit/test_imp022_service_management_ui.py
tests/contract/test_imp023_patch_lifecycle_pack.py
tests/unit/test_imp023_patch_lifecycle_rule.py
tests/unit/test_imp023_patch_lifecycle_ui.py
tests/contract/test_imp024_endpoint_protection_pack.py
tests/unit/test_imp024_endpoint_protection_rule.py
tests/unit/test_imp024_endpoint_protection_ui.py
tests/contract/test_imp025_user_media_remote_pack.py
tests/unit/test_imp025_user_media_remote_rule.py
tests/unit/test_imp025_user_media_remote_ui.py
```

전체 자동시험:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Test
```

Schema example 검증:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Schema
```

## Content hash profile

`content_sha256`은 자기 자신과 승인 envelope를 제외한 Pack payload의 RFC 8785 JCS SHA-256이다.

```text
JCS(pack - {content_sha256, approval}) → SHA-256
```

`approval`이 `DRAFT`에서 `APPROVED`로 바뀌어도 payload가 같으면 content hash는 같다. 반대로 Control parameter, 원문 hash, target 또는 rule version이 바뀌면 content hash가 달라져야 한다.

## 다음 단계 경계

PC-01~18은 테스트 데이터에서만 판정하며 실제 Windows 자료를 사용하지 않는다. `IMP-027` 단계 G 시연·Gap review는 false PASS와 차단 결함 0건으로 통과했지만 실제 수집·운영 서명·Pack 승인은 5개 보류 Gap으로 남겼다. 다음은 `IMP-028` Mock Collector·Manifest verifier이며 자동 조치는 아직 진행하지 않는다.
