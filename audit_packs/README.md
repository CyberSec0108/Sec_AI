# Audit Pack 관리 안내

이 폴더는 수집된 보안 상태를 어떤 기준으로 판정할지 정의하는 점검 기준 묶음(Audit Pack), 합성 시험 자료(Fixture), 제품별 상태 매핑과 기준 스냅샷을 보관합니다.

Audit Pack은 점검 명령을 실행하는 프로그램이 아닙니다. Collector가 읽기 전용으로 모은 자료를 정규화한 뒤, 규칙 엔진이 `PASS`, `FAIL`, `REVIEW`, `ERROR`, `N/A` 중 하나로 판단할 때 사용하는 버전 고정 계약입니다.

## 현재 구성

| 위치 | 역할 | 현재 상태 |
|---|---|---|
| [`kisa_2026_pc/`](kisa_2026_pc/README.md) | Windows PC-01~18 기준, 합성 Fixture, Adapter Catalog | `0.6.0 DRAFT` |
| [`kisa_2026_unix/`](kisa_2026_unix/README.md) | UNIX U-01~U-67 공통 기준과 Ubuntu/Rocky Adapter 준비 영역 | `2026-DRAFT` |
| `examples/` | 향후 공통 Pack 예제 예약 영역 | 현재 공용 예제 없음 |
| `schema/` | 향후 Pack 전용 보조 계약 예약 영역 | 정본 Schema는 `database/schemas`에 있음 |

현재 `APPROVED` 상태의 운영 Audit Pack은 없습니다. 개발 화면과 시험에서 보이는 판정은 DRAFT 기준을 명시적으로 선택한 개발 결과이며, 운영 공식 Finding으로 취급하면 안 됩니다.

## 전체 처리 흐름

```text
점검 기준 원문
  → guides/catalog.json                       원문 신원·해시 승인
  → guides/mappings/*.json                    Control 출처 연결 검토
  → audit_packs/<pack>/src/pack-<version>.json
  → 합성 Fixture·결정론·안전성 시험
  → 사람 검토·조직 서명·배포 승인
  → 규칙 엔진이 검증된 Evidence를 판정
```

다음 세 승인은 서로 다릅니다.

```text
Guide Catalog APPROVED
≠ Control Source Mapping APPROVED
≠ Audit Pack APPROVED
```

가이드가 내부 검색용으로 승인되어도 Mapping이나 Pack이 자동 승인되지 않습니다. LLM이 만든 Mapping, 규칙 또는 Fixture 제안도 사람 검토, Schema, 결정론 회귀, 서명과 승인 전에는 실행 가능한 규칙으로 등록하지 않습니다.

## Windows Pack 구조

```text
kisa_2026_pc/
├─ src/                       사람이 검토하는 버전별 Pack source
├─ fixtures/                  개인정보 없는 입력과 기대 결과
│  ├─ account_policy/
│  ├─ service_management/
│  ├─ patch_lifecycle/
│  ├─ endpoint_protection/
│  ├─ user_media_remote/
│  ├─ full_pack/
│  └─ pc07/                   개별 입력·기대 결과
├─ adapter_catalogs/          제품 상태를 공통 사실로 매핑하는 DRAFT 목록
└─ reference_snapshots/       외부 기준의 날짜·출처·해시 스냅샷
```

`src/pack.json`과 `src/pack-0.2.0.json`부터 `pack-0.6.0.json`까지는 각 시점의 재현 자료입니다. 이전 버전은 과거 결과 재현에 필요하므로 덮어쓰지 않습니다. 기준을 바꾸려면 새 버전 파일과 새 Fixture를 추가합니다.

## 파일을 수정할 때

### Control 또는 규칙 변경

1. KISA 원문과 승인된 Control Source Mapping을 확인합니다.
2. 기존 Pack을 수정하지 않고 다음 버전의 source를 추가합니다.
3. `content_sha256`은 `content_sha256`과 `approval`을 제외한 payload의 RFC 8785 JCS SHA-256으로 다시 계산합니다.
4. 양호, 취약, 수집 오류, 기준 부족, 적용 제외를 포함한 합성 Fixture를 갱신합니다.
5. Schema와 규칙 엔진 시험, 100회 결정론 회귀를 실행합니다.
6. 검토·서명이 끝나기 전까지 `approval.status`를 `DRAFT`로 유지합니다.

### Fixture 추가

- 실제 사용자명, 조직명, 서버 주소, 파일명, 토큰 또는 원본 명령 출력을 넣지 않습니다.
- 하나의 사례가 어떤 상태를 기대하는지 명확하게 기록합니다.
- 권한 부족, timeout, 파싱 실패를 취약 상태인 `FAIL`로 바꾸지 않습니다.
- Package 검증 실패 자료가 저장·정규화·판정 단계로 넘어가지 않는지도 확인합니다.
- `fixtures/index.json` 또는 해당 영역의 coverage 파일과 시험을 함께 갱신합니다.

### Adapter Catalog 또는 외부 기준 갱신

- 제품명만 보고 상태를 추측하지 않고 정확한 버전·원문 URL·조회일·해시를 고정합니다.
- 알 수 없는 상태는 안전하게 `REVIEW` 또는 `ERROR`로 남기며 임의의 `PASS`를 만들지 않습니다.
- 스냅샷의 과거 파일을 수정하지 않고 새 날짜 또는 새 버전을 추가합니다.

## 보안 및 승인 원칙

- Collector와 AI는 공식 Finding 상태를 만들거나 바꿀 수 없습니다.
- 수집 실패와 권한 부족은 취약 판정이 아닙니다.
- DRAFT Pack은 개발용 opt-in에서만 사용합니다.
- 조직·자산 범위, Pack ID·version·hash, Evidence hash가 모두 판정 입력에 결합되어야 합니다.
- Pack 서명과 SHA-256은 역할이 다릅니다. 해시 일치는 내용 무결성만 확인하며 승인자 신원을 증명하지 않습니다.
- `build/` 같은 생성물 위치가 생기더라도 사람이 관리하는 source를 수동 복사하지 않고 검증된 builder가 생성해야 합니다.

## 관련 구현

| 목적 | 위치 |
|---|---|
| Audit Pack JSON 계약 | [`../database/schemas/audit_pack.schema.json`](../database/schemas/audit_pack.schema.json) |
| Schema 설명·검증 | [`../database/schemas/README.md`](../database/schemas/README.md) |
| 정규화·적용성·규칙·Finding | [`../src/README.md`](../src/README.md) |
| 원문 Catalog·Mapping | [`../guides/README.md`](../guides/README.md) |
| Pack 계약 시험 | [`../tests/README.md`](../tests/README.md) |
| 단계별 검증 기록 | [`../deploy/verification/`](../deploy/verification/) |

## 검증 명령

Pack과 규칙 관련 단위·계약 시험:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Test
```

JSON Schema와 valid/invalid example 검증:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Schema
```

전체 표준 검증:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

Pack 변경은 관련 시험이 통과했다는 이유만으로 승인 완료가 되지 않습니다. 검증 결과, 검토자, source hash, 서명과 배포 상태를 별도 승인 기록에 남겨야 합니다.
