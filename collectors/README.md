# Collector 소스 관리 안내

이 폴더는 Windows 10·11 PC와 지원 Linux 서버의 상태를 읽기 전용으로 수집하는 원샷 Collector 진입점, 허용 Probe 계약, 안전 정책과 합성 시험 자료를 보관합니다.

Collector의 역할은 사실을 모아 검증 가능한 Package로 만드는 것까지입니다. 취약 여부를 공식 판정하거나 설정을 자동 변경하지 않습니다.

## 한눈에 보는 구조

```text
collectors/
└─ one_shot/
   ├─ entrypoint.py                    Windows 실행 진입점
   ├─ linux_entrypoint.py              Linux 공통 실행 진입점
   ├─ linux_ubuntu24_entrypoint.py     이전 Ubuntu 24.04 산출물 호환 진입점
   ├─ linux_rocky9_entrypoint.py       이전 Rocky Linux 9 산출물 호환 진입점
   ├─ contracts/                       Probe 허용 목록·안전·제출·UI 계약
   ├─ probes/windows/powershell/       고정된 읽기 전용 PowerShell Probe
   ├─ fixtures/                        개인정보 없는 합성 Manifest·수집 사례
   └─ build/windows_version_info.txt   Windows 실행 파일 version resource 입력
```

실제 수집·Package·서명·제출 로직은 [`../src/security_audit/collector/`](../src/security_audit/collector/)와 [`../src/security_audit/supply_chain/`](../src/security_audit/supply_chain/)에 있습니다. 이 폴더의 진입점은 빌드 도구가 사용할 얇은 실행 경계입니다.

## 실행 흐름

```text
사용자 점검 요청
  → 서명·만료·대상·nonce가 검증된 Manifest
  → OS와 권한 수준 확인
  → exact allowlist에 등록된 읽기 전용 Probe만 실행
  → 시간·출력 크기·프로세스 트리 제한 적용
  → Evidence 또는 안전한 수집 오류 생성
  → hash가 결합된 Package 생성
  → 온라인 credential 또는 오프라인 조직 서명으로 제출
```

사용자가 중앙 웹에서 파일을 내려받는 개발 시험은 Collector source 자체를 직접 제공하지 않습니다. 빌드·SBOM·악성코드 검사·서명 Catalog를 통과한 산출물만 다운로드 영역에 준비합니다.

## 일반 권한과 추가 권한

Windows 점검은 일반 권한 항목과 관리자 동의가 필요한 추가 항목을 분리합니다.

- 일반 점검은 자동으로 UAC를 띄우지 않습니다.
- 추가 점검은 실행할 항목과 필요한 이유를 먼저 보여줍니다.
- 사용자가 별도로 동의한 항목만 사용자 요청 UAC로 실행합니다.
- UAC를 취소해도 이미 모은 일반 점검 결과를 보존합니다.
- 선택하지 않은 관리자 Probe를 실행하지 않습니다.

Linux 원샷 점검은 사용자가 자신의 Ubuntu 22.04·24.04, Debian 12,
Rocky·RHEL·AlmaLinux 9 x64 서버에서 실행하는 개발 흐름입니다. 공용 실행 파일이
`/etc/os-release`와 아키텍처를 확인해 정확한 Adapter를 고르며, 지원하지 않거나 불일치하면
추측 실행하지 않습니다. Ubuntu 22.04·24.04, Debian 12, Rocky 9, AlmaLinux 9는 실제 VM
반복 인수를 통과한 `SUPPORTED`이며 RHEL 9만 공식 구독 이미지 인수 전 `PILOT`입니다.
AlmaLinux 최소 image처럼 선택 구성요소가 없으면 관련 Probe는 `ERROR`로 남기고 양호로
바꾸지 않습니다. SSH 중앙 점검과 개인 원샷 실행은 인증·자산 등록 경계가 다른 별도
흐름입니다.

## 계약 파일 읽는 법

`contracts/`의 JSON은 단계별로 누적된 안전 경계를 고정합니다.

| 파일 묶음 | 내용 |
|---|---|
| `imp028~031_*` | Manifest, Probe allowlist, 프로세스 안전, PC-01~18 범위 |
| `imp032~033_*` | 온라인 1회용 credential과 오프라인 조직 서명 제출 |
| `imp034~035_*` | native build, SBOM, 취약점·악성코드·서명 Release Gate |
| `imp040~043_*` | 1클릭 실행, 진행·취소·결과, 관리자 별도 동의 |
| `product_ai_01_*` | AI 설명에 전달할 수 있는 제한된 결과 출처 |

과거 계약은 재현 자료이므로 덮어쓰지 않습니다. 동작을 바꾸려면 새 계약 버전과 회귀시험을 추가하고 기존 버전과의 호환 여부를 기록합니다.

## Probe 작성 원칙

- 임의 명령 문자열, shell expression, 사용자가 입력한 raw command를 실행하지 않습니다.
- executable, 인수, 환경 변수와 출력 parser를 exact allowlist로 고정합니다.
- 설정 조회만 수행하며 registry, service, firewall, 계정, 파일 권한을 변경하지 않습니다.
- Probe별 timeout, 최대 출력 크기와 process tree 종료를 적용합니다.
- 표준 출력 전체 대신 판정에 필요한 최소 사실만 구조화합니다.
- 비밀번호, token, cookie, private key, 개인 식별값을 수집하거나 로그에 남기지 않습니다.
- 권한 부족·미지원·조회 실패를 `FAIL`로 만들지 않고 명확한 수집 상태로 보존합니다.

PowerShell Probe를 수정한 경우 실행 전후 설정 diff 0, 일반/관리자 권한 경계, timeout과 취소 동작을 함께 검증해야 합니다.

## 빌드와 산출물

사람이 수정하는 source와 생성 산출물을 분리합니다.

| 구분 | 위치 |
|---|---|
| Collector source·계약 | `collectors/`, `src/security_audit/collector/` |
| 빌드·서명 도구 | [`../tools/README.md`](../tools/README.md) |
| dependency lock | [`../requirements/README.md`](../requirements/README.md) |
| Docker build 정의 | [`../deploy/README.md`](../deploy/README.md) |
| 로컬 빌드·다운로드 산출물 | `runtime/` 아래의 Git 제외 영역 |
| 검증 기록·SBOM 상태 | [`../deploy/verification/`](../deploy/verification/) |

실행 파일, private key, 인증서 password, 실제 Package와 VM 자료를 이 폴더에 넣지 않습니다. 개발용 서명은 운영 신뢰를 뜻하지 않으며 조직 서명 Gate를 대신하지 않습니다.

## 주요 명령

Windows Collector 관련 집중시험은 해당 `tools/verify-imp*.ps1`을 사용합니다. Linux 원샷 build는 다음 진입점을 사용합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build-linux-oneshot.ps1
```

Windows native build는 승인된 Windows 환경에서 다음 스크립트로 수행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build-imp034-windows-collector.ps1
```

실행파일 내부 구성, 처음부터 다시 만드는 절차, version·Probe·의존성 변경 후 재빌드와
서명·검증 산출물은
[`SecAI Windows 실행파일 구성·빌드·재현 상세 가이드`](../docs/maintenance/SecAI_Windows_실행파일_빌드_구성_재현_가이드.md)를
따릅니다.

일반 코드·계약 회귀:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Test
```

실제 호스트나 VM에서 실행하는 시험은 설정을 변경하지 않는지 별도 snapshot/diff로 확인해야 합니다. 자세한 Linux VM 절차는 [`../docs/guides/Linux_원샷_VM_시험_안내.md`](../docs/guides/Linux_원샷_VM_시험_안내.md)를 따릅니다.

## 변경 전 체크리스트

- [ ] 지원 OS와 권한 수준이 계약에 명확히 적혀 있습니다.
- [ ] 새 Probe가 exact allowlist에 등록되어 있습니다.
- [ ] timeout·출력 크기·취소·process tree 종료를 시험했습니다.
- [ ] 실제 비밀정보나 개인 식별값을 Fixture에 넣지 않았습니다.
- [ ] 수집 오류를 취약 판정으로 오분류하지 않습니다.
- [ ] 기존 계약·Pack·Finding 재현성을 깨지 않습니다.
- [ ] build hash, SBOM, CVE, 악성코드와 서명 상태를 검증했습니다.

