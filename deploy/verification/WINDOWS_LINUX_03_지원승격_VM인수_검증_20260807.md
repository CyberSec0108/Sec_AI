# WINDOWS-LINUX-03 Windows 10·추가 Linux 지원 승격 및 VM 인수 검증

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-08-07 |
| 지원 승격 | Windows 10 x64, Ubuntu 22.04 x64, Debian 12 x64, AlmaLinux 9 x64 |
| 유지 상태 | RHEL 9 x64 `PILOT`, Windows Server·Domain Controller `UNSUPPORTED` |
| 판정 경계 | 플랫폼 Adapter 지원 상태만 변경. KISA Audit Pack은 계속 `DRAFT`이며 공식 Finding이 아님 |

## 1. 구현 결과

- Windows 10은 Windows 11과 같은 PC-01~PC-18 읽기 전용 Adapter를 사용하는
  `SUPPORTED` 대상으로 변경했다. Windows 11 전용 patch·수명 근거가 맞지 않는 항목은
  `PASS`로 만들지 않고 `REVIEW` 또는 `ERROR`로 남긴다.
- Ubuntu 22.04, Debian 12와 AlmaLinux 9를 `PILOT`에서 `SUPPORTED`로 승격했다.
- RHEL 9는 Red Hat 구독으로 받은 공식 qcow2 경로와 별도로 확인한 SHA-256을 모두
  지정해야만 VM을 만들 수 있다. 이번 검증에는 공식 image가 없으므로 `PILOT`을 유지했다.
- 도움말 UI 계약을 `product-help-v5`로 올리고 실제 지원·시험 지원·미지원 경계를
  현재 Catalog와 맞췄다.

## 2. VM 자동화 보완

`deploy/vmware/rocky-lab.ps1`을 기존 Rocky 전용 경로에서 다음 배포판 Catalog를 받는
공통 cloud image 실습기로 확장했다.

- `Ubuntu22`, `Rocky9`, `Debian12`, `RHEL9`, `AlmaLinux9`
- 공개 image는 발행기관 checksum 목록을 먼저 내려받아 로컬 image hash와 일치할 때만
  qcow2/raw → VMware VMDK 변환
- RHEL은 자동 공개 다운로드 없이 `SourceImagePath`와 `SourceImageSha256` 필수
- NoCloud ISO로 `secai-lab` SSH key 계정과 초기 취약 기준 표식 생성
- VMware UI를 열지 않는 `nogui` 실행
- VMware Tools 주소 조회를 우선하고 고정 MAC ARP 조회를 보조로 사용
- Windows PowerShell에서 빈 SSH key 암호가 잘못 전달되지 않도록
  `ProcessStartInfo.ArgumentList`로 무암호 key 생성

Ubuntu 22.04의 `ubuntu-lab.ps1 -Version 22.04`는 같은 검증 경로로 위임한다. 최초 OVA
진단 과정에서 생성된 실패 VM과 암호가 잘못 붙은 시험 key는 삭제하지 않고
`.runtime/vmware` 안의 타임스탬프 실패 백업으로 이동했다.

## 3. 공식 image 확인

| 배포판 | image 확인 알고리즘 | 실제 확인값 | 결과 |
|---|---|---|---|
| Ubuntu 22.04 | SHA-256 | `bf4be84ed1cf255e8ef20e58db2ce0d1d565882c55e8c78fba0d25c6e32ef945` | Ubuntu `SHA256SUMS` 일치 |
| Debian 12 | SHA-512 | `3622c990108a044ed411652f8741e77c5822c365114d7b940206b243f8fb617b8586792df4cdb7afba1b71d1a09289d8ed632124688f2c8352cb08190a1e9868` | Debian `SHA512SUMS` 일치 |
| AlmaLinux 9 | SHA-256 | `c397eed7023e92c841155831b1f47e26300e5bef0f0256c129322307c897a251` | AlmaLinux `CHECKSUM` 일치 |

VM 주소, 개인키와 host 내부 식별정보는 검증 문서에 기록하지 않았다. image와 모든 VM
생성물은 source가 아닌 `.runtime/vmware` 아래에만 있다.
검증 종료 후 새 VM 세 대는 모두 안전 종료했고 `secai-initial-vulnerable` snapshot을
보존했다. 기존 Ubuntu 24.04·Rocky·Aruba VM의 실행 상태는 변경하지 않았다.

## 4. 실제 반복 점검

각 VM에서 중앙 SSH 점검기와 같은 고정 42개 read-only Probe를 실행해 U-01~U-67
결과를 두 번 만들었다. 논리 hash는 수집 시각을 제외하고 Control ID·상태·result code·
확인 요약·Evidence normalized SHA-256으로 계산했다.

| 배포판 | 두 실행 결과 | 판정 집계 | 논리 hash | 설정 hash 전후 |
|---|---:|---|---|---|
| Ubuntu 22.04 | 67 / 67, 수집 실패 `{}` | PASS 33, FAIL 10, ERROR 0, REVIEW 6, N/A 18 | `832458ddc3b6fcdd1e164e612d0bc1a271e7ebaf80838c9f2b70ced1a97b985f` 두 번 일치 | `7a68933498888dff7d41a4cbad501a1733083dd907772f85df7339443d9045e1` 일치 |
| Debian 12 | 67 / 67, 수집 실패 `{}` | PASS 32, FAIL 10, ERROR 0, REVIEW 7, N/A 18 | `d60021d856d3ebe93c20cad7f33d18dc7c5ef3ca4a7266aef8eccdde047b95ea` 두 번 일치 | `d6e6a352f95099ec045448cd63e3f4a0e6bad9f21c6b78a76140ffaef76b00ab` 일치 |
| AlmaLinux 9 | 67 / 67 | PASS 31, FAIL 10, ERROR 4, REVIEW 6, N/A 16 | `47c722daea426f35286dfec4929a9893b72222daa793df7602946bb3fc7438fe` 두 번 일치 | `f6ae1822033615090376d2b69af02688369b0a716174f4aa895f001824f6336a` 일치 |

AlmaLinux 최소 cloud image에는 `firewalld` executable과 DNF security cache가 없어
`linux.firewall-state`, `linux.firewall-rules`, `linux.pending-security-updates`가 두 실행
모두 `COMMAND_FAILED`였다. 관련 U-28·U-45·U-49·U-64를 `ERROR`로 보존했으며 부분
증적으로 `PASS`를 만들지 않았다. 이는 Adapter가 최소 image의 선택 구성요소 부재를
정확히 표시한 결과이며, 운영 server에서는 패키지 설치 상태에 따라 다시 판정해야 한다.

## 5. RHEL 안전 차단

다음처럼 공식 image와 확인값 없이 RHEL 준비를 요청한 실행은 의도한 오류로 중단됐다.

```text
RHEL 9는 Red Hat 구독으로 받은 qcow2 경로와 SHA-256을 함께 지정해야 합니다.
```

구독 제한을 우회한 URL, 미확인 mirror 또는 Alma/Rocky image로 RHEL 인수를 대신하지 않았다.

## 6. 코드 검증

- PowerShell parser: `ubuntu-lab.ps1`, `rocky-lab.ps1` 구문 오류 0
- 플랫폼 Catalog·VM 자동화 source 계약·도움말 집중 회귀: `19 passed`
- Linux 등록·제품·one-shot·Package·U 판정·다중 플랫폼 회귀: `84 passed`
- 변경 Python Ruff: `All checks passed`
- `discovery.py` strict mypy: `Success: no issues found`
- 같은 도움말 시험 파일 전체 실행에서 현재 홈 화면과 오래된 기대 문구가 다른 기존 시험
  2건(`PowerShell`, `3. KISA 근거 질문`)은 실패했다. 이번 지원 승격과 관계없어 시험을
  약화하거나 홈 화면을 되돌리지 않았다.

## 7. 남은 Gate

- Windows 10 clean VM 일반/관리자 Probe, 설정 diff 0, PDF·CVE 전체 사용자 흐름 인수
- RHEL 9 공식 구독 image 실제 반복 인수
- 지원 Linux의 권한 부족·timeout·locale·출력 상한 공격 회귀 확대
- 조직 서명, 운영 KMS/HSM, Audit Pack 승인과 실제 운영 server Pilot

`SUPPORTED`는 현재 Adapter가 exact 플랫폼을 수집·판정할 수 있다는 제품 지원 상태다.
운영 승인, 공식 취약 판정 또는 승인된 KISA Finding을 뜻하지 않는다.

## 8. 후속 runtime 정리

사용자 지시에 따라 인수 완료 뒤 보관했던 실패 VM 백업을 후속 정리했다.

- 실패 Ubuntu VM 5개와 연결된 실패·미생성 VM SSH key 삭제
- 성공 VM 생성 뒤 남은 재다운로드 가능한 Linux image cache 삭제
- 저장소에서 참조하지 않는 과거 U-01~U-67 임시 JSON과 Aruba 설정·확인 script 삭제
- 임시 GnuPG 확인 home 삭제
- 삭제 전 27개 exact 경로가 모두 `.runtime` 내부이며 실행 VM과 충돌하지 않음을 확인
- 총 `12,677,715,362 bytes`(`11.807 GiB`) 영구 삭제

성공 VM 6개, 새 Linux VM의 `secai-initial-vulnerable` snapshot, 성공 VM SSH key,
Compose bind용 `.runtime/linux-asset-keys`와 재구하기 어려운 Aruba 원본 OVA는 보존했다.
정리 후 실패·임시 파일명 패턴 잔여 0건, `.runtime` 전체 크기 `20.300 GiB`, API
health/ready와 PostgreSQL·Redis·AIStor·ClamAV 의존성은 모두 정상이다.
