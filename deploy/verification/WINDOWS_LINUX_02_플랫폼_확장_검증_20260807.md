# WINDOWS-LINUX-02 Windows·Linux 플랫폼 확장 검증

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-08-07 |
| 범위 | Windows 10·11 x64, Ubuntu 22.04·24.04, Debian 12, Rocky·RHEL·AlmaLinux 9 x64 |
| 제외 | Switch Adapter·수집·판정은 변경하지 않음 |
| 판정 경계 | Windows 10 `PARTIAL`, 신규 Linux 4종 `PILOT`; 실제 VM 인수 전 운영 완료 아님 |

## 1. 구현 결과

- Windows PowerShell Probe가 Registry의 `InstallationType`과 Build를 함께 확인해
  Windows 10·11 client를 구분한다. `Client`가 아닌 Server/DC 제품은 `UNSUPPORTED`로
  중단한다.
- Windows 10·11은 같은 PC 읽기 전용 Adapter를 사용하지만 Windows 10은 `PARTIAL`이다.
  Windows 11 전용 패치·수명 snapshot이 일치하지 않으면 PASS를 만들지 않는다.
- Linux는 `/etc/os-release`와 `uname -m`을 중앙과 실행 서버에서 각각 확인하고 exact
  Support Catalog 항목 한 개가 일치할 때만 실행한다.
- Ubuntu 22.04·Debian 12는 Debian 계열 계획, RHEL 9·AlmaLinux 9는 Rocky/RHEL 계열
  계획을 재사용한다. 사용자 입력 shell이나 자동 sudo는 추가하지 않았다.
- Manifest·Package JSON Schema와 PostgreSQL CHECK를 여섯 배포판에 맞췄다. migration은
  기존 revision을 수정하지 않고 `0035_platform_expansion`으로 추가했다.

## 2. 지원 상태

| 대상 | 상태 | 실제 환경 검증 |
|---|---|---|
| Windows 11 x64 | `SUPPORTED` | 기존 실제 호스트 근거 유지 |
| Windows 10 x64 | `PARTIAL` | 합성·계약시험만 완료 |
| Windows Server/DC | `UNSUPPORTED` | 전용 기준이 없어 의도적으로 차단 |
| Ubuntu 24.04 x64 | `SUPPORTED` | 기존 실제 VM 근거 유지 |
| Rocky Linux 9 x64 | `SUPPORTED` | 기존 실제 VM 근거 유지 |
| Ubuntu 22.04 x64 | `PILOT` | 합성·계약시험만 완료 |
| Debian 12 x64 | `PILOT` | 합성·계약시험만 완료 |
| RHEL 9 x64 | `PILOT` | 합성·계약시험만 완료 |
| AlmaLinux 9 x64 | `PILOT` | 합성·계약시험만 완료 |

## 3. 실행 검증

### 집중 회귀

```powershell
docker compose --project-directory . `
  -f deploy/compose/compose.yml `
  -f deploy/compose/compose.dev.yml `
  run --rm dev-tools -m pytest <관련 10개 시험 파일> -q
```

- 결과: 관련 회귀 `111 passed`, Starlette deprecation warning 1건
- PowerShell Windows 10·11/Server 경계와 hash 회귀: `25 passed`
- PowerShell parser: 변경 Probe 3개 구문 오류 0
- 확인 범위: 플랫폼 Resolver, Linux U 판정, Profile, Windows Probe·CVE 구성요소,
  Linux one-shot 수집·처리·제품 흐름, 도움말 계약

### 정적 검증

- 변경 Python 파일 Ruff: `All checks passed`
- 변경 운영 Python 19개 mypy: `Success: no issues found`
- 변경 JSON Schema 3개 Draft 2020-12 구조 검사: `3 schema contracts valid`
- Alembic source head: `0035_platform_expansion (head)`
- 개발 DB migration 적용 후 current: `0035_platform_expansion (head)`
- API image 재빌드·재기동 후 health/ready: `ok`, PostgreSQL·Redis·AIStor·ClamAV 모두 `true`

### 실행 파일·개발 다운로드

| 산출물 | SHA-256 | 확인 결과 |
|---|---|---|
| `SecAI-Collector-Windows-x64.exe` | `9a95c6e374c6ec50817a24af67b5fb096c5657d60a66a945b3d44d9bbadc9646` | 개발 Authenticode·timestamp, self-check, 변조 거부, ClamAV·Defender CLEAN |
| `secai-linux-check-x86_64` | `926b3dea030d40c60e5f9972d7bb6e5b019d188054c5baa42bfbcb442620b546` | Linux 6종 자동 식별 공용 파일, ClamAV CLEAN |
| `secai-linux-check-ubuntu24-x86_64` | `c1ac4230d4bc2d2c8f6118ec156c42f4dbeb4f5ee1cb9485c86b258d59af4ed8` | 이전 호환 파일, ClamAV CLEAN |
| `secai-linux-check-rocky9-x86_64` | `6ecf56b275e82f801072efbdb18c2d4893d8aba8fdb5fe843a6c59b6a2da7d37` | 이전 호환 파일, ClamAV CLEAN |

- Windows unsigned build: `runtime/imp034-artifacts/build-20260807T010833Z`, 10개 Gate PASS,
  pip-audit 알려진 취약점 0
- Windows 개발 서명: `runtime/imp035-artifacts/acceptance-20260807T010931Z`, 12개 구현
  Gate PASS, 조직 Publisher·운영 폐기·clean VM Gate는 DEFERRED
- Linux 최종 build: `runtime/linux-oneshot-artifacts/build-20260807T013114Z`
- Linux lock pip-audit: 알려진 취약점 0
- Linux builder Grype `0.116.1`, DB `v6.1.9`/2026-08-06: Critical 0, High 0,
  Medium 70, Low 130, Negligible 4, OpenVEX 적용 3
- 최종 Linux 세 artifact는 사전 검사 artifact와 SHA-256이 동일함을 확인했다.
- 최종 Windows signed EXE `self-check`: PASS, 수집·상승·설정 변경·Finding 0
- Linux 공용 파일은 network 없음·read-only·capability 없음 Ubuntu 24.04 container에서
  `--help` 시작 PASS
- 활성 개발 Catalog: `runtime/dev-signed-downloads/release-20260807T013323Z`, 네 artifact 모두
  `DEV-SIGNED-TEST`, `download_allowed=true`, 2026-08-14 만료

전체 Schema 예제 검증은 기존 `valid/finding_explanation_input.json`에
`evidence_trace`가 없는 별도 불일치로 중단됐다. 이번에 변경한 Linux Schema 세 개는 위의
독립 검사와 플랫폼 회귀시험을 통과했다. 관련 없는 예제를 이번 범위에서 수정하지 않았다.
전체 Ruff는 기존 `administrator_launcher.py`, `collector/cli.py`,
`build-full-guide-artifacts.py`의 import order 3건으로 중단됐으며, 이번 변경 파일 집중 Ruff는
모두 통과했다.

## 4. 남은 Gate

- Windows 10 clean VM에서 일반/관리자 Probe, 설정 diff 0, PDF·CVE 전체 흐름 인수
- Ubuntu 22.04, Debian 12, RHEL 9, AlmaLinux 9 각각의 실제 VM 정상·권한 부족·timeout 인수
- 신규 Linux 산출물의 조직용 Ed25519 release 서명
- 개발 Catalog 만료 전 재빌드·재검사·재서명
- 배포판별 KISA 적용성·패키지 관리 차이를 검토한 운영 Pack 승인

이 Gate를 통과하기 전 `PARTIAL/PILOT`을 `SUPPORTED` 또는 운영 완료로 바꾸지 않는다.
