# SecAI Windows 실행파일 구성·빌드·재현 상세 가이드

> 현재 기준: 일반 사용자 다운로드는 Windows artifact와 Linux 공용 자동 식별 artifact를 제공한다. Ubuntu 24.04·Rocky 9 전용 Linux 파일은 호환 Catalog 검증용으로 함께 보존한다. 아래 `IMP-034/035` 명칭은 현재 build 도구 파일명과 과거 인수 이력이다.

| 항목 | 내용 |
|---|---|
| 문서 목적 | 다른 개발자나 코딩 에이전트가 현재 source만 보고 Windows 실행파일을 다시 만들고 검증할 수 있게 설명 |
| 기준일 | 2026-08-07 |
| 대상 파일 | `SecAI-Collector-Windows-x64.exe` |
| 현재 제품 version | `0.1.0` |
| 대상 OS·CPU | Windows 10·11 x64·AMD64; 둘 다 공통 PC Adapter `SUPPORTED` |
| 패키징 | CPython 3.14.6 + PyInstaller 6.21.0 one-file |
| 현재 배포 상태 | 개발용 `DEV-UNSIGNED` 또는 `DEV-SIGNED-TEST`; 운영 배포본 아님 |
| 가장 중요한 빌드 명령 | `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build-imp034-windows-collector.ps1` |

## 1. 이 문서로 할 수 있는 일

이 문서는 다음 질문에 답합니다.

1. SecAI Windows 실행파일이 설치 프로그램인지 단일 실행파일인지
2. EXE 안에 어떤 코드·Python Runtime·설정·Probe가 들어가는지
3. 어떤 파일이 빌드 입력이고 어떤 파일이 산출물인지
4. 새 Windows 11 개발 PC에서 어떻게 같은 절차로 다시 만드는지
5. 빌드 결과가 정상인지 어떤 영수증으로 확인하는지
6. 개발용 Authenticode 서명과 웹 다운로드 묶음을 어떻게 만드는지
7. source·Probe·의존성·version을 바꾼 뒤 무엇을 함께 갱신해야 하는지
8. 자주 발생하는 오류를 어떻게 구분하는지

과거 실행파일의 SHA-256을 그대로 복제하는 것이 목표는 아닙니다. 같은 source·lock·도구와
검증 절차로 새 산출물을 만들고, 그 산출물의 새 SHA-256과 계보를 남기는 것이 목표입니다.

## 2. 먼저 이해할 결론

### 2.1 설치 프로그램이 아니다

현재 `SecAI-Collector-Windows-x64.exe`는 MSI·MSIX·Setup EXE 형태의 설치 프로그램이
아닙니다. 레지스트리에 제품을 설치하거나 Windows Service·Scheduled Task를 등록하는
구조도 아닙니다.

현재 형태는 다음과 같습니다.

```text
Python source와 dependency
  + 고정 PowerShell Probe
  + 계약·Schema·DRAFT 기준 자료
  + CPython Runtime
  + PyInstaller bootloader
→ Windows x64 단일 EXE
```

사용자가 EXE를 실행하면 PyInstaller one-file bootloader가 필요한 파일을 실행 중 임시
디렉터리에 풀고 Python 진입점을 실행합니다. 프로그램 종료 뒤 임시 실행 자료는 PyInstaller
수명주기를 따릅니다. 설치 마법사, 설치 경로 선택, 제거 프로그램은 없습니다.

### 2.2 EXE 하나만으로 모든 SecAI 서버가 들어가는 것은 아니다

EXE는 현재 Windows PC의 보안 상태를 읽는 Collector와 localhost Launcher입니다. 다음
중앙 기능은 EXE 안에 들어가지 않습니다.

- FastAPI Web/API 서버
- PostgreSQL·pgvector
- Redis·Worker·Scheduler
- AIStor·ClamAV 서버
- Model Gateway·OpenRouter·vLLM
- 전체 Web template와 사용자 계정 DB

더블클릭한 EXE는 기본적으로 `http://localhost:18480`의 SecAI 중앙 화면과 연결합니다.
따라서 사용자가 점검을 시작하려면 해당 PC에서 중앙 서비스가 실행 중이어야 합니다.
`self-check` 명령만 중앙 서비스 없이 단독 실행할 수 있습니다.

### 2.3 현재 개발 파일은 운영 설치본이 아니다

빌드 단계별 의미는 다음과 같습니다.

| 단계 | 결과 | 의미 |
|---|---|---|
| IMP-034 | `DEV-UNSIGNED` EXE | 단일 EXE 생성·SBOM·취약점·악성코드 검사 완료, 전자서명 없음 |
| IMP-035 | 개발용 Authenticode EXE | 서명 기술 검증용 self-signed Publisher, 다른 PC의 신뢰 보장 아님 |
| DEV-SIGNED-TEST | Authenticode EXE + Ed25519 Catalog | 로그인·1회용 코드 기반 개발 다운로드 시험 |
| 운영 Release | 현재 없음 | 조직 인증서·Publisher·CRL/OCSP·clean VM·SmartScreen Gate 필요 |

### 2.4 과거 IMP-034 계약과 현재 실행 동작을 구분한다

`collectors/one_shot/contracts/imp034_native_build_policy.json`의
`actual_collection_cli_enabled=false`는 IMP-034 최초 native build에서 self-check만 검증하던
당시 경계를 보존한 과거 계약입니다. 현재 `src/security_audit/collector/cli.py`에는 실제
`launch`와 사용자 동의형 `administrator-launch`가 구현되어 있습니다.

따라서 현재 실행파일 동작은 source와 현재 Launcher 시험을 정본으로 판단합니다. 과거 계약을
현재에 맞춰 조용히 덮어쓰지 않으며, 운영 Release에서는 현재 기능을 반영한 새 build/release
계약 version과 acceptance가 필요합니다.

## 3. 전체 구조 한눈에 보기

```text
사람이 관리하는 source
├─ collectors/one_shot/entrypoint.py
├─ src/security_audit/collector/
├─ src/security_audit/application/의 Windows 점검 관련 모듈
├─ collectors/one_shot/contracts/
├─ collectors/one_shot/probes/windows/powershell/
├─ database/schemas/
├─ DRAFT Pack·Reference·Adapter·Guide Mapping 4종
├─ requirements/collector-build.in
├─ requirements/lock/collector-build.lock
└─ collectors/one_shot/build/windows_version_info.txt
                   │
                   ▼
tools/build-imp034-windows-collector.ps1
  ├─ 정확한 CPython 3.14.6 준비
  ├─ hash lock으로 builder venv 구성
  ├─ tools/build_imp034_collector.py 호출
  ├─ PyInstaller one-file build
  ├─ self-check·PE32+ AMD64 검사
  ├─ CycloneDX SBOM·pip-audit
  ├─ ClamAV·Microsoft Defender
  └─ manifest·acceptance·SHA256SUMS 생성
                   │
                   ▼
runtime/imp034-artifacts/build-<UTC>/
                   │
                   ├─ 여기서 중지: DEV-UNSIGNED
                   │
                   ▼
tools/sign-imp035-windows-collector.ps1
  ├─ 개발용 RSA 3072 Code Signing 인증서 생성
  ├─ SHA-256 Authenticode + timestamp
  ├─ 변조 거부·self-check
  ├─ 서명 후 ClamAV·Defender
  └─ 임시 인증서·private key 제거
                   │
                   ▼
runtime/imp035-artifacts/acceptance-<UTC>/
                   │
                   ▼ 선택 단계
tools/prepare-dev-signed-downloads.ps1
  ├─ Windows·Linux 공용·Ubuntu 호환·Rocky 호환 파일 hash 검증
  ├─ Ed25519 개발 Catalog 서명
  └─ 웹 다운로드용 활성 release pointer 생성
```

## 4. EXE 내부 구성

### 4.1 PyInstaller 실행 계층

PyInstaller가 만드는 실행파일은 대략 다음 구성으로 이해할 수 있습니다.

```text
SecAI-Collector-Windows-x64.exe
├─ Windows AMD64 PyInstaller bootloader
├─ CPython 3.14.6 Runtime
├─ 사용되는 Python 표준 라이브러리
├─ SecAI Python 모듈과 import graph
├─ Collector dependency와 전이 dependency
├─ resources/
│  ├─ embedded-resources.json
│  ├─ collectors/one_shot/contracts/*.json·*.ps1
│  ├─ collectors/one_shot/probes/windows/powershell/*.ps1
│  ├─ database/schemas/**/*.json
│  ├─ DRAFT Audit Pack
│  ├─ Microsoft reference snapshot
│  ├─ endpoint protection Adapter Catalog
│  └─ KISA PC Control Source Mapping
└─ Windows version resource
```

PyInstaller 내부 binary 구조를 직접 편집하지 않습니다. EXE 안에 넣을 code와 data는
`tools/build_imp034_collector.py`의 PyInstaller 인수와 resource 선택 규칙으로 결정합니다.

### 4.2 실행 진입점

최초 진입 파일은 다음과 같습니다.

```text
collectors/one_shot/entrypoint.py
```

이 파일은 얇은 wrapper이며 실제 CLI로 위임합니다.

```text
collectors/one_shot/entrypoint.py
→ security_audit.collector.cli.main()
```

실제 명령 처리 파일:

```text
src/security_audit/collector/cli.py
```

지원 명령:

| 명령 | 역할 |
|---|---|
| 인수 없음 | `launch`와 동일하게 SecAI Launcher 시작 |
| `launch` | self-check 후 localhost bridge와 중앙 제품 화면 연결 |
| `self-check` | Python Runtime·Windows AMD64·포함 resource hash만 확인 |
| `administrator-launch` | 사용자가 선택·동의한 관리자 Probe만 별도 UAC 프로세스로 실행하는 내부 명령 |
| `--version` | Collector version 표시 |

`administrator-launch`는 일반 사용자가 임의 Probe를 넣지 못하도록 `argparse` 선택값과 내부
allowlist로 제한합니다.

### 4.3 포함되는 Python code

PyInstaller는 다음 두 방식으로 code를 포함합니다.

1. `entrypoint.py`에서 시작되는 정적 import graph
2. `--collect-submodules security_audit.collector`로 Collector package 하위 모듈 수집

대표 포함 영역:

- `src/security_audit/collector/cli.py`
- `src/security_audit/collector/launcher.py`
- `src/security_audit/collector/administrator_launcher.py`
- `src/security_audit/collector/windows.py`
- `src/security_audit/collector/expanded.py`
- `src/security_audit/collector/process.py`
- `src/security_audit/collector/safety.py`
- `src/security_audit/collector/allowlist.py`
- `src/security_audit/collector/manifest.py`
- Launcher에서 import하는 Windows 결과·기준·설명용 application 모듈

`apps/api` 전체를 EXE에 복사하는 방식이 아닙니다. PyInstaller 분석에서 실제로 import되는
모듈과 명시적으로 수집한 Collector 하위 모듈만 binary bundle 대상입니다.

### 4.4 Python dependency

사람이 관리하는 Windows Collector 직접 의존성은 다음 파일에 있습니다.

```text
requirements/collector.in
```

현재 주요 직접 의존성:

| dependency | 역할 |
|---|---|
| HTTPX | 제한된 HTTP 통신 계약 |
| JSON Schema | Manifest·Package 계약 검증 |
| Pydantic | 입력·출력 DTO 검증 |
| RFC 8785 | canonical JSON과 결정론적 hash 입력 |

빌드 도구 의존성은 다음 파일에서 Collector runtime 의존성을 포함하고 PyInstaller를
추가합니다.

```text
requirements/collector-build.in
requirements/lock/collector-build.lock
```

현재 PyInstaller는 정확히 `6.21.0`입니다. 실제 설치는 항상 `collector-build.lock`의 모든
전이 dependency와 artifact SHA-256을 `--require-hashes`로 검증합니다.

### 4.5 포함되는 data resource

`tools/build_imp034_collector.py`는 `.json`, `.ps1` 중 다음 root 아래 파일을 재귀적으로
선택합니다.

```text
collectors/one_shot/contracts/
collectors/one_shot/probes/windows/powershell/
database/schemas/
```

그리고 다음 4개 파일을 명시적으로 추가합니다.

```text
audit_packs/kisa_2026_pc/src/pack-0.6.0.json
audit_packs/kisa_2026_pc/reference_snapshots/microsoft_windows_11/2026-07-23.json
audit_packs/kisa_2026_pc/adapter_catalogs/endpoint_protection/0.1.0.json
guides/mappings/kisa_2026_pc_control_sources.json
```

2026-08-07 source 기준 선택 수는 다음과 같습니다.

| 구분 | 파일 수 |
|---|---:|
| Collector 계약 | 14 |
| Windows PowerShell Probe | 6 |
| `database/schemas` 아래 JSON | 86 |
| 명시적 DRAFT·Reference·Mapping | 4 |
| 합계 | 110 |

이 숫자는 source가 바뀌면 달라질 수 있습니다. 새 빌드의 정본은 EXE 옆에 생성되는
`*.embedded-resources.json`과 `self-check`의 `embedded_resources_verified` 값입니다.

각 resource에는 다음 정보가 기록됩니다.

```json
{
  "path": "프로젝트 루트 상대경로",
  "sha256": "64자리 SHA-256",
  "bytes": 1234
}
```

실행할 때 EXE는 PyInstaller 임시 root의 `resources/embedded-resources.json`을 읽고 실제
포함 파일의 크기와 SHA-256을 전부 다시 계산합니다. 하나라도 다르면 `self-check`가
`FAIL`입니다.

### 4.6 source snapshot과 실제 embedded resource는 다르다

builder는 build 계보를 위해 다음 입력의 경로·크기·SHA-256을 정렬해 하나의
`source_snapshot_sha256`을 만듭니다.

```text
src/security_audit/ 전체
collectors/one_shot/ 전체
database/schemas/ 전체
requirements/lock/collector-build.lock
requirements/collector-build.in
pyproject.toml
명시적 DRAFT·Reference·Mapping 4종
```

source snapshot에 들어갔다고 모든 파일이 EXE에 포함되는 것은 아닙니다. 실제 Python code는
PyInstaller import graph, 실제 data는 앞 절의 resource 목록으로 결정됩니다.

현재 snapshot은 `tools/build_imp034_collector.py`와 PowerShell wrapper 자체를 결합 hash에
포함하지 않고 Git revision도 `UNAVAILABLE_NO_GIT_CLIENT`로 기록합니다. 개발 재현에는 현재
방식으로 충분하지만 정식 Release provenance에서는 승인 Git commit과 builder script hash를
추가로 고정해야 합니다.

### 4.7 Windows version resource와 아이콘

Windows 탐색기의 파일 속성에 들어가는 값은 다음 파일에서 가져옵니다.

```text
collectors/one_shot/build/windows_version_info.txt
```

현재 포함 정보:

- Company: `Sec_AI Project`
- Description: `Sec_AI Windows One-shot Security Collector`
- Product: `Sec_AI MVP`
- File version·Product version: `0.1.0`
- Original filename: `SecAI-Collector-Windows-x64.exe`

현재 PyInstaller 인수에는 `--icon`이 없습니다. 따라서 프로젝트 전용 `.ico`를 EXE에
명시적으로 넣는 구조는 아직 아닙니다. 웹 화면의 파란색 다운로드 아이콘은 HTML/CSS의 UI
표시이며 EXE 자체 아이콘과 별개입니다.

## 5. EXE에 포함되지 않는 것

다음 자료는 의도적으로 실행파일에 포함하지 않습니다.

- 실제 `.env`
- password·token·cookie·private key·인증서 password
- `runtime/dev-secrets`
- 실제 사용자명·조직명·자산 UUID
- 실제 수집 Package와 원본 Evidence
- PostgreSQL·Redis·AIStor data
- KISA·기관 원본 PDF 전체
- OpenRouter API key와 모델 weight
- Docker image·VM image
- 개발 서명용 private key
- 과거 `runtime/imp034-artifacts`와 `runtime/imp035-artifacts`

빌드 resource 선택은 `.json`과 `.ps1` allowlist 및 명시 파일로 제한됩니다. `.pem`, `.pfx`,
`.key`, `.env` 등을 root 안에 우연히 두더라도 정상 정책상 포함 대상이 아닙니다.

## 6. 실행 시 동작

### 6.1 더블클릭 또는 `launch`

```text
사용자가 EXE 실행
→ frozen self-check
→ 127.0.0.1:18481 Launcher bridge 생성
→ 일회용 launcher token 생성
→ http://localhost:18480/ui/launcher-connect#launcher_token=... 열기
→ 사용자가 웹에서 "내 PC 점검하기" 선택
→ 일반 권한 15개 Probe 읽기 전용 실행
→ 진행·취소·결과를 localhost bridge로 교환
```

허용 중앙 Origin은 다음 둘뿐입니다.

```text
http://127.0.0.1:18480
http://localhost:18480
```

Launcher bridge는 `127.0.0.1`에만 열립니다. 다른 PC에서 포트로 직접 접근하는 서버가
아닙니다. 기존 Launcher가 18481을 사용 중이면 내부 고정 token이 있는 재실행 요청으로
기존 Launcher를 종료한 뒤 새 실행으로 교체합니다. 관련 없는 프로세스가 포트를 사용하면
안전하게 중단합니다.

### 6.2 일반 권한 점검

- 자동 UAC를 띄우지 않습니다.
- 고정된 일반 권한 Probe 15개만 실행합니다.
- PowerShell executable·script·인수를 source allowlist로 제한합니다.
- timeout·출력 크기·process tree 종료를 적용합니다.
- 점검 전후 설정 diff가 0이 아니면 결과를 정상으로 인정하지 않습니다.
- 권한 부족·미지원·수집 실패를 보안 취약 `FAIL`로 변환하지 않습니다.

### 6.3 관리자 추가 점검

```text
웹 화면에서 관리자 항목과 이유 표시
→ 사용자가 항목 선택·별도 동의
→ 같은 EXE를 administrator-launch로 사용자 요청 UAC 실행
→ 127.0.0.1:18482 관리자 결과 bridge 생성
→ 선택한 관리자 Probe만 실행
→ 결과 화면으로 반환
```

UAC 취소 시 일반 점검 결과는 유지됩니다. 관리자 프로세스는 고정 `CONSENT_VERSION`, 허용된
Probe ID, 검증된 기준 context와 일회용 result token을 요구합니다.

### 6.4 `self-check`

`self-check`는 실제 PC 보안 설정을 읽지 않습니다.

확인 항목:

- PyInstaller frozen 실행 여부
- 내장 Python이 정확히 3.14.6인지
- Windows AMD64인지
- embedded resource manifest 유효성
- 모든 resource의 파일 크기와 SHA-256
- 실제 수집이 시작되지 않았는지
- 설정 변경과 공식 Finding 생성이 없는지

실행:

```powershell
.\SecAI-Collector-Windows-x64.exe self-check
```

정상 결과의 핵심 값:

```text
status = PASS
frozen_runtime = true
python_runtime = 3.14.6
target.os = Windows
target.architecture = AMD64
resource_failures = []
settings_modified = false
actual_collection_started = false
official_finding_created = false
```

## 7. 빌드 도구별 책임

### 7.1 `build-imp034-windows-collector.ps1`

사람이 실행하는 기본 wrapper입니다.

책임:

1. 프로젝트 루트를 script 위치에서 계산
2. `runtime/imp034-python3146`에 정확한 CPython 3.14.6 준비
3. `runtime/imp034-builder-venv` 준비·복구
4. `collector-build.lock`을 `--require-hashes`로 설치
5. `pip check`
6. Python builder 호출
7. SBOM·pip-audit
8. ClamAV·Defender
9. unsigned Authenticode 상태 확인
10. 최종 acceptance 생성

### 7.2 `build_imp034_collector.py`

실제 PyInstaller 인수를 만들고 native EXE를 생성합니다.

현재 주요 옵션:

```text
--name SecAI-Collector-Windows-x64
--onefile
--console
--noupx
--clean
--noconfirm
--paths <project>/src
--collect-submodules security_audit.collector
--version-file collectors/one_shot/build/windows_version_info.txt
```

resource마다 `--add-data`가 추가됩니다. Windows에서 PyInstaller data 구분자는 `;`이며
Python의 `os.pathsep`를 사용하므로 script에 직접 구분자를 하드코딩하지 않습니다.

빌드 시 다음 환경도 설정합니다.

```text
PYTHONHASHSEED=0
SOURCE_DATE_EPOCH=1784793600
```

이는 입력 순서와 일부 생성 metadata를 안정화하지만 모든 Windows build의 EXE SHA-256이
영원히 같다는 보장은 아닙니다. Builder OS, bootloader, 서명, timestamp와 build tool
차이 때문에 새 build hash가 달라질 수 있습니다.

### 7.3 `finalize_imp034_collector.py`와 `collector_build.py`

다음 10개 Gate를 모두 확인합니다.

1. Windows 11 x64 native builder
2. CPython 3.14.6·PyInstaller 6.21.0
3. hash-locked dependency와 lock hash
4. PE32+ AMD64 one-file·100MiB 이하
5. 별도 Python 없는 frozen self-check·resource hash
6. CycloneDX SBOM과 exact lock component 일치
7. pip-audit 알려진 dependency 취약점 0
8. ClamAV·Microsoft Defender `CLEAN`
9. IMP-034에서 `NOT_SIGNED`
10. self-check 중 설정 변경·자동 상승·실제 수집·Finding 없음

하나라도 실패하면 `imp034-acceptance.json`을 `PASS`로 만들지 않습니다.

### 7.4 `sign-imp035-windows-collector.ps1`

최신 `imp034-acceptance.json = PASS` unsigned build를 자동으로 선택합니다.

개발 서명 절차:

```text
accepted unsigned EXE hash 확인
→ 새 acceptance 디렉터리에 복사
→ CurrentUser/My에 RSA 3072 self-signed Code Signing 인증서 생성
→ private key NonExportable
→ SHA-256 Authenticode + 외부 timestamp
→ signer·timestamp·pre/post hash 확인
→ 한 byte 변조 파일이 HashMismatch인지 검사
→ signed EXE self-check
→ 임시 인증서·private key 제거
→ signed EXE ClamAV·Defender 재검사
→ IMP-035 acceptance·manifest·SHA256SUMS 생성
```

개발 인증서를 Windows Root나 TrustedPublisher에 설치하지 않으므로 서명 뒤에도 Windows
신뢰 상태가 `UnknownError` 또는 `UntrustedRoot`로 보일 수 있습니다. 이는 운영 인증서가
아니기 때문에 예상되는 결과입니다.

### 7.5 `prepare-dev-signed-downloads.ps1`

이 단계는 EXE를 새로 빌드하지 않습니다. 검증된 Windows EXE와 Linux 공용·호환 세 파일을 웹에서
안전하게 내려받을 수 있는 개발 Catalog로 묶습니다.

- 현재 wrapper는 Windows·Linux 공용·Ubuntu 호환·Rocky 호환 네 파일이 모두 있어야 합니다.
- Windows는 IMP-035 Authenticode acceptance가 필요합니다.
- Linux는 해당 release manifest의 보안 Gate가 필요합니다.
- 프로젝트 밖 Ed25519 private key로 파일 hash와 Catalog를 서명합니다.
- private key는 API나 다운로드 디렉터리에 복사하지 않습니다.
- 기본 유효기간은 7일, 허용 범위는 1~100일입니다.

## 8. 새 Windows 11 PC에서 처음부터 다시 만드는 절차

### 8.1 준비 조건

필수 환경:

- Windows 11 x64 실제 host 또는 승인된 Windows 11 x64 VM
- 프로젝트 source 전체
- PowerShell
- Docker Desktop과 Linux container 실행 가능 상태
- Python Install Manager의 `py` 명령과 `py install` 지원
- Microsoft Defender Antivirus·실시간 보호 활성
- 인터넷 연결
  - 최초 CPython·hash-locked wheel 설치
  - pip-audit advisory 조회
  - 개발 서명 시 timestamp server
- 프로젝트 `sec-ai-mvp/dev-tools:0.1.0` image
- 실행 중인 ClamAV와 Docker network `sec-ai-mvp-app`

Linux·WSL에서 Windows EXE를 cross-build하지 않습니다. PyInstaller는 현재 계약에서
cross-compiler로 사용하지 않습니다.

### 8.2 프로젝트 루트 확인

PowerShell에서 프로젝트 루트로 이동합니다. 다음 파일이 보여야 합니다.

```powershell
Get-Item .\tools\build-imp034-windows-collector.ps1
Get-Item .\collectors\one_shot\entrypoint.py
Get-Item .\requirements\lock\collector-build.lock
```

실제 `.env`, 인증서, private key나 과거 `runtime`을 다른 PC source 묶음에 포함할 필요는
없습니다.

### 8.3 기본 도구 확인

```powershell
[Environment]::Is64BitOperatingSystem
$env:PROCESSOR_ARCHITECTURE
py --version
docker version
Get-MpComputerStatus |
  Select-Object AntivirusEnabled, RealTimeProtectionEnabled,
                AMProductVersion, AntivirusSignatureVersion
```

확인 기대값:

- 64bit OS: `True`
- architecture: `AMD64`
- Docker daemon 응답 성공
- Defender Antivirus·실시간 보호: `True`

설치된 기본 Python version은 3.14.6이 아니어도 됩니다. build wrapper가 전용
`runtime/imp034-python3146`을 별도로 준비하고 실제 version을 다시 검사합니다. 단,
`py install` 자체가 동작해야 합니다.

### 8.4 개발 image와 Core 준비

이미 개발 환경과 ClamAV가 정상이라면 이 절은 생략할 수 있습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action Build

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Init

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action UpWithoutAIStor

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Status

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Health
```

빌드 script가 ClamAV 컨테이너 이름 `clamav`를 `sec-ai-mvp-app` 내부 network에서 찾습니다.
Core를 올리지 않고 build만 실행하면 EXE 생성 뒤 ClamAV 단계에서 실패할 수 있습니다.

### 8.5 source 기준선 검증

실행파일에 넣을 source 자체가 실패한 상태에서 binary만 만들지 않습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action All
```

이 명령은 Config·Python version·Pytest·Schema·Ruff·mypy를 실행합니다. 현재 작업 밖 기존
실패가 있으면 실패를 숨기지 말고 Collector 관련 집중시험과 분리해 기록합니다.

### 8.6 unsigned EXE 빌드

프로젝트 루트에서 다음 명령을 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\build-imp034-windows-collector.ps1
```

최초 실행은 CPython과 dependency 설치 때문에 시간이 더 걸릴 수 있습니다. script는 다음
경로만 build용으로 사용합니다.

```text
runtime/imp034-python3146/
runtime/imp034-builder-venv/
runtime/imp034-artifacts/build-<UTC>/
```

각 build는 새 timestamp 디렉터리를 만듭니다. 기존 acceptance 디렉터리를 덮어쓰지 않습니다.

### 8.7 최신 build 찾기

```powershell
$buildDirectory = Get-ChildItem `
  -LiteralPath .\runtime\imp034-artifacts `
  -Directory -Filter 'build-*' |
  Sort-Object Name -Descending |
  Select-Object -First 1

$buildDirectory.FullName
Get-ChildItem -LiteralPath $buildDirectory.FullName
```

### 8.8 acceptance 확인

```powershell
$acceptance = Get-Content `
  -LiteralPath (Join-Path $buildDirectory.FullName 'imp034-acceptance.json') `
  -Raw | ConvertFrom-Json

$acceptance.acceptance_status
$acceptance.artifact
$acceptance.checks | Select-Object id, title, passed
```

필수 결과:

```text
acceptance_status = PASS
checks 10개 passed = true
release_channel = DEV-UNSIGNED
known_vulnerabilities = 0
clamav = CLEAN
microsoft_defender = CLEAN
```

### 8.9 EXE 직접 확인

```powershell
$exe = Join-Path $buildDirectory.FullName 'SecAI-Collector-Windows-x64.exe'

Get-FileHash -LiteralPath $exe -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $exe |
  Select-Object Status, SignatureType, SignerCertificate
& $exe self-check
& $exe --version
```

IMP-034 직후에는 `Get-AuthenticodeSignature`가 `NotSigned`여야 정상입니다. 서명된 파일이
나오면 unsigned build와 signing 단계가 섞인 것이므로 acceptance를 중단합니다.

## 9. unsigned 산출물 구성

정상 build 디렉터리는 다음과 같습니다.

```text
runtime/imp034-artifacts/build-<UTC>/
├─ SecAI-Collector-Windows-x64.exe
├─ SecAI-Collector-Windows-x64-0.1.0.manifest.json
├─ SecAI-Collector-Windows-x64-0.1.0.cdx.json
├─ SecAI-Collector-Windows-x64-0.1.0.vulnerability.json
├─ SecAI-Collector-Windows-x64-0.1.0.clamav.json
├─ SecAI-Collector-Windows-x64-0.1.0.defender.json
├─ SecAI-Collector-Windows-x64-0.1.0.authenticode.json
├─ SecAI-Collector-Windows-x64-0.1.0.embedded-resources.json
├─ imp034-build-context.json
├─ imp034-acceptance.json
└─ SHA256SUMS.txt
```

| 파일 | 확인할 내용 |
|---|---|
| EXE | 실제 단일 실행파일 |
| `manifest.json` | release channel, source snapshot, lock, 파일 hash |
| `cdx.json` | CycloneDX dependency SBOM |
| `vulnerability.json` | pip-audit dependency별 취약점 결과 |
| `clamav.json` | ClamAV engine·artifact hash·CLEAN 여부 |
| `defender.json` | Defender engine·signature·artifact hash·결과 |
| `authenticode.json` | unsigned 상태 확인 |
| `embedded-resources.json` | EXE에 넣은 data 파일별 path·size·hash |
| `build-context.json` | OS·Python·PyInstaller·source snapshot·self-check |
| `acceptance.json` | 최종 10개 Gate PASS/FAIL |
| `SHA256SUMS.txt` | 산출물 전체 hash 목록 |

문서에 적힌 과거 EXE 크기나 SHA-256을 현재 정답으로 사용하지 않습니다. 매 build의
`imp034-acceptance.json`과 `SHA256SUMS.txt`가 해당 build의 정본입니다.

## 10. 개발용 Authenticode 서명 재현

### 10.1 실행

IMP-034가 PASS한 뒤 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\sign-imp035-windows-collector.ps1
```

기본 timestamp server가 실패하면 승인된 fallback server를 한 번 사용합니다. 각 요청은
45초로 제한됩니다.

### 10.2 최신 signed 디렉터리 찾기

```powershell
$signedDirectory = Get-ChildItem `
  -LiteralPath .\runtime\imp035-artifacts `
  -Directory -Filter 'acceptance-*' |
  Sort-Object Name -Descending |
  Select-Object -First 1

$signedDirectory.FullName
```

### 10.3 acceptance 확인

```powershell
$signedAcceptance = Get-Content `
  -LiteralPath (Join-Path $signedDirectory.FullName 'imp035-acceptance.json') `
  -Raw | ConvertFrom-Json

$signedAcceptance.acceptance_status
$signedAcceptance.implementation_checks |
  Select-Object id, title, passed
$signedAcceptance.external_gates
```

현재 개발 환경의 기대값:

```text
acceptance_status = PASS_WITH_DEFERRED_EXTERNAL_GATES
implementation_complete = true
imp_complete = false
production_release_ready = false
implementation_checks 12개 PASS
external_gates 3개 DEFERRED
```

### 10.4 서명된 EXE 확인

```powershell
$signedExe = Join-Path $signedDirectory.FullName 'SecAI-Collector-Windows-x64.exe'

Get-FileHash -LiteralPath $signedExe -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $signedExe |
  Select-Object Status, SignatureType, SignerCertificate, TimeStamperCertificate
& $signedExe self-check
```

서명이 EXE 안에 추가되므로 unsigned와 signed SHA-256은 달라야 합니다. 개발 root를 신뢰
저장소에 설치하지 않으므로 `Status=UnknownError`가 표시될 수 있습니다. `imp035-acceptance`
없이 Windows 표시만 보고 배포 승인하지 않습니다.

### 10.5 signed 산출물

대표 파일:

```text
runtime/imp035-artifacts/acceptance-<UTC>/
├─ SecAI-Collector-Windows-x64.exe
├─ imp034-acceptance.source.json
├─ imp035-signing-context.json
├─ imp035-acceptance.json
├─ SecAI-Collector-Windows-x64-0.1.0.dev-release-manifest.json
├─ SecAI-Collector-Windows-x64-0.1.0.cdx.json
├─ SecAI-Collector-Windows-x64-0.1.0.vulnerability.json
├─ SecAI-Collector-Windows-x64-0.1.0.signed.clamav.json
├─ SecAI-Collector-Windows-x64-0.1.0.signed.defender.json
└─ SHA256SUMS.txt
```

## 11. 개발용 웹 다운로드 자료 만들기

이 단계는 Windows EXE만 만드는 절차가 아니라 Windows EXE, Linux 6종 자동 식별 공용 파일,
이전 Ubuntu·Rocky 호환 파일을 포함한 네 파일의 통합 개발 다운로드 Catalog를 만드는
절차입니다.

### 11.1 Linux 산출물이 없을 때

현재 `prepare-dev-signed-downloads.ps1`은 Windows와 Linux 공용·Ubuntu/Rocky 호환 artifact를 모두 요구합니다. Linux release가
없다면 먼저 다음을 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\build-linux-oneshot.ps1
```

Linux 상세 build·VM 시험은 다음 문서를 따릅니다.

- [`Linux 원샷 점검 프로그램 구현 체크리스트`](../plans/Linux_원샷_점검_프로그램_구현_체크리스트.md)
- [`Linux 원샷 VM 시험 안내`](../guides/Linux_원샷_VM_시험_안내.md)

### 11.2 Catalog 준비

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\prepare-dev-signed-downloads.ps1
```

기본 private key 위치:

```text
%LOCALAPPDATA%\Sec_AI\dev-signing\dev-download-ed25519.pem
```

이 경로는 프로젝트 밖입니다. key를 source·runtime download directory·Docker image 안으로
복사하지 않습니다.

생성 구조:

```text
runtime/dev-signed-downloads/
├─ active-release.json
├─ dev-download-public-key.json
└─ release-<UTC>/
   ├─ SecAI-Collector-Windows-x64.exe
   ├─ secai-linux-check-x86_64
   ├─ secai-linux-check-ubuntu24-x86_64
   ├─ secai-linux-check-rocky9-x86_64
   ├─ dev-signed-download-catalog.json
   └─ DEV-SIGNED-TEST.txt
```

일반 사용자 화면은 `secai-linux-check-x86_64` 하나를 우선 제공한다. 이 파일이
`/etc/os-release`와 아키텍처를 확인해 Ubuntu 22.04·24.04, Debian 12,
Rocky·RHEL·AlmaLinux 9 x64 중 exact Adapter를 선택한다. 배포판별 두 파일은 이전 개발
흐름과의 호환용이며 새 플랫폼을 위해 파일을 여섯 개로 나누지 않는다.

실제 파일명 정본은 생성된 Catalog를 따릅니다. Catalog 생성 뒤 API가 현재 활성 release를
읽도록 서비스 반영이 필요할 수 있습니다. 상세 사용법은
[`Windows·Linux 임시서명 다운로드 안내`](../guides/Windows_Linux_임시서명_다운로드_점검_안내.md)를
따릅니다.

## 12. version을 올릴 때 함께 바꿀 파일

현재 `0.1.0`은 여러 build·검증 파일에 명시되어 있습니다. version을 하나만 바꾸면 파일명,
SBOM, acceptance와 Windows 속성이 불일치합니다.

함께 확인할 위치:

| 파일 | 변경 항목 |
|---|---|
| `pyproject.toml` | `[project].version` |
| `src/security_audit/__init__.py` | `__version__` |
| `tools/build_imp034_collector.py` | `ARTIFACT_VERSION`, embedded manifest 이름 |
| `tools/build-imp034-windows-collector.ps1` | `$artifactVersion` |
| `src/security_audit/supply_chain/collector_build.py` | `VERSION` |
| `tools/sign-imp035-windows-collector.ps1` | `$artifactVersion` |
| `src/security_audit/supply_chain/collector_release.py` | manifest·scan·SBOM 파일명 상수 |
| `collectors/one_shot/build/windows_version_info.txt` | numeric version과 문자열 version |
| `collectors/one_shot/contracts/imp034_native_build_policy.json` | artifact version |
| 관련 test·Fixture·검증 문서 | 기대 version·파일명 |

version 변경은 단순 문구 수정이 아니라 공급망 계약 변경입니다. 테스트를 먼저 갱신하고 새
unsigned build·서명·SBOM·취약점·악성코드 검사를 전부 다시 실행합니다. 과거 runtime
acceptance와 검증 기록을 새 version 값으로 덮어쓰지 않습니다.

## 13. Probe·계약·Schema를 바꾼 뒤 rebuild

### 13.1 PowerShell Probe 변경

변경 위치:

```text
collectors/one_shot/probes/windows/powershell/
```

확인 순서:

1. 읽기 전용 동작 유지
2. exact executable·script·argv allowlist 확인
3. script SHA-256 상수·계약·Fixture 갱신
4. timeout·출력 상한·process tree 종료 시험
5. 일반/관리자 권한 경계 시험
6. 실제 Windows 실행 전후 설정 diff 0 확인
7. 새 EXE build·self-check·악성코드 검사

`.ps1` 파일은 resource root에 있으므로 다음 build에 자동 선택됩니다.

### 13.2 계약 JSON 변경

변경 위치:

```text
collectors/one_shot/contracts/
```

과거 IMP 계약을 새 의미로 덮어쓰기보다 새 contract version을 추가합니다. 새 `.json`은
자동으로 포함되지만, code가 그 계약을 실제로 소비하는지 별도 테스트가 필요합니다.

### 13.3 Schema 변경

기존 Schema를 무조건 수정하지 않습니다. 호환성에 따라 새 version과 valid/invalid example을
추가한 뒤 Schema 검증을 먼저 통과합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action Schema
```

현재 build 선택 규칙은 `database/schemas` 아래 모든 `.json`을 포함하므로 valid/invalid
example도 EXE resource에 들어갑니다. 크기와 필요성을 바꾸려면 build 계약·시험을 함께
변경해야 합니다.

### 13.4 새로운 별도 resource 추가

새 파일이 기존 세 resource root 밖에 있다면 자동 포함되지 않습니다. 실행 중 반드시 필요한
정적 자료만 `LIVE_DRAFT_RESOURCE_PATHS`와 관련 test에 명시적으로 추가합니다.

private key·인증서·실제 `.env`·사용자 자료를 편의를 이유로 resource 목록에 추가하지
않습니다.

## 14. dependency를 변경한 뒤 rebuild

### 14.1 변경 원칙

1. 직접 의존성 의도는 `requirements/collector.in`에서 수정합니다.
2. PyInstaller 같은 build 도구는 `requirements/collector-build.in`에서 수정합니다.
3. `requirements/lock/collector-build.lock`을 사람이 직접 편집하지 않습니다.
4. 승인된 Windows 11 x64 resolver에서 모든 transitive version과 hash를 다시 생성합니다.
5. `requirements/verification/collector-build-lock.json`과 `LOCK-SHA256SUMS.txt`를 갱신합니다.
6. license·wheel 제공 여부·취약점·SBOM 차이를 검토합니다.
7. 새 builder venv에서 `--require-hashes` 설치·`pip check`를 확인합니다.
8. 전체 native build와 서명 후 검사까지 다시 실행합니다.

정확한 resolver option과 생성 환경은
[`requirements README`](../../requirements/README.md)와
[`잠금 메타데이터`](../../requirements/잠금_메타데이터.md)를 따릅니다.

### 14.2 기존 builder venv 처리

build wrapper는 `runtime/imp034-builder-venv`가 손상됐으면 runtime 경계를 확인한 뒤
재생성합니다. 정상 venv는 재사용하지만 매번 exact lock 설치와 `pip check`를 다시
수행합니다.

lock 변경 뒤 기존 환경 영향이 의심되면 source나 workspace 전체를 삭제하지 말고 build
전용 runtime venv만 정확한 경로인지 확인한 후 재생성합니다.

## 15. 테스트와 최종 인수

### 15.1 관련 집중시험

주요 test:

```text
tests/unit/test_imp034_collector_build.py
tests/unit/test_imp035_collector_release.py
tests/unit/test_imp040_product_launcher.py
tests/unit/test_imp043_administrator_consent.py
tests/unit/test_windows_administrator_complete_flow.py
tests/unit/test_dev_signed_download_api.py
tests/unit/test_dev_signed_download_ui_contract.py
```

표준 test wrapper:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action Test
```

전체 표준 Gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action All
```

### 15.2 build 후 필수 확인

- `imp034-acceptance.json = PASS`
- 10개 IMP-034 check 전부 PASS
- `self-check = PASS`
- PE32+ AMD64
- 100MiB 이하
- embedded resource failure 0
- SBOM component와 exact lock 일치
- 알려진 dependency 취약점 0
- ClamAV·Defender CLEAN
- unsigned 단계는 Authenticode `NotSigned`
- signed 단계는 pre/post hash가 다르고 timestamp 존재
- byte 변조 signature 거부
- 임시 private key·certificate cleanup PASS
- 설정 diff 0과 자동 UAC 0

### 15.3 실제 사용자 흐름 확인

1. 중앙 Core를 healthy 상태로 준비합니다.
2. 일반 사용자 token으로 EXE를 더블클릭합니다.
3. 브라우저가 SecAI Launcher 연결 화면으로 열리는지 확인합니다.
4. `내 PC 점검하기`에서 일반 15개 진행·취소·재시도를 확인합니다.
5. 관리자 추가 점검은 항목·이유를 본 뒤 별도 동의합니다.
6. UAC 취소 시 일반 결과가 보존되는지 확인합니다.
7. 실행 전후 Windows 설정 diff가 0인지 확인합니다.

개발 PC 시험은 clean Windows 11·SmartScreen 운영 인수를 대신하지 않습니다.

## 16. 자주 발생하는 오류

| 오류·증상 | 원인 후보 | 확인·조치 |
|---|---|---|
| `Unable to install the exact CPython 3.14.6` | `py install` 미지원·network 장애 | `py --version`, Python Install Manager와 network 확인 |
| `requires exact CPython 3.14.6` | runtime 경로가 다른 version | `runtime/imp034-python3146/python.exe` version 확인 |
| hash-locked dependency 설치 실패 | lock과 package artifact 불일치·index 장애 | lock을 수정하지 말고 network·승인 index·hash 확인 |
| `pip check` 실패 | dependency 충돌 | `.in`과 승인 resolver로 lock 재생성 |
| `sec-ai-mvp/dev-tools:0.1.0` 없음 | dev-tools image 미빌드 | `tools/dev.ps1 -Action Build` |
| Docker network `sec-ai-mvp-app` 없음 | Core Compose 미기동 | `tools/core.ps1 -Action UpWithoutAIStor` |
| ClamAV 연결·검사 실패 | `clamav` unhealthy·DB 초기화 중 | Core Status/Health와 container log 확인 후 재시도 |
| Defender 비활성 | Antivirus 또는 RealTimeProtection off | 조직 정책 확인 후 Defender 활성 상태에서 다시 build |
| `MpCmdRun.exe` 없음 | Defender CLI 미제공 환경 | 승인된 Windows 11 builder 사용 |
| frozen self-check 실패 | resource 누락·hash 불일치·잘못된 Python/CPU | `resource_failures`, embedded manifest, build context 확인 |
| PE 검사 실패 | Windows x64 native build가 아님 | WSL/Linux cross-build 금지, Windows AMD64에서 재실행 |
| IMP-034에서 이미 Signed | 과거 signed 파일 혼입 | 새 timestamp build를 만들고 unsigned 경계 확인 |
| `No accepted IMP-034 build was found` | acceptance PASS build 없음 | IMP-034 build의 `imp034-acceptance.json` 확인 |
| timestamp server 실패 | 외부 network·server 장애 | 45초 timeout·fallback 결과 확인, 서명 없이 성공 처리 금지 |
| signed 파일이 `UnknownError` | 개발 self-signed root를 신뢰 store에 미등록 | 정상 개발 경계일 수 있으므로 IMP-035 acceptance 확인 |
| 웹 다운로드 준비 실패 | Windows·Ubuntu·Rocky 중 하나 없음 | 세 platform release와 각각의 security Gate 확인 |
| 실행 시 localhost 화면 연결 실패 | 중앙 서비스가 18480에서 실행되지 않음 | `tools/core.ps1 -Action Health` 확인 |
| 18481 사용 충돌 | 다른 프로세스 또는 이전 Launcher 응답 불가 | 기존 SecAI 종료 후 재실행, 임의 프로세스 강제 종료 금지 |

## 17. 운영 Release로 전환하려면

현재 개발 서명 script를 그대로 운영 서명으로 부르면 안 됩니다. 운영에는 최소 다음 Gate가
추가로 필요합니다.

1. 조직 또는 공인 CA의 Code Signing 인증서
2. 승인된 Publisher 이름과 인증서 chain
3. non-exportable key의 조직 Key Storage/HSM 정책
4. 운영 timestamp 정책
5. 실제 CRL/OCSP 폐기 확인과 장애 시 fail-closed 처리
6. clean Windows 11 x64 VM snapshot
7. Microsoft Defender·SmartScreen·조직 EDR 인수
8. 설치형 도우미를 만들 경우 MSI/MSIX installer 별도 설계
9. upgrade·rollback·uninstall·자동 업데이트 정책
10. 다운로드 server TLS·조직 인증·감사·보존 정책

현재 self-signed 개발 인증서나 Ed25519 개발 Catalog key를 운영에 재사용하지 않습니다.

## 18. 재현 체크리스트

### 환경

- [ ] Windows 11 x64·AMD64입니다.
- [ ] `py install`과 Docker가 동작합니다.
- [ ] Defender Antivirus·실시간 보호가 켜져 있습니다.
- [ ] `sec-ai-mvp/dev-tools:0.1.0` image가 있습니다.
- [ ] ClamAV와 `sec-ai-mvp-app` network가 준비됐습니다.
- [ ] 필요한 외부 package·advisory·timestamp network를 사용할 수 있습니다.

### source·lock

- [ ] `entrypoint.py`, `collector-build.lock`, version resource가 존재합니다.
- [ ] 실제 secret·private key·Evidence가 source에 없습니다.
- [ ] `tools/dev.ps1 -Action All` 결과를 확인했습니다.
- [ ] source 변경에 필요한 contract·Schema·Fixture를 함께 갱신했습니다.

### unsigned build

- [ ] `build-imp034-windows-collector.ps1`을 실행했습니다.
- [ ] 최신 build의 acceptance가 PASS입니다.
- [ ] 10개 check가 전부 PASS입니다.
- [ ] self-check가 PASS입니다.
- [ ] SBOM·취약점·ClamAV·Defender 결과가 정상입니다.
- [ ] Authenticode는 아직 NotSigned입니다.

### 개발 서명

- [ ] accepted unsigned build만 입력으로 사용했습니다.
- [ ] pre-sign과 post-sign SHA-256을 모두 기록했습니다.
- [ ] timestamp와 변조 거부가 통과했습니다.
- [ ] signed EXE self-check·ClamAV·Defender가 통과했습니다.
- [ ] 임시 인증서와 private key가 제거됐습니다.
- [ ] 운영 Release가 아니라는 표시를 유지했습니다.

### 다운로드·인수

- [ ] 웹 다운로드가 필요하면 Linux 두 release도 준비했습니다.
- [ ] Ed25519 private key는 프로젝트 밖에 있습니다.
- [ ] Catalog·file hash·active pointer를 확인했습니다.
- [ ] 실제 사용자 흐름과 설정 diff 0을 확인했습니다.
- [ ] 조직 인증서·SmartScreen Gate 전에는 운영 배포로 표시하지 않았습니다.

## 19. 관련 파일과 문서

### 핵심 source

- [`Windows PyInstaller 진입점`](../../collectors/one_shot/entrypoint.py)
- [`Windows Collector CLI`](../../src/security_audit/collector/cli.py)
- [`일반 점검 Launcher`](../../src/security_audit/collector/launcher.py)
- [`관리자 추가 점검 Launcher`](../../src/security_audit/collector/administrator_launcher.py)
- [`Windows version resource`](../../collectors/one_shot/build/windows_version_info.txt)

### 빌드·서명

- [`Windows build wrapper`](../../tools/build-imp034-windows-collector.ps1)
- [`PyInstaller builder`](../../tools/build_imp034_collector.py)
- [`IMP-034 acceptance`](../../src/security_audit/supply_chain/collector_build.py)
- [`개발 Authenticode wrapper`](../../tools/sign-imp035-windows-collector.ps1)
- [`IMP-035 acceptance`](../../src/security_audit/supply_chain/collector_release.py)
- [`개발 다운로드 Catalog 준비`](../../tools/prepare-dev-signed-downloads.ps1)

### 계약·lock·검증

- [`Collector README`](../../collectors/README.md)
- [`requirements README`](../../requirements/README.md)
- [`IMP-034 build 정책`](../../collectors/one_shot/contracts/imp034_native_build_policy.json)
- [`IMP-035 release 정책`](../../collectors/one_shot/contracts/imp035_release_policy.json)
- [`IMP-034 검증 기록`](../../deploy/verification/IMP034_Windows_실행파일_빌드_검증.md)
- [`IMP-035 검증 기록`](../../deploy/verification/IMP035_Authenticode_수집기_인수.md)
- [`Windows·Linux 임시서명 다운로드 안내`](../guides/Windows_Linux_임시서명_다운로드_점검_안내.md)

과거 검증 기록의 크기·hash·resource 수는 당시 source의 결과입니다. 현재 rebuild 판단에는
새 output directory의 acceptance·manifest·SHA256SUMS를 사용합니다.
