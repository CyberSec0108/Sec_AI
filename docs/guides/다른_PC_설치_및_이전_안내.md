# Sec_AI 다른 PC 설치·이전 안내

| 항목 | 내용 |
|---|---|
| 기준일 | 2026-08-07 현재 기능 기준 |
| 대상 | 같은 조직의 다른 Windows 11 x64 개발·검증 PC |
| 지원 방식 | 온라인 source-only 이전, 오프라인 source+잠긴 Docker image 이전 |
| 현재 성격 | DEV-LOCAL 개발 환경; 운영·Pilot 배포 절차가 아님 |
| 미포함 | 실제 `.env`, Secret, AIStor license, DB·증적·VM, 로컬 vLLM model, 검색 model volume |

## 1. 먼저 확인할 제한

이 절차는 Sec_AI source와 재현 가능한 개발 Container를 다른 PC에 준비합니다. 다음 항목을 완료했다는 뜻은 아닙니다.

- 조직 코드서명·SmartScreen·clean Windows VM Release Gate
- 실제 TLS·WebAuthn·조직 OIDC 운영 인증
- Linux 운영 KMS·Pack 서명·내부망 Worker 배치
- Cisco 실제 장비 지원과 Aruba 운영 Pack 승인
- 승인된 로컬 vLLM model·GPU·외부 egress 0

회사 내부 여러 사용자가 Web UI로 Linux 서버를 점검하는 운영 배치는 [`회사 내부망 Linux SSH 점검 UI 배포·운영 안내`](회사_내부망_Linux_SSH_점검_UI_배포_운영_안내.md)를 별도로 따릅니다.

## 2. 대상 PC 준비

대상 PC에는 다음 항목이 필요합니다.

1. Windows 11 x64
2. BIOS/UEFI virtualization과 Windows의 WSL 2 사용 가능 상태
3. Docker Desktop 최신 조직 승인 버전, **Linux containers** mode
4. Windows PowerShell 5.1 이상
5. `curl.exe`
6. `127.0.0.1:18480`, 선택형 DB 관리 UI의 `127.0.0.1:18490`을 다른 프로그램이 사용하지 않는 상태
7. source·Docker image·volume을 둘 충분한 로컬 디스크

Host에 Python, Node.js, PostgreSQL, Redis와 AIStor를 따로 설치하지 않습니다.

PowerShell에서 다음 사전 확인을 실행합니다.

```powershell
docker version
docker compose version
curl.exe --version
```

Docker 명령이 실패하면 Docker Desktop이 실행 중인지, Linux container mode인지 먼저 확인합니다.

## 3. 이전 방식 선택

| 방식 | 적합한 환경 | 묶음 내용 | 대상 PC의 Network |
|---|---|---|---|
| source-only | 승인된 registry·Internet에 연결 가능 | source ZIP·Manifest·SHA-256 | image pull·build에 필요 |
| 전체 offline bundle | 폐쇄망 또는 동일 image를 그대로 옮길 때 | source ZIP + 잠긴 외부·project image TAR + Manifest·SHA-256 | 기본 import에는 불필요 |

전체 offline bundle에도 Runtime volume, VM, 검색 model, 로컬 vLLM model과 Secret은 포함되지 않습니다.

## 4. 원본 PC에서 묶음 만들기

프로젝트 루트에서 Docker Desktop을 실행한 뒤 전체 묶음을 만듭니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\export-portable-bundle.ps1
```

온라인 대상 PC용 source-only 묶음은 다음과 같습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\export-portable-bundle.ps1 -SourceOnly
```

결과는 `portable\out\secai-portable-<UTC 시각>\`에 생성됩니다.

```text
secai-source.zip
secai-images.tar          # 전체 묶음만
BUNDLE-MANIFEST.json
SHA256SUMS.txt
import-portable-bundle.ps1
README.md
```

전체 묶음은 현재 Core의 API, Gateway, 일반·유지보수 Worker, Scheduler, Model Gateway, PostgreSQL+pgvector, Redis, AIStor, ClamAV, 선택형 pgAdmin과 개발 도구 image를 기록합니다. 취약점 Gate가 끝나지 않은 로컬 vLLM image와 별도 검색 model은 자동 포함하지 않습니다.

묶음 디렉터리 전체를 승인된 내부 전송수단으로 옮깁니다. 파일을 일부만 복사하거나 압축을 다시 만들지 않습니다.

## 5. 대상 PC에서 무결성 확인·가져오기

빈 대상 디렉터리를 선택합니다. 예시는 `D:\Sec_AI`이며 다른 절대경로도 사용할 수 있습니다.

```powershell
Set-Location D:\transfer\secai-portable-<UTC 시각>
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\import-portable-bundle.ps1 `
  -Destination D:\Sec_AI
```

가져오기 스크립트는 `SHA256SUMS.txt`를 먼저 확인하고, 전체 묶음이면 Docker image TAR를 적재한 뒤 source를 풉니다. hash가 다르면 즉시 중단하고 원본 묶음을 다시 전달받습니다.

`-Force`는 기존 파일을 덮을 수 있으므로 새 PC의 빈 디렉터리 설치에는 사용하지 않습니다.

## 6. 환경 파일과 Runtime 디렉터리 준비

```powershell
Set-Location D:\Sec_AI
Copy-Item -LiteralPath .env.example -Destination .env
New-Item -ItemType Directory -Force -Path .runtime\vmware | Out-Null
```

`.runtime\vmware`는 Compose의 읽기 전용 bind 경로를 준비하기 위한 빈 디렉터리입니다. Linux VM이 자동 설치됐다는 의미가 아닙니다. Linux 개발 점검이 필요하면 VM·snapshot·SSH key를 승인된 별도 절차로 반입하고 [`KISA Linux 점검 안내`](KISA_2026_UNIX_Linux_점검_안내.md)를 확인합니다.

`.env`에는 공개 가능한 환경 선택만 둡니다. password, API key, token, license와 private key를 직접 쓰지 않고 `runtime/dev-secrets`의 secret file을 사용합니다.

기본 port를 바꿀 때는 `.env`의 다음 변수만 조직 승인 범위에서 조정합니다.

```text
SECAI_GATEWAY_BIND
SECAI_GATEWAY_PORT
SECAI_PGADMIN_BIND
SECAI_PGADMIN_PORT
```

외부 주소에 bind하거나 DEV HTTP를 내부망에 공개하지 않습니다.

## 7. 개발 Secret 준비

먼저 무작위 DEV secret을 생성합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Init
```

파일은 `runtime/dev-secrets`에 생성되고 현재 Windows 사용자·SYSTEM·Administrators만 접근하도록 ACL을 제한합니다. 값은 화면에 출력하지 않습니다.

### 7.1 Model Gateway 설정

현재 API Compose는 내부 Gateway token file을 요구합니다. AI 기능을 사용할 PC는 승인된 원격 모델 설정 파일을 별도 보안 전송으로 받은 뒤 다음 공식 import 경로를 사용합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\import-llm-settings.ps1 `
  -SourceEnvironmentFile D:\secure-transfer\approved-llm.env
```

입력 파일에는 스크립트가 요구하는 `DEEPSEEK_API_BASE`, `DEEPSEEK_API_KEY`, `MODEL_NAME`이 있어야 합니다. 변수명은 legacy import 계약이며 특정 공급자를 운영 승인했다는 의미가 아닙니다. 스크립트는 API key를 secret file로 분리하고 내부 Gateway token을 생성·보존합니다.

승인된 모델 설정이 없으면 임의 key·공개 무료 endpoint·개인 계정을 넣지 않습니다. 이 경우 Docker 기반 source 검증까지만 수행하고 live AI 포함 Core 기동은 Secret 승인 때까지 보류합니다.

### 7.2 AIStor license

AIStor를 포함할 때만 조직이 발급받은 license를 별도 반입합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 `
  -Action Init `
  -AIStorLicensePath D:\secure-transfer\minio.license
```

License를 source, portable bundle, 문서, 채팅과 image에 복사하지 않습니다.

## 8. Source·계약 검증

온라인 source-only 이전은 먼저 개발 image를 빌드합니다. 전체 offline bundle은 이미 적재된 project image를 사용할 수 있지만 source와 현재 잠금의 정합성을 확인하기 위해 같은 Gate를 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action Build
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action All
```

`All`은 Compose config, Python version, unit·contract Pytest, JSON Schema 예제, Ruff와 mypy를 검사합니다. 실패하면 기대값을 바꾸거나 시험을 생략하지 말고 로그와 현재 `구현_현황.md`의 알려진 기준선을 대조합니다.

## 9. Core 시작

AIStor license 없이 개발 Core를 시작할 때는 다음 명령을 사용합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action UpWithoutAIStor
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Health
```

이 상태에서는 `/health/live`의 HTTP 200이 정상이고, AIStor가 없기 때문에 `/health/ready`의 `503 not_ready`는 의도된 fail-closed 상태입니다.

AIStor license까지 준비한 전체 개발 Core는 다음과 같습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Up
```

기동 과정은 migration을 적용하고 DEV-LOCAL `local-owner` 계정을 멱등하게 준비합니다.

## 10. 로그인·기능 확인

Browser에서 [http://localhost:18480](http://localhost:18480)을 엽니다.

- DEV username: `local-owner`
- password file: `runtime/dev-secrets/auth_dev_password`
- 개발용 두 번째 인증코드 file: `runtime/dev-secrets/auth_dev_mfa_code`

값은 해당 PC에서만 읽고 문서·채팅·화면공유·로그에 복사하지 않습니다. DEV 인증은 Pilot MFA가 아닙니다.

기본 확인 항목은 다음과 같습니다.

1. 로그인과 session 생성
2. 제품 홈 표시
3. Windows 점검 화면과 현재 기능 상태
4. KISA Guide 검색
5. 승인된 경우 Model Gateway AI 설명
6. `core.ps1 -Action Health`

Windows Collector EXE는 개발 source와 별도의 build·서명 Gate가 있습니다. 기존 PC의 EXE를 임의 복사해 운영 배포하지 않습니다.

## 11. 선택형 DB 관리 UI

개발 관리자만 다음 명령으로 loopback pgAdmin을 엽니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\open-database-admin.ps1 -Action Start
```

- 주소: [http://127.0.0.1:18490](http://127.0.0.1:18490)
- login ID: `admin@secai.dev`
- pgAdmin password file: `runtime/dev-secrets/pgadmin_default_password`
- DB password file: `runtime/dev-secrets/postgres_db_admin_password`

PostgreSQL `5432`는 Host에 공개하지 않습니다.

## 12. 중지·재시작

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Restart
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Logs
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Down
```

`Down`은 named volume을 삭제하지 않습니다. Volume·DB·증적 삭제는 별도 승인과 backup 확인 없이 수행하지 않습니다.

## 13. 다른 PC로 자동 이전되지 않는 자료

| 자료 | 처리 |
|---|---|
| `.env` | 대상 PC에서 `.env.example`로 새로 만들고 비밀값은 넣지 않음 |
| `runtime/dev-secrets` | 대상 PC에서 재생성하거나 승인된 secret 절차로 이전 |
| AIStor license | 같은 조직의 이용조건 확인 후 별도 보안 전송 |
| PostgreSQL·AIStor volume | 승인된 Backup/Restore 절차와 hash·RPO/RTO 검증 |
| 원본 증적 | 보존·권한·암호화·감사 절차로 별도 이전 |
| Ubuntu·Rocky VM·snapshot | VMware 기준선·hash·snapshot 절차로 별도 준비 |
| BGE-M3·Reranker model | model lock·license·benchmark 뒤 별도 volume 준비 |
| local vLLM image·weight | 현재 취약점·GPU·승인 model Gate로 이전/실행 차단 |
| Authenticode key | 조직 PKI·HSM/보안 저장소 절차; bundle 포함 금지 |

## 14. 문제 해결

| 증상 | 확인 |
|---|---|
| `checksum mismatch` | 묶음 사용 중단, 원본 PC에서 다시 생성·전달 |
| `Destination is not empty` | 새 빈 디렉터리 사용; 무분별한 `-Force` 금지 |
| Docker build가 registry에 연결되지 않음 | 전체 offline bundle 사용 또는 조직 proxy·registry 승인 확인 |
| secret file missing | `core.ps1 -Action Init`, 승인 LLM 설정 import 여부 확인 |
| bind source path missing | `.runtime\vmware` 빈 디렉터리와 KISA PDF 존재 확인 |
| `18480` port 충돌 | 기존 Sec_AI process 확인 후 종료하거나 승인된 loopback port로 변경 |
| live 200, ready 503 | AIStor 미기동이면 정상; 전체 기동이면 AIStor·DB·Redis·ClamAV health 확인 |
| AI만 실패 | approved API key·Gateway token·model ID·timeout·egress 확인 |
| Linux 자산이 없음 | portable bundle은 VM·SSH key를 포함하지 않음; 별도 개발 VM 절차 필요 |

## 15. 설치 완료 체크리스트

- [ ] Bundle SHA-256 검증 통과
- [ ] 실제 `.env`·Secret·license가 bundle에 없었음
- [ ] Docker Desktop Linux container mode 확인
- [ ] `.env`와 `.runtime\vmware` 준비
- [ ] DEV secret ACL 적용
- [ ] 승인된 경우 Model Gateway secret import
- [ ] `dev.ps1 -Action All` 결과 기록
- [ ] Core Status·Health 확인
- [ ] 로그인·제품 홈 확인
- [ ] 운영·Pilot 완료로 잘못 표시하지 않음
- [ ] 설치 PC·날짜·Bundle ID·Manifest hash를 내부 인수 기록에 남김
