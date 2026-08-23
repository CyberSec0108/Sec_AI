# 개발·검증 도구 안내

이 폴더는 Sec_AI를 빌드·실행·검증하고 제한된 관리 작업을 수행하는 PowerShell/Python 진입점을 보관합니다. 비즈니스 규칙 자체는 `src/`에 두고, 이곳의 스크립트는 반복 가능한 명령 조정과 검증 결과 요약에 집중합니다.

## 가장 많이 사용하는 진입점

| 스크립트 | 용도 | 대표 실행 |
|---|---|---|
| `dev.ps1` | 잠긴 개발 container의 Test·Schema·Lint·Type·All | `-Action All` |
| `core.ps1` | Core 초기화·기동·상태·Health·로그·중지 | `-Action Status` |
| `demo.ps1` | 합성 Package→Finding 시연 | 인수 기록에 따라 실행 |
| `open-database-admin.ps1` | loopback pgAdmin 선택 기동 | `-Action Start` |
| `generate-repository-catalog.ps1` | Runtime·secret 제외 파일 카탈로그 재생성 | 기본 OutputPath 사용 |
| `set-lab-linux-password.ps1` | Linux 실습 VM 공통 비밀번호·SSH 로그인 적용 및 검증 | 기본값으로 등록된 5종 전체 |

프로젝트 루트에서 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Status
```

`-ExecutionPolicy Bypass`는 해당 PowerShell 프로세스에만 적용하며 Windows 전역 정책을 변경하지 않습니다.

## 도구 분류

### 개발 환경과 서비스

| 파일 | 역할 |
|---|---|
| `init-dev-secrets.ps1` | 로컬 개발용 secret file 생성·ACL 제한 |
| `bootstrap-dev-auth.ps1` | 개발 계정 인증 bootstrap |
| `core.ps1` | Compose Core lifecycle |
| `dev.ps1` | 잠긴 품질 도구 실행 |
| `import-llm-settings.ps1` | 승인된 LLM 설정을 runtime secret 경계로 반입 |
| `open-database-admin.ps1` | 관리자 전용 DB 화면 선택 기동 |
| `search-model-runtime.ps1` | 별도 model-search Compose 관리 |

### Collector build·서명·다운로드

| 파일 묶음 | 역할 |
|---|---|
| `build_imp034_collector.py`, `build-imp034-windows-collector.ps1` | Windows native Collector build |
| `finalize_imp034_collector.py` | hash·SBOM·취약점·악성코드 Gate 반영 |
| `sign-imp035-windows-collector.ps1`, `finalize_imp035_collector.py` | Windows 개발/조직 서명 Release 검증 |
| `build_linux_oneshot_collector.py`, `build-linux-oneshot.ps1` | Linux 6종 자동 식별 공용 파일과 Ubuntu/Rocky 호환 파일 build |
| `prepare_dev_signed_downloads.py`, `prepare-dev-signed-downloads.ps1` | Windows/Linux 개발 서명 Catalog와 다운로드 자료 준비 |
| `verify-dev-signed-vm-downloads.ps1` | 1회용 다운로드·VM 실행 E2E 검증 |

private key는 프로젝트 밖의 경로만 사용합니다. build 결과와 다운로드 산출물은 `runtime/` 아래에 생성하며 source, Git 또는 이동 묶음에 넣지 않습니다. `DEV-UNSIGNED`나 보안 Gate가 끝나지 않은 산출물은 다운로드 가능 상태로 승격하지 않습니다.

### 가이드·검색 모델

| 파일 | 역할 |
|---|---|
| `verify_imp047_guide_source.py`, `verify-imp047-guide-source.ps1` | exact PDF hash·페이지·Mapping 검증 |
| `build-full-guide-artifacts.py` | 전체 분류 Page Map·Mapping 생성 |
| `ingest-approved-guide.py` | 승인 범위의 가이드 검증·적재 |
| `reembed-bge-m3.py` | 잠긴 BGE-M3 vector generation 생성·검증·활성화 |
| `verify-imp048-guide-store.ps1`, `verify-imp048-pgvector.ps1` | Guide store·pgvector 검증 |
| `verify-imp049-guide-grounding.ps1` | 질문별 페이지·문단 근거·범위 누출 검증 |

원문 전체를 로그에 출력하거나 승인되지 않은 외부 모델로 전송하지 않습니다. Catalog 승인, Mapping 승인과 Audit Pack 승인을 구분합니다.

### 단계별 검증

`verify_imp*.py`와 `verify-imp*.ps1`은 IMP-029 이후 Windows 수집·제출·제품 흐름, Queue/Storage 복구, 인증, 가이드, 모델 Gateway와 초보자 UI를 재현합니다. `verify-product-ai-*.ps1`은 결과 가이드, AI 설명과 대화 관리의 집중 Gate입니다.

일반적으로 PowerShell wrapper가 다음을 담당합니다.

1. 필요한 Compose service 상태 확인
2. 잠긴 container에서 Python verifier 실행
3. actual HTTP·DB·Worker 또는 브라우저 경계 연결
4. 민감 값을 제외한 PASS/FAIL 요약 출력

Python 파일을 직접 실행하기 전에 대응 wrapper와 [`../deploy/verification/`](../deploy/verification/) 기록을 확인합니다.

### 이동·유지보수

| 파일 | 역할 |
|---|---|
| `export-portable-bundle.ps1` | source-only 또는 source+image 이동 묶음 생성 |
| `generate-repository-catalog.ps1` | 저장소 파일 기능 카탈로그 갱신 |
| `scan_clamd.py` | ClamAV daemon을 이용한 제한된 파일 검사 |

이동 묶음은 사용자가 요청했을 때만 생성합니다. `runtime`, 실제 `.env`, secret, license, 증적, DB volume과 기존 `portable/out`은 포함하지 않습니다.

### 로컬 실습 VM 자격증명 관리

Linux 실습 VM의 공통 계정과 비밀번호는 source가 아닌
`runtime/dev-secrets/lab_vm_credentials.json`에서 관리합니다. 이 파일의
`linux.common_credential.password`를 바꾼 뒤 아래 도구를 다시 실행하면 등록된 Ubuntu,
Rocky Linux, Debian, AlmaLinux VM에 같은 값이 적용됩니다. 도구는 SSH 키로 최초 접속하고,
비밀번호 로그인을 허용한 다음 키를 사용하지 않은 재로그인까지 확인합니다. 원래 꺼져 있던
VM은 시험 후 게스트 OS 명령으로 정상 종료합니다.

```powershell
# 등록된 Linux 실습 VM 전체 적용·검증
pwsh -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\set-lab-linux-password.ps1

# 특정 VM만 적용·검증
pwsh -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\set-lab-linux-password.ps1 -TargetId debian_12
```

현재 선택 가능한 `TargetId`는 `ubuntu_24_04_lts`, `rocky_linux_9`,
`ubuntu_22_04_lts`, `debian_12`, `almalinux_9`입니다. VM snapshot을 과거 상태로
되돌리거나 cloud-init으로 다시 만들면 비밀번호 설정도 되돌아갈 수 있으므로 이 도구를 다시
실행합니다. 비밀번호 값은 명령 인수나 로그에 넣지 않습니다.

Aruba AOS-CX 실습 계정의 긴급 회전은 `rotate-aruba-lab-passwords.ps1`을 사용합니다.
새 값은 DPAPI 파일과 통합 자격증명 파일에만 저장하고 화면에는 출력하지 않습니다.

## 새 도구 작성 원칙

- 프로젝트 루트를 script 위치에서 계산하고 절대 사용자 경로를 하드코딩하지 않습니다.
- PowerShell은 `Set-StrictMode -Version Latest`와 `$ErrorActionPreference = "Stop"`을 사용합니다.
- 외부 명령의 exit code를 확인하고 실패를 성공처럼 계속하지 않습니다.
- 사용자 입력 경로는 absolute path로 정규화한 뒤 허용 루트 안인지 확인합니다.
- 임의 shell 문자열을 조합하지 않고 인수 배열과 `-LiteralPath`를 사용합니다.
- password, token, private key와 전체 환경 변수 값을 출력하지 않습니다.
- 생성물은 `runtime/`, `portable/out/` 같은 제외 영역에 두고 source와 섞지 않습니다.
- destructive 작업은 exact 대상과 복구 가능성을 확인하고 사용자 승인 없이 volume·DB·source를 삭제하지 않습니다.
- 검증 로직이 재사용되면 `src/`에 구현하고 script는 얇은 진입점으로 유지합니다.

## 도구 수정 시 확인

PowerShell syntax와 Compose 설정, 관련 Python 품질 검사를 변경 위험에 맞게 실행합니다.

```powershell
# Compose 병합 결과
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Config

# Python 도구 포함 Ruff
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Lint

# 전체 표준 검증
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

실제 host, VM, Docker volume, 외부 모델 또는 서명키가 필요한 검증은 자동으로 안전하다고 가정하지 않습니다. 필요한 권한·자료·영향 범위를 대응 안내에서 확인한 뒤 실행합니다.

## 관련 문서

- Core 실행: [`../deploy/README.md`](../deploy/README.md)
- dependency lock: [`../requirements/README.md`](../requirements/README.md)
- Collector: [`../collectors/README.md`](../collectors/README.md)
- 이동 묶음: [`../portable/README.md`](../portable/README.md)
- 테스트 분류: [`../tests/README.md`](../tests/README.md)
- 유지보수 절차: [`../docs/maintenance/유지보수_가이드.md`](../docs/maintenance/유지보수_가이드.md)
