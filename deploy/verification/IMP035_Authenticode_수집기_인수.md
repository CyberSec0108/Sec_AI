# IMP-035 Authenticode·Collector 인수 기록

| 항목 | 결과 |
|---|---|
| IMP | `IMP-035` |
| 검증일 | 2026-07-23 |
| 현재 상태 | `PASS_WITH_DEFERRED_EXTERNAL_GATES` |
| 개발 구현 | 12/12 PASS |
| IMP 완료 | 아니요 |
| 운영 배포 준비 | 아니요 |
| Profile | `DEV-EPHEMERAL-AUTHENTICODE` |
| 외부 Gate | 3개 `DEFERRED` |

## 1. 쉽게 설명한 결과

EXE에 전자서명을 붙이고 그 서명이 파일 내용과 정확히 결합되는지 확인하는 **기술 절차**는 완성했다. 파일 한 byte를 바꾸면 Windows가 `HashMismatch`로 거부했고, 서명된 EXE도 별도 Python 없이 실행됐으며 두 악성코드 검사를 다시 통과했다.

현재 도장은 조직에서 발급한 정식 도장이 아니라 시험이 끝나면 폐기하는 **개발용 임시 도장**이다. 따라서 “서명 기능은 작동한다”는 결과이지 “다른 PC가 믿을 수 있는 정식 배포본이다”라는 결과가 아니다.

## 2. 서명 전·후 파일

| 구분 | 값 |
|---|---|
| unsigned 입력 | `runtime/imp034-artifacts/build-20260723T075526Z/SecAI-Collector-Windows-x64.exe` |
| unsigned bytes | `10,674,908` |
| unsigned SHA-256 | `050d1237a2b30954720d8f218d95ff41645fe6c04604410f009a5018b972430e` |
| signed 결과 | `runtime/imp035-artifacts/acceptance-20260723T080809Z/SecAI-Collector-Windows-x64.exe` |
| signed bytes | `10,682,576` |
| signed SHA-256 | `4a41267022faff84c5aa4a16a5dcb51356c8678a3eecd144c16755c057858a5c` |
| Release channel | `DEV-SIGNED-UNTRUSTED-OUTSIDE-TEST` |

서명은 EXE 안에 인증서와 timestamp 자료를 추가하므로 서명 전·후 SHA-256이 달라지는 것이 정상이다. 두 값을 모두 manifest에 기록했다.

## 3. 개발 서명 기준

| 기준 | 실제 값 |
|---|---|
| Key | RSA 3072 |
| Digest | SHA-256 |
| EKU | Code Signing `1.3.6.1.5.5.7.3.3` |
| Private key | Windows CNG `NonExportable`로 생성 |
| 인증서 | 30일 개발용 self-signed Publisher |
| Timestamp | DigiCert SHA-256 timestamp responder 포함 |
| Windows trust store | 개발 인증서를 등록하지 않음 |
| Private key cleanup | PASS, CurrentUser `My`에서 제거 |
| 인증서 잔여 | `My`, `Root`, `TrustedPublisher` 합계 0 |

Windows 신뢰 저장소에 개발 root를 추가하면 개발 파일을 정식 Publisher처럼 보이게 할 위험이 있다. 이 구현은 root를 설치하지 않고 signer certificate pin과 파일 변조 검사를 수행한다. 따라서 검증 후 `Get-AuthenticodeSignature`가 `UnknownError`와 `UntrustedRoot`를 표시하는 것은 예상 결과다.

## 4. 구현 인수 12개

1. IMP-034 unsigned PASS 입력과 pre-sign hash 결합
2. Authenticode SHA-256 signature와 post-sign hash
3. RSA 3072·Code Signing EKU·non-exportable DEV key
4. self-signed DEV trust anchor·signer pin·trust store 미등록
5. timestamp 존재
6. DEV CA revocation 상태 `GOOD`·24시간 이내
7. 서명 후 byte 변조 `HashMismatch` 거부
8. 서명된 EXE frozen self-check
9. signed artifact ClamAV·Defender `CLEAN`
10. 알려진 dependency 취약점 0건 유지
11. 임시 인증서·private key cleanup
12. 운영 배포·다운로드·Finding·이동 묶음 없음

모두 PASS다.

## 5. 폐기 확인 시험의 범위

자동시험은 다음 상태를 fail-closed로 거부한다.

- `REVOKED`
- `UNAVAILABLE`
- `UNKNOWN`
- 확인 시각이 24시간보다 오래됨
- 미래 시각의 확인 자료

현재 개발 인증서는 외부 CA가 운영하는 CRL/OCSP가 없는 일회성 self-signed 인증서다. 따라서 `EPHEMERAL_DEV_CA_POLICY`의 생성·폐기 기록으로만 개발 분기를 확인했다. 정식 운영 폐기 확인을 완료했다고 표시하지 않는다.

## 6. 실행 인수

서명된 EXE는 현재 Windows 11 Enterprise x64, Build `26200`, 비상승 token에서 다음을 통과했다.

- Python Runtime 없이 `self-check` 실행
- 포함 자료 40개 hash 검증
- 실제 수집 시작 안 함
- 자동 UAC 시작 안 함
- 설정 변경 안 함
- 공식 Finding 생성 안 함
- ClamAV `CLEAN`
- Microsoft Defender `CLEAN`

현재 개발 PC는 Docker와 개발 도구가 설치된 환경이므로 clean VM으로 간주하지 않는다.

## 7. 외부 Release Gate 3개

| ID | 보류 항목 | 완료에 필요한 자료 |
|---|---|---|
| `IMP035-X01` | 조직 code-signing 인증서·승인된 Publisher | 조직 또는 공인 CA가 발급한 Code Signing 인증서와 non-exportable key 접근 |
| `IMP035-X02` | 운영 CRL/OCSP 폐기 확인 | 발급 CA의 실제 revocation endpoint·정책·online/offline 확인 결과 |
| `IMP035-X03` | clean Windows 11 VM·SmartScreen 인수 | 초기화된 Windows 11 x64 VM과 Snapshot, 네트워크·Defender·SmartScreen 시험 |

현재 호스트에는 조직 코드서명 인증서와 `signtool`이 없다. Windows 11 ISO는 확인했지만 Windows Sandbox는 활성화되지 않았고 Hyper-V feature 확인·VM 생성에는 관리자 권한과 재부팅 가능성이 필요하므로 현재 프로젝트 작업에서 임의 활성화하지 않았다.

세 Gate 중 하나라도 남아 있으면 `IMP-035`의 외부 인수와 `R5-PILOT-RC`를 완료로 표시하지 않는다. 개발 구현은 `R3-WINDOWS-COLLECTOR-DEV` 범위에서만 사용할 수 있다.

## 8. 재실행

최신 IMP-034 PASS 파일을 개발용으로 다시 서명하고 검사한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\sign-imp035-windows-collector.ps1
```

이 명령은 기존 파일을 덮어쓰지 않고 `runtime/imp035-artifacts/acceptance-<UTC>`를 새로 만든다. timestamp server 요청은 45초로 제한하고 첫 server 실패 시 승인된 fallback을 한 번 시도한다.

프로젝트 전체 회귀:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

최종 결과:

- Pytest 320 PASS
- Schema 9종·example 16건 PASS
- Ruff PASS
- mypy strict 156 files PASS

## 9. Web 표시와 배포 경계

[`http://localhost:18480/ui/collector-release`](http://localhost:18480/ui/collector-release)은 개발 구현 통과와 외부 Gate 3개를 함께 표시한다. `/api/v1/demo/collector-release/download`는 존재하지 않는다.

연결된 앱 브라우저가 없어 스크린샷 검사는 수행하지 못했다. FastAPI TestClient와 실제 Gateway HTTP 응답으로 문구·metadata·404 다운로드 경계를 검증한다.

이동 묶음은 만들지 않았다.
