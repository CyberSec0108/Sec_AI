# IMP-034 Windows x64 Native Build 검증 기록

| 항목 | 결과 |
|---|---|
| IMP | `IMP-034` |
| 검증일 | 2026-07-23 |
| 상태 | `PASS` |
| 대상 | Windows 11 x64 One-shot Collector 개발 빌드 |
| 산출물 | `SecAI-Collector-Windows-x64.exe` |
| Release channel | `DEV-UNSIGNED` |
| 다음 단계 | `IMP-035` Authenticode·Collector 인수 |

## 1. 이번 단계의 의미

Python source를 대상 PC에 복사하는 대신 Windows에서 바로 실행할 수 있는 단일 EXE를 만들었다. 빌드에 사용한 Python·PyInstaller·외부 부품 버전을 고정하고, “어떤 부품이 들어갔는지”를 적은 SBOM과 파일 해시·취약점·악성코드 검사 영수증을 함께 만들었다.

이 통과는 **서명 전 개발 파일을 재현하고 검사할 수 있다**는 뜻이다. 아직 전자서명된 운영 배포본, 실제 PC 수집 승인 또는 공식 보안 판정 완료를 뜻하지 않는다.

## 2. 확정 빌드 기준

| 기준 | 실제 값 |
|---|---|
| Builder OS | Windows 11 x64 |
| Python | CPython `3.14.6` |
| PyInstaller | `6.21.0` |
| Packaging | one-file, console, no UPX |
| PE 형식 | PE32+ AMD64 (`0x8664`) |
| Artifact version | `0.1.0` |
| Artifact bytes | `10,674,908` |
| Artifact SHA-256 | `050d1237a2b30954720d8f218d95ff41645fe6c04604410f009a5018b972430e` |
| Dependency lock | `requirements/lock/collector-build.lock` |
| Lock SHA-256 | `6319eb0a3b0443d646157cc9f4f3ad466d18f821a98fd67c6eb291e2e8277f73` |
| Locked components | 24 |
| Embedded resources | 40 |
| Source snapshot SHA-256 | `51da327b009cf1749eeea55c8fe23518a78bdc6323625c15d8f75c1627fde05a` |

실행 파일의 Windows 제품 정보에는 `Sec_AI Project`, `Sec_AI Windows One-shot Security Collector`와 원본 파일명이 들어가 다른 프로젝트 실행 파일과 구분된다.

현재 호스트에는 Git client가 없어 commit ID는 `UNAVAILABLE_NO_GIT_CLIENT`로 기록했다. 대신 build 입력 130개 파일의 경로·크기·SHA-256을 결합한 source snapshot SHA-256을 manifest에 남겼다. Git이 준비된 정식 build runner에서는 commit ID도 함께 기록해야 한다.

## 3. 자동 인수 결과

다음 10개 기준을 모두 통과했다.

1. Windows 11 x64 native builder 사용
2. CPython 3.14.6·PyInstaller 6.21.0 exact build
3. `--require-hashes` 설치와 dependency lock 결합
4. PE32+ AMD64 one-file과 100 MiB 상한
5. 별도 Python 없는 frozen self-check와 embedded resource hash 확인
6. CycloneDX SBOM과 lock의 exact component 일치
7. pip-audit 알려진 취약점 0건
8. ClamAV·Microsoft Defender 모두 `CLEAN`
9. unsigned 개발 경계와 IMP-035 Authenticode 보류
10. 설정 변경·자동 상승·실제 수집·Finding·이동 묶음 없음

Self-check는 Collector module 54개 export와 포함 자료 40개를 확인했다. 이 명령은 호스트 보안 설정을 읽지 않고 실제 수집을 시작하지 않는다.

## 4. 공급망·악성코드 검사

| 검사 | 결과 |
|---|---|
| CycloneDX JSON SBOM | lock의 24개 이름·버전과 exact match |
| pip-audit `2.10.1` | 알려진 취약점 `0` |
| ClamAV | `CLEAN` |
| Microsoft Defender | `CLEAN` |
| Authenticode | `NOT_SIGNED`, IMP-035로 보류 |

ClamAV와 Defender 영수증은 모두 최종 EXE의 동일 SHA-256을 기록한다. Defender는 수정·삭제 없이 검사만 하도록 실행했다. “취약점 0건”은 검사 시점에 pip-audit 데이터베이스에 알려진 항목이 없었다는 뜻이며, 미래의 취약점까지 없음을 보장하지 않는다.

## 5. 생성 파일

최종 개발 결과는 source가 아닌 다음 runtime 디렉터리에 있다.

```text
runtime/imp034-artifacts/build-20260723T075526Z/
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

`runtime/`은 source 관리 대상이 아니다. 사용자가 요청한 이동 묶음도 만들지 않았다.

## 6. 누구나 다시 실행하는 파일

프로젝트 루트의 PowerShell에서 다음 한 명령을 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build-imp034-windows-collector.ps1
```

이 파일은 다음 작업을 순서대로 자동 수행한다.

```text
정확한 Python 3.14.6 준비
→ hash lock 설치와 pip check
→ PyInstaller Windows x64 build
→ frozen self-check·PE 검사
→ CycloneDX SBOM·pip-audit
→ ClamAV·Microsoft Defender
→ Authenticode 현재 상태 확인
→ manifest·SHA256SUMS·10개 인수 결과 생성
```

매 실행은 새 timestamp 디렉터리를 만든다. 기존 결과를 덮어쓰지 않는다. 온라인 PyPI 취약점 조회, 실행 중인 Sec_AI ClamAV 컨테이너와 활성 Microsoft Defender가 필요하다.

## 7. 개발용 Web 정보 화면

[`http://localhost:18480/ui/collector-build`](http://localhost:18480/ui/collector-build)은 파일명·버전·SHA-256·SBOM·취약점·악성코드 검사 상태만 표시한다. 화면과 JSON API에는 EXE bytes, 라이선스, 비밀키 또는 원본 증적이 없다.

`/api/v1/demo/collector-build/download` 경로는 존재하지 않는다. `SECAI_DEV_DEMO_ENABLED=false` 환경에서는 화면과 정보 API도 404다.

앱 브라우저가 현재 Codex에 연결되지 않아 스크린샷 기반 시각 검사는 수행하지 못했다. 대신 FastAPI TestClient와 실제 Gateway HTTP 응답으로 문구·상태·다운로드 부재를 검증한다.

## 8. 회귀검증

프로젝트 표준 명령:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

최종 기준:

- Pytest: 309 PASS
- JSON Schema: 9 schemas·16 examples PASS
- Ruff: PASS
- mypy strict: 152 source files PASS
- Core: AIStor 포함 8개 서비스와 Gateway readiness PASS

## 9. 남은 경계

IMP-035 전에는 다음을 완료로 보지 않는다.

- 실제 조직 code-signing 인증서와 non-exportable private key
- Authenticode 서명·timestamp·인증서 chain·폐기 확인
- 서명 후 artifact SHA-256·SBOM·악성코드 재검사
- 깨끗한 Windows 11 VM에서 SmartScreen·백신 포함 실행 인수
- 관리자 5개 Probe의 명시적 승인 기반 실측
- 서명된 파일의 다운로드·배포 승인

따라서 IMP-034의 EXE는 운영 PC에 배포하거나 공식 점검에 사용하지 않는다.
