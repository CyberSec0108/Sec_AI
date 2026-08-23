# IMP-029 Windows context·PC-07 읽기 전용 Probe 검증

## 1. 완료 범위

| 항목 | 결과 |
|---|---|
| 구현 단계 | `IMP-029` |
| 대상 | 현재 Windows 11 x64와 KISA `PC-07` |
| 실행 방식 | 고정 PowerShell source를 현재 사용자 권한으로 읽기 전용 실행 |
| Probe | `win.storage.disks`, `win.storage.partitions`, `win.storage.volumes` |
| 자동 권한 상승 | 없음 |
| 설정 변경 | 없음 |
| 공식 Finding | 생성하지 않음 |
| 다음 단계 | `IMP-030` 권한 분리·Probe 안전성 |

이 단계의 `COLLECTED`는 자료를 읽었다는 뜻이다. PC가 안전하다는 `PASS`가 아니며 파일시스템의 공식 판정은 검증·정규화된 Evidence를 받은 Audit Pack 규칙 엔진만 담당한다.

## 2. 주요 산출물

| 산출물 | 용도 |
|---|---|
| `src/security_audit/collector/windows.py` | 실행 계획 제한, script hash, Windows context·출력 검증 |
| `collectors/one_shot/probes/windows/powershell/pc07_storage_context.ps1` | 고정 읽기 전용 Windows Probe |
| `collectors/one_shot/contracts/imp029_probe_allowlist.json` | 실제 OS 접근을 허용한 PC-07 세 Probe 계약 |
| `collectors/one_shot/fixtures/imp029/windows_read_only_sample.json` | 개인정보가 없는 비식별 계약 시험 자료 |
| `tools/verify-imp029-windows.ps1` | 현재 PC에서 다시 실행하는 사용자용 검증 파일 |
| `/ui/windows-context` | 비식별 context와 안전 경계 안내 |
| `/api/v1/demo/windows-context` | DEV 전용 비식별 context API |

PowerShell source SHA-256:

```text
cfb964afa76655f83f3bf9eaaa4db25b3f9d30eba92ecfb14ebc37a16ce0404b
```

Collector는 실행 직전에 이 값과 source를 다시 비교한다. 값이 다르면 PowerShell을 시작하지 않고 `SCRIPT_INTEGRITY_MISMATCH`로 거부한다.

## 3. 무엇을 읽고 무엇을 읽지 않는가

### 읽는 값

- Windows 제품명, 표시 버전, Build, UBR, x64 여부
- 현재 process SID와 관리자 토큰 여부
- 디스크 bus 종류·online 여부·virtual/removable 분류
- 파티션 GPT type·boot/system/hidden 여부
- 볼륨 filesystem·drive type·health·mount 종류
- 확인 가능한 경우 BitLocker 잠금·보호 상태

### 수집하지 않는 값

- 사용자 이름, 전자우편 주소와 조직명
- 호스트 이름, MAC 주소와 장치 serial
- Windows Product ID와 license 값
- 디스크 FriendlyName과 volume label
- 파일·폴더 목록과 파일 내용
- folder mount의 실제 로컬 경로

현재 process SID는 scope 확인에 필요한 실행 context지만 검증 보고서와 웹 화면에는 원문을 남기지 않는다. 형식 일치 여부만 기록하고 `S-1-5-21-[REDACTED]`로 표시한다.

## 4. PowerShell 실행 경계

현재 PC의 script execution policy가 `.ps1` 직접 실행을 제한하더라도 policy 값을 변경하지 않는다. Python Collector가 hash 검증을 끝낸 고정 ASCII source를 `powershell.exe -EncodedCommand`로 전달한다.

- `-ExecutionPolicy Bypass`를 Collector 명령에 넣지 않는다.
- `shell=True`, `Invoke-Expression`, 사용자 제공 command와 사용자 제공 parameter를 사용하지 않는다.
- Base64는 암호화나 은닉 수단이 아니라 Windows PowerShell 인자 quoting 손실을 막는 전송 형식이다.
- 실행 파일은 `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`로 고정한다.
- stderr의 실제 환경 문자열은 사용자 화면이나 검증 문서에 복사하지 않는다.

`tools/verify-imp029-windows.ps1` 실행 예시의 `-ExecutionPolicy Bypass`는 검증 wrapper 1회 process에만 적용되며 시스템 execution policy를 저장·변경하지 않는다. 운영 배포본의 code signing과 Authenticode는 `IMP-034~035` Gate다.

## 5. 현재 Windows 실제 실행 결과

2026-07-23 현재 프로젝트 PC에서 `tools/verify-imp029-windows.ps1`을 실행했다.

| 확인 항목 | 비식별 결과 |
|---|---|
| OS target | Windows 11 Enterprise x64 |
| 표시 버전·Build | `25H2`, `26200.8875` |
| 현재 토큰 | 관리자 토큰 아님 |
| SID | Windows SID 형식 확인, 원문 미저장 |
| `win.storage.disks` | `COLLECTED`, 4 record |
| `win.storage.partitions` | `COLLECTED`, 4 record |
| `win.storage.volumes` | `COLLECTED`, 4 record |
| synthetic | `false` |
| 실제 원시 결과 저장 | 없음 |
| 설정 변경 | 없음 |
| 공식 Finding | 없음 |

실제 drive letter, volume GUID, volume label과 SID는 이 기록에 넣지 않았다. Probe 내부 결합 ID도 실행마다 `vol-001` 형식의 불투명 번호로 바꾼다.

## 6. 오류와 판정의 분리

| 상황 | Collector 처리 | 보안 판정 |
|---|---|---|
| Windows 11 x64가 아님 | `TARGET_CONTEXT_MISMATCH` | `FAIL` 아님 |
| PowerShell 실행 불가 | `POWERSHELL_UNAVAILABLE` | `FAIL` 아님 |
| script hash 불일치 | `SCRIPT_INTEGRITY_MISMATCH` | 실행 전 거부 |
| timeout | `PROBE_TIMEOUT` | `FAIL` 아님 |
| 출력 한도 초과 | `OUTPUT_TOO_LARGE` | `FAIL` 아님 |
| SID·storage 출력 형식 오류 | `PROBE_OUTPUT_INVALID` | `FAIL` 아님 |
| BitLocker/파일시스템 확인 불가 | `UNKNOWN` evidence | 이후 규칙 엔진에서 `ERROR` 후보 |

권한 부족, 수집 실패와 형식 오류를 취약 `FAIL`로 바꾸지 않는 기존 원칙을 유지한다.

## 7. 자동 검증

표준 전체 검증:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

현재 Windows 실제 읽기:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-imp029-windows.ps1
```

검증 기준선:

| Gate | 결과 |
|---|---|
| Pytest | `259 passed` |
| JSON Schema | 8 schemas·14 examples PASS |
| Ruff | PASS |
| mypy strict | 123 source files PASS |
| 현재 Windows 실제 Probe | 6/6 acceptance check PASS |
| Core service | 8개 healthy |
| `/ui/windows-context` | HTTP 200, 필수 문구·비식별 표시 PASS |

기존 Starlette `httpx` deprecation warning 1건은 계속 존재하며 이번 변경에서 새 warning은 추가하지 않았다.

Codex in-app browser가 현재 세션에 연결되어 있지 않아 screenshot 기반 시각 검사는 실행하지 못했다. 대신 Jinja render 단위시험, 필수 한글 문구·비식별 값 검사, 재빌드된 Gateway의 HTTP 200과 DEV API 응답을 확인했다. 화면의 최종 육안 검토는 브라우저 연결이 가능한 환경에서 다시 수행할 수 있다.

## 8. 보류 범위

다음 항목은 IMP-029 완료로 간주하지 않는다.

- 관리자 권한이 필요한 Probe를 별도 process로 상승 실행
- timeout 시 process tree 종료와 streaming output hard cap 강화
- 실행 전후 설정 snapshot을 통한 변경 0건 기계 검증
- PC-01~18 전체 native Probe와 제품 Adapter
- Online/Offline 제출·서명·재전송 방지
- PyInstaller Windows x64 artifact·SBOM·악성코드 검사
- Authenticode 서명과 clean Windows 11 인수

위 항목 중 권한 분리와 안전 제한 강화는 바로 다음 `IMP-030`에서 진행한다.
