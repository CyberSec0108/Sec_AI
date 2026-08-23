# IMP-036 현재 Windows 11 시험 기준선 검증

| 항목 | 결과 |
|---|---|
| IMP | `IMP-036` |
| 검증일 | 2026-07-23 |
| 현재 상태 | `PASS` |
| 시험 환경 | 현재 Windows 개발 PC |
| 깨끗한 VM | 아니요, `IMP-052`로 보류 |
| 설정 전후 차이 | 0건 |
| 공식 Finding | 생성하지 않음 |
| 이동 묶음 | 생성하지 않음 |
| 다음 작업 | `IMP-037` PC-01~18 읽기 전용 수집 실측 |

## 1. 쉽게 설명한 결과

다음 실제 수집 시험을 시작하기 전에 현재 PC와 서버 구성요소가 준비됐는지 읽기 전용으로 확인했다.

- Windows 11 Home, 25H2, 빌드 `26200.8894`, x64
- 일반 사용자 토큰, 자동 관리자 전환 없음
- Microsoft Defender Antivirus 활성·실시간 보호 사용
- Windows Defender Firewall 프로필 3개 중 3개 사용
- 서명된 개발용 Collector 자체 점검 통과
- Docker Core 8개 서비스 실행·Health 통과
- 실행 전후 감시한 Windows 설정 차이 0건

현재 PC에는 개발 도구와 기존 설정이 있으므로 깨끗한 시험용 PC가 아니다. 이 결과는 개발 기능 확인이며 VM 인수, 운영 배포 또는 PC가 보안상 양호하다는 판정이 아니다.

## 2. 비식별 영수증

검증 결과는 `apps/web/data/imp036_baseline.json`에 화면 표시용 최소 정보만 기록했다.

기록하지 않은 값:

- 사용자 SID·사용자명
- 컴퓨터 이름
- 드라이브 문자·볼륨 GUID·볼륨 라벨·디스크 일련번호
- 설정 원본값과 Snapshot digest
- Docker container ID·container 이름·mount·label
- 비밀번호·token·인증서·기타 비밀값

영수증에는 OS 종류·버전·구조, 일반/관리자 구분, 보안제품 요약, Collector 자체 점검 결과, 서비스 이름별 실행·Health 여부와 설정 차이 건수만 남겼다.

## 3. 설정 전후 Snapshot

IMP-030의 고정 Snapshot 계약으로 다음 표면을 실행 전후에 같은 방식으로 비교했다.

1. PowerShell 실행 정책
2. 디스크 online·offline·read-only 상태
3. 파티션 구성과 주요 flag
4. 볼륨 파일시스템·유형·크기
5. 확인 가능한 BitLocker 잠금·보호 상태

현재 PC에서는 일반 사용자에게 Windows Storage API의 `Get-Disk` 접근이 거부됐다. 자동 권한 상승을 하지 않고, 접근할 수 없는 디스크·파티션·볼륨 표면은 원시 오류나 식별정보 대신 고정 `UNAVAILABLE` 상태로 Snapshot에 포함하도록 계약을 보강했다. 전후 모두 같은 접근 상태였고 차이는 0건이다. 접근 불가 표면의 실제 설정을 확인했다고 표시하지 않는다.

변경된 IMP-030 Snapshot source SHA-256:

```text
5c507ed7a884206a32fd30bcab67c97e7649b2253e307a60aa6c0ea75dd028c1
```

IMP-036 전용 비식별 Probe source SHA-256:

```text
dce067e96e173769bd5d1e19789d8b098fbbac52252d384169ecb59f01ac80e0
```

두 스크립트는 사용자 입력 명령을 받지 않고 설정 쓰기, 자동 UAC, 재부팅과 보안 조치를 실행하지 않는다.

## 4. 다른 PC 재실행 호환

이전 PC에서 만들어진 `runtime/imp029-collector-venv`는 Python 실행 경로가 이전 사용자 계정을 가리켜 그대로 실행할 수 없었다. IMP-036 실행 파일은 다음 순서로 잠긴 CPython 3.14.6 환경을 찾는다.

1. 기존 IMP-034 CPython 3.14.6 runtime과 잠긴 Collector site-packages
2. IMP-036 전용 가상환경
3. 설치된 `py -3.14`

이전 가상환경을 삭제하거나 사용자 파일을 덮어쓰지 않았다.

## 5. 재실행

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-imp036-windows-baseline.ps1
```

Docker named pipe와 현재 Windows 읽기 권한이 필요하지만 관리자 권한으로 자동 상승하지 않는다. 결과가 통과하면 기존 파일을 이동 묶음으로 만들지 않고 화면용 비식별 영수증만 갱신한다.

개발 화면:

```text
http://localhost:18480/ui/windows-baseline
```

개발 API:

```text
http://localhost:18480/api/v1/demo/windows-baseline
```

DEV 화면 설정이 꺼져 있으면 두 경로 모두 404이며, Collector EXE 다운로드 경로는 추가하지 않았다.

## 6. 자동 검증

표준 명령:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

| Gate | 결과 |
|---|---|
| IMP-030·031·036 집중시험 | 23 PASS |
| 전체 Pytest | 326 PASS, 기존 Starlette 경고 1건 |
| JSON Schema | 9 schemas·16 examples PASS |
| Ruff | PASS |
| mypy strict | 160 source files PASS |
| Windows 실제 기준선 | PASS |
| Docker Core | 8/8 running·healthy |
| 설정 전후 | 동일, 차이 0건 |
| 비식별 API·DEV 외 404 | PASS |

## 7. 배포·실행 상태 동기화

IMP-036 source와 실행 중 컨테이너의 불일치를 남기지 않기 위해 다음 명령으로 8개 프로젝트 이미지를 현재 source에서 다시 빌드하고 migration을 적용한 뒤 컨테이너를 재생성했다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Up
```

최종 확인:

- `postgres`, `redis`, `aistor`, `clamav`, `api`, `worker`, `scheduler`, `gateway` 8개 모두 `running·healthy`
- Gateway live `ok`
- Gateway ready의 PostgreSQL·Redis·AIStor·ClamAV 모두 `true`
- `/ui/windows-baseline` HTTP 200, `windows-baseline-v1` marker 확인
- `/api/v1/demo/windows-baseline` `PASS`, 설정 차이 0, Core Health 8, `clean_vm_verified=false`

## 8. 남은 경계

IMP-036에서 수행하지 않은 항목:

- PC-01~18 전체 실제 수집과 판정
- 관리자 Probe 5개 실행
- VM 생성·Hyper-V 활성화·재부팅
- 조직 코드서명 인증서 설치·SmartScreen 인수
- 운영 다운로드·Pilot 승인
- DRAFT 결과의 공식 판정 표시

다음 구현은 `IMP-037` 하나만 진행한다.
