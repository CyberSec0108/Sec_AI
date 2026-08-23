# IMP-037 PC-01~18 읽기 전용 수집 실측 검증

| 항목 | 결과 |
|---|---|
| IMP | `IMP-037` |
| 검증일 | 2026-07-23 |
| 현재 상태 | `PASS` |
| 시험 환경 | 현재 Windows 11 개발 PC |
| 일반 권한 항목 | 15개 실행, 15개 수집 |
| 관리자 권한 항목 | 사용자 동의 후 별도 실행, 5개 결과 |
| 설정 전후 차이 | 일반 0건·관리자 0건 |
| 공식 Finding | 생성하지 않음 |
| 원본 수집값 저장 | 하지 않음 |
| 이동 묶음 | 생성하지 않음 |
| 다음 작업 | `IMP-038` 현재 OS 전체 판정 회귀 |

## 1. 쉽게 설명한 결과

현재 PC에서 KISA PC-01~18 점검에 필요한 Windows 자료를 읽기 전용으로 확인했다.

- 일반 사용자 권한 15개는 모두 자료를 읽었다.
- 관리자 권한 5개는 읽을 항목을 먼저 안내하고 Windows UAC에서 사용자가 허용한 뒤 별도 프로세스로 실행했다.
- 관리자 항목 중 PC-08 부팅 항목 1개는 수집했고, PC-02·04·06·10은 Windows 조회 실패 상태를 반환했다.
- 조회 실패 4개를 `양호`나 `수집 성공`으로 바꾸지 않았다.
- 일반·관리자 실행 전후 감시한 Windows 설정은 모두 동일했다.
- 비밀번호 내용, 사용자·PC 이름, SID, 저장 장치 식별자와 원본 설정값은 결과 파일에 저장하지 않았다.

이 단계의 `PASS`는 “20개 항목의 수집 결과를 안전하게 구분하고 보존했다”는 뜻이다. 현재 PC가 보안상 양호하다는 뜻이 아니며, 실제 DRAFT 판정은 IMP-038에서 검증한다.

## 2. 실제 수집 결과

| 권한 | 항목 수 | 수집 성공 | 권한 부족 | 기능 미지원 | 조회 실패 |
|---|---:|---:|---:|---:|---:|
| 일반 사용자 | 15 | 15 | 0 | 0 | 0 |
| 관리자 | 5 | 1 | 0 | 0 | 4 |
| 합계 | 20 | 16 | 0 | 0 | 4 |

관리자 항목별 상태:

| 점검 항목 | 확인 내용 | 수집 상태 |
|---|---|---|
| PC-02 | 비밀번호 최소 길이·사용 기간 등 정책 | 조회 실패 |
| PC-04 | SMB 공유와 접근 권한 | 조회 실패 |
| PC-06 | 설치 프로그램 목록 | 조회 실패 |
| PC-08 | 부팅 가능한 운영체제 항목 | 수집 성공 |
| PC-10 | Windows 업데이트 이력·빌드·재시작 필요 여부 | 조회 실패 |

조회 실패는 현재 Windows 구성과 조회 API가 반환한 원본 수집 상태다. IMP-038은 이 상태를 임의의 `PASS`로 판정하지 않고 `ERROR` 또는 `REVIEW` 경계로 연결해야 한다.

## 3. 권한과 안전 경계

관리자 수집은 다음 항목을 모두 만족했다.

1. 자동 UAC 없음
2. 실행 전 5개 항목과 이유 안내
3. 명시적 동의 switch 없이는 실행 거부
4. 이미 상승된 별도 프로세스에서만 실행
5. 30초 timeout·65,536 bytes 출력 상한
6. 실행 전후 Snapshot 차이 0건
7. 원본 record 대신 Probe ID·Control ID·상태·오류 범주·record 수만 저장

화면용 영수증은 `apps/web/data/imp037_collection.json`이며 공식 Finding과 원본 증적은 포함하지 않는다. 관리자 중간 영수증은 `runtime`에만 남고 source 산출물로 취급하지 않는다.

## 4. 다른 PC 호환 보완

현재 PC에서는 CIM 기반 운영체제 조회와 Windows PowerShell 보안 모듈 자동 로드가 환경에 따라 실패했다. 설정 쓰기나 권한 우회 없이 다음 읽기 경로로 보완했다.

- 운영체제 제품·빌드: Windows CurrentVersion 레지스트리
- 서비스 상태: Service Control Manager와 서비스별 Start 레지스트리
- 실행 정책 Snapshot: 정책·PowerShell 레지스트리와 process 환경
- 저장 장치: 기존 Storage cmdlet 유지, 권한 거부는 별도 결과로 보존

현재 고정 source SHA-256:

```text
standard controls  41e785effaa5fdbd314b04bb7fb92a2ce21b9555e6b7bca372c6104b87d1fc87
administrator      ee2b6f7e92495c048a91a6e6fc732fb8f881354fa9543254dbe9745ff9d2a9d6
PC-07 storage      cfb964afa76655f83f3bf9eaaa4db25b3f9d30eba92ecfb14ebc37a16ce0404b
safety snapshot    5c507ed7a884206a32fd30bcab67c97e7649b2253e307a60aa6c0ea75dd028c1
```

## 5. 사용자 화면

개발 화면:

```text
http://localhost:18480/ui/windows-collection
```

개발 API:

```text
http://localhost:18480/api/v1/demo/windows-collection
```

화면에는 KISA PC-01~18 기준에 맞춰 각 항목에서 무엇을 확인하는지 쉬운 한국어로 설명한다. 기술적인 Probe 이름은 보조 정보로만 표시하고, 수집 성공이 보안상 양호 판정이 아니라는 문구를 유지한다. DEV 화면 설정이 꺼져 있으면 두 경로 모두 404다.

## 6. 재실행

관리자 5개를 포함한 전체 실측:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\verify-imp037-windows-collection.ps1 -ConsentToAdministratorCollection
```

명시적 동의 switch가 없으면 관리자 프로세스와 UAC를 시작하지 않는다. 사용자는 UAC에서 취소할 수 있다.

## 7. 자동 검증

표준 명령:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

| Gate | 결과 |
|---|---|
| IMP-029·031·037 관련 집중시험 | 20 PASS |
| 전체 Pytest | 333 PASS, 기존 Starlette 경고 1건 |
| JSON Schema | 9 schemas·16 examples PASS |
| Ruff | PASS |
| mypy strict | 164 source files PASS |
| Windows 실제 수집 | 20개 결과·설정 차이 0건 |
| Docker Core | 8/8 running·healthy |
| Gateway live·ready | PASS, 의존성 4개 true |
| 화면·API | HTTP 200, 20개·수집 16·조회 실패 4 |

## 8. 배포·실행 상태 동기화

IMP-037 source와 실행 중인 컨테이너를 일치시키기 위해 migration을 확인하고 8개 프로젝트 이미지를 현재 source에서 다시 빌드한 뒤 컨테이너를 재생성했다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Up
```

최종 확인:

- `postgres`, `redis`, `aistor`, `clamav`, `api`, `worker`, `scheduler`, `gateway` 모두 `running·healthy`
- `127.0.0.1:18480/ui/windows-collection` HTTP 200
- `windows-collection-v1` 화면 marker 확인
- API `acceptance_status=PASS`, `total=20`, `collected=16`, `query_failed=4`
- `settings_diff_count=0`, `official_finding_created=false`

## 9. 남은 경계

IMP-037에서 수행하지 않은 항목:

- 현재 PC 수집값의 DRAFT Rule 판정
- 조회 실패 4개의 원인별 Windows Adapter 보완
- 실제 Package 제출과 PostgreSQL Finding 저장
- clean Windows 11 VM 회귀
- 조직 코드서명·SmartScreen·운영 다운로드

다음 구현은 `IMP-038` 하나만 진행한다.
