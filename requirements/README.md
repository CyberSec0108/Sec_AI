# Python dependency locks

이 디렉터리는 Sec_AI의 사람이 관리하는 직접 의존성 입력(`*.in`)과 `pip-tools`가 생성한 해시 잠금파일(`lock/*.lock`)을 보관한다.

## 디렉터리 구조

```text
requirements/
├─ *.in                         사람이 검토하는 직접 의존성 입력
├─ constraints.in               공통 version 상한·정합성 제약
├─ lock/*.lock                  플랫폼별 전체 transitive hash lock
├─ verification/*.json          공통 version·advisory·lock 검증 기준
├─ LOCK-SHA256SUMS.txt           lock 파일 자체의 SHA-256 목록
└─ 잠금_메타데이터.md            생성 환경·명령·image digest 기록
```

`*.in`과 `lock/*.lock`을 모두 사람이 직접 편집하지 않습니다. 직접 의존성 의도는 `*.in`에 기록하고, 승인된 builder가 transitive dependency와 모든 허용 wheel hash를 lock에 생성합니다.

## Runtime matrix

| Lock | Runtime | Platform | 용도 |
|---|---|---|---|
| `api.lock` | CPython 3.14.6 | Linux amd64 | FastAPI API/UI |
| `worker.lock` | CPython 3.14.6 | Linux amd64 | Celery Worker/Beat, LangGraph workflow |
| `ingestion.lock` | CPython 3.14.6 | Linux amd64 | 가이드 parsing/ingestion |
| `collector.lock` | CPython 3.14.6 | Windows amd64 | Collector runtime dependency |
| `collector-build.lock` | CPython 3.14.6 | Windows amd64 | PyInstaller build environment |
| `linux-collector-build.lock` | CPython 3.14.6 | manylinux glibc 2.34 x86_64 | Ubuntu 24.04·Rocky 9 원샷 Collector build |
| `dev.lock` | CPython 3.14.6 | Linux amd64 | CI와 개발 도구 |

`remediation.in`은 후속 기능의 자리만 예약한다. `ADR`과 실행 모델이 승인되기 전에는 `remediation.lock`을 만들지 않는다.

`rfc8785==0.1.4`는 canonical JSON hash·서명 입력을 만드는 공통 직접 의존성이다. Linux API·Worker·Ingestion·DEV lock과 IMP-028 Windows Collector runtime·build lock에 동일 version과 PyPI artifact SHA-256을 기록한다.

## Rules

1. 직접 의존성은 해당 `*.in`에서만 변경한다.
2. 운영 및 build 설치는 `lock/*.lock`만 사용한다.
3. 설치할 때 반드시 `python -m pip install --require-hashes --no-compile -r <lock>`를 사용하고 이어서 `python -m pip check`를 실행한다.
4. Linux lock은 승인된 dependency-builder container에서, Windows Collector lock은 신뢰된 Windows 11 x64 runner에서 생성한다.
5. lock 재생성 후 diff, license, vulnerability, wheel 제공 여부와 test 결과를 검토한다.
6. 운영 build에서 index URL을 바꾸거나 승인되지 않은 source distribution을 즉석 build하지 않는다.
7. `pip`, `setuptools`, `wheel`, `pip-tools` 자체도 플랫폼별 `build-tools-*.lock`에 별도로 잠근다.

재생성 명령과 build environment의 digest는 `잠금_메타데이터.md`에 기록한다.

## 입력과 lock 연결

| 입력 | 생성되는 주요 lock | 소비자 |
|---|---|---|
| `base.in`, `api.in` | `lock/api.lock` | API·Web |
| `base.in`, `worker.in` | `lock/worker.lock` | Worker·Scheduler |
| `base.in`, `ingestion.in` | `lock/ingestion.lock` | Guide ingest |
| `collector.in` | `lock/collector.lock` | Windows Collector runtime |
| `collector-build.in` | `lock/collector-build.lock` | Windows native builder |
| `linux-collector.in`, `linux-collector-build.in` | `lock/linux-collector-build.lock` | Linux one-shot builder/runtime |
| `dev.in` | `lock/dev.lock` | pytest·Ruff·mypy·Schema 도구 |
| `build-tools.in` | `lock/build-tools-*.lock` | 플랫폼별 lock/build toolchain |

`verification/*.json`은 단순 메모가 아니라 공통 package version, 특정 advisory 처리와 runtime/build lock의 일치 조건을 고정합니다. dependency를 바꾸면 대응 검증 기준과 `LOCK-SHA256SUMS.txt`도 함께 갱신합니다.

## 안전한 갱신 절차

1. 공급자 release note, Python/platform 지원, license와 알려진 취약점을 확인합니다.
2. 직접 의존성만 해당 `*.in`에서 변경합니다.
3. [`잠금_메타데이터.md`](잠금_메타데이터.md)에 기록된 exact builder에서 lock을 재생성합니다.
4. diff에서 예상하지 않은 package·index·source distribution·hash 변화를 검토합니다.
5. `--require-hashes --no-compile`로 새 환경에 설치하고 `pip check`를 실행합니다.
6. SBOM과 취약점 DB를 갱신하고 Critical/High 및 악용 가능성을 검토합니다.
7. 관련 단위·통합·native build 시험을 실행합니다.
8. lock 자체 SHA-256과 생성 환경 기록을 갱신합니다.

인터넷이 연결된 개발 PC에서 즉석 `pip install`한 결과를 운영 lock으로 복사하지 않습니다. Windows와 manylinux wheel은 각 승인 플랫폼에서 생성·검증하며, wheel이 없다는 이유로 운영 build에서 임의 source compile을 허용하지 않습니다.

## 변경 체크리스트

- [ ] 새 production dependency가 표준 라이브러리나 기존 package로 대체 불가능한지 검토했습니다.
- [ ] 정확한 version·artifact hash·license·공급자 출처를 확인했습니다.
- [ ] runtime lock과 build lock을 혼동하지 않았습니다.
- [ ] 모든 transitive artifact가 hash로 잠겼습니다.
- [ ] `pip check`, SBOM, 최신 취약점 DB와 관련 시험을 통과했습니다.
- [ ] 변경 이유와 생성 image digest를 메타데이터에 기록했습니다.
- [ ] 비밀 index credential이나 내부 URL을 lock·로그에 넣지 않았습니다.

Docker에서 lock을 소비하는 위치는 [`../deploy/README.md`](../deploy/README.md), Collector build 경계는 [`../collectors/README.md`](../collectors/README.md), 전체 검증 명령은 [`../tools/README.md`](../tools/README.md)를 확인합니다.
