# Windows·Linux DEV-SIGNED-TEST 다운로드 검증

## 1. 목적

조직용 운영 인증서가 준비되기 전 개발시험 범위에서 Windows·Ubuntu·Rocky 점검 프로그램을 중앙 UI로 안전하게 내려받아 실행할 수 있는지 검증한다.

이 기록은 운영 서명 승인이 아니다. 결과 채널은 `DEV-SIGNED-TEST`, `production_release=false`로 고정한다.

## 2. 구현 경계

- 외부 개인키: `%LOCALAPPDATA%\Sec_AI\dev-signing\dev-download-ed25519.pem`
- API 공개 범위: 공개키·서명 Catalog·세 실행파일을 담은 `runtime/dev-signed-downloads`의 읽기 전용 bind만 허용
- 공통 서명: Ed25519로 각 파일 SHA-256과 Catalog를 분리 서명
- Windows 추가 서명: IMP-035 개발용 self-signed Authenticode
- 코드: 로그인 사용자만 발급, 20글자, 10분, 1회, OS·Catalog hash·파일 hash scope, HMAC-only 저장
- 공개 fetch: 정확한 `/api/v1/dev-downloads/fetch/{platform}` POST만 인증 middleware 예외. 코드 원문은 body로만 전달
- 네트워크: Gateway는 계속 `127.0.0.1:18480`만 bind. Linux VM은 SSH reverse tunnel 사용
- 실패 정책: 만료·폐기·서명·hash·path·size·Gate 중 하나라도 불일치하면 파일을 보내지 않음

## 3. 실제 임시 Release

| 항목 | 값 |
|---|---|
| Release | `release-20260806T035227Z` |
| Profile | `SECAI-DEV-SIGNED-DOWNLOAD-V1` |
| Channel | `DEV-SIGNED-TEST` |
| Production | `false` |
| Download allowed | `true` |
| 만료 | 2026-08-13 03:52:30Z |
| Catalog SHA-256 | `9fb20fd99a5aa0fa2cc8233861b359c9b8b4b9d3f75b6b9187396a8859e13165` |

| Platform | 파일 | bytes | SHA-256 |
|---|---|---:|---|
| Windows 11 x64 | `SecAI-Collector-Windows-x64.exe` | 12,718,680 | `9e85d11f82b5d0f0976b8de34995995dd4f7295ca09100c63ea2cea84ed45e2b` |
| Ubuntu 24.04 x64 | `secai-linux-check-ubuntu24-x86_64` | 33,206,344 | `42413e0d49d96c97b6fe1e1c08bf9ebb84b7e35499ddd24d6c79819400214443` |
| Rocky 9 x64 | `secai-linux-check-rocky9-x86_64` | 33,206,336 | `08a716a2ed343ff20f76a56b27dafe5b1de0ba7ec7fb869878e8ab8833d04dfd` |

Windows 입력은 `runtime/imp035-artifacts/acceptance-20260806T034811Z`, Linux 입력은 `runtime/linux-oneshot-artifacts/build-20260806T021722Z`다. Windows IMP-035는 구현 Gate 12/12, 취약점 0, ClamAV·Defender CLEAN이며 Linux Release는 의존성 PASS·악성코드 CLEAN·OS Gate PASS다.

## 4. 자동 검증

### 4.1 TDD

구현 전 세 테스트 파일이 `ModuleNotFoundError`로 실패하는 것을 확인한 뒤 최소 구현을 추가했다. 대용량 Linux 다운로드 실패 재현 뒤 Gateway 전용 streaming 회귀 테스트를 추가했고, 수정 전 1 FAIL·수정 후 PASS를 확인했다.

### 4.2 집중 시험

```text
pytest tests/unit/test_dev_signed_artifact_download.py
       tests/unit/test_dev_signed_download_ui_contract.py
       tests/unit/test_dev_signed_download_api.py -q
```

결과: `8 passed`, Starlette TestClient deprecation warning 1건. 기능 실패는 아니다.

검증 범위:

- Catalog·artifact Ed25519 정상 검증
- 파일 변조·서명 변조·만료·폐기·path 탈출 차단
- 코드 scope·만료·1회 사용·HMAC-only 저장
- 비로그인 코드 발급 차단, CSRF 차단
- 정상 파일 fetch와 replay 401
- UI의 세 OS·hash·브라우저 검증·URL secret 금지
- 공개 fetch middleware 예외의 exact path
- API read-only runtime mount
- Gateway의 대용량 fetch `proxy_buffering off`, `proxy_cache off`

추가 결과:

- Ruff 변경 파일: PASS
- mypy strict 집중 5 source files: PASS
- JavaScript `node --check` 2개: PASS
- Compose config: PASS
- 재빌드 Gateway `nginx -t`: PASS
- Core health live/ready: PASS

기존 인증·계정 승인·Linux 원샷 API·제품 홈까지 넓힌 회귀에서는 38 PASS와 기존 불일치 1 FAIL을 확인했다. 실패 1건은 이미 로그인 화면에서 제거된 `현재는 개발용 로그인입니다.` 문구를 옛 `test_imp046_auth_rbac_web_security.py`가 계속 요구하는 문제로 이번 다운로드 변경과 관련이 없다. 테스트를 skip하거나 기대값을 임의로 바꾸지 않았다.

## 5. 실제 Gateway 다운로드 E2E

DEV-LOCAL 로그인→MFA→다운로드 UI→코드 발급→public fetch→SHA-256→같은 코드 replay 순서로 실제 `localhost:18480`을 호출했다.

| Platform | HTTP | SHA-256 | 같은 코드 재사용 |
|---|---:|---|---:|
| Windows | 200 | MATCH | 401 |
| Ubuntu | 200 | MATCH | 401 |
| Rocky | 200 | MATCH | 401 |

UI는 HTTP 200, Release channel은 `DEV-SIGNED-TEST`, artifact 3개, `production_release=false`를 반환했다.

첫 시험에서는 Windows 12.7MB는 성공했으나 Ubuntu 33.2MB가 Gateway 16MB tmpfs buffering 때문에 중단됐다. 다운로드 전용 location만 `proxy_buffering off`로 변경한 뒤 세 파일 모두 정상 완료했다. 전체 location이나 다른 API의 buffering 정책은 변경하지 않았다.

## 6. 실행 확인

### 6.1 Windows

Gateway로 받은 Windows 복사본에서 다음을 확인했다.

| 항목 | 결과 |
|---|---|
| frozen self-check | PASS |
| Authenticode type | Authenticode |
| signer certificate 존재 | true |
| host trust | `UnknownError` |

`UnknownError`는 self-signed 개발 인증서를 IMP-035 시험 종료 시 신뢰 저장소에서 제거한 결과다. 조직 신뢰를 뜻하지 않으며 공통 Ed25519 Catalog·파일 hash 검증이 다운로드 Gate 역할을 한다.

### 6.2 Ubuntu·Rocky VM

시험 VM을 켜고 Windows→VM SSH reverse tunnel `18480:127.0.0.1:18480`을 연 뒤, UI가 발급한 코드를 stdin으로 전달해 VM이 직접 다운로드했다.

| VM | 결과 |
|---|---|
| Ubuntu 24.04 x86_64 | `DOWNLOAD_HASH_EXEC=PASS` |
| Rocky Linux 9 x86_64 | `DOWNLOAD_HASH_EXEC=PASS` |

두 VM 모두 파일 hash 일치, 실행파일 권한 설정, `--help` 실행을 통과했다. 코드 원문은 URL·명령 인자·출력에 포함하지 않았고 생성한 `/tmp` 파일은 시험 직후 제거했다. 시험을 위해 켠 Ubuntu·Rocky VM은 정상 종료했으며 기존 Aruba VM은 건드리지 않았다.

## 7. 남은 운영 Gate

- 조직 발급 Authenticode/Ed25519 인증서와 승인 key ID
- 운영 HSM/KMS 또는 서명 서비스와 다인 승인
- 운영 CRL/OCSP·폐기 목록 배포
- 영구 감사 DB·다중 API instance 공유 code store
- HTTPS 조직 주소·SSO·방화벽·Pilot 단말 신뢰 설치
- Windows clean VM·SmartScreen, Linux 운영 지원 Matrix 전체 인수

따라서 현재 결과는 개발시험용 다운로드 가능 상태이며 운영 배포 완료로 표시하지 않는다.
