# SWITCH-03 Aruba AOS-CX 실제 VM 읽기 전용 검증

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-08-06 |
| 대상 | HPE Aruba Networking AOS-CX Virtual 10.13.1170 |
| 가상화 | VMware Workstation, VMnet1 Host-only |
| 관리 주소 | `192.168.11.10/24` |
| REST API | `v10.13`, HTTPS `443`, 설정 조회는 고정 `GET`만 허용 |
| 결론 | 안전·취약 판정, 오류 경계 4종, 설정 불변 Gate 통과 |
| 제품 상태 | 개발용 실제 벤더 VM 세로 기능. 운영 Pack·UI·PDF·AI 인수 전 `LIVE` 금지 |

## 1. 이미지와 격리 경계

- OVA: `ArubaOS-CX_10_13_1170.ova`
- OVA SHA-256: `9d88e4842c108f573faceffd30bf27488d63ac07fee68f856afb7cc8beef4a6a`
- HPE 분리 서명 검증: 정상
  - 서명 키 지문: `EDA4 A571 61C0 F8F1 3F56 2671 484B 6AFC 9A72 41F1`
  - 서명 시각: 2026-04-22
  - 키는 서명 뒤 만료됐으므로 당시 유효성 기준으로만 기록한다.
- VMware NIC는 `VMnet1` Host-only만 사용하며 Bridged/NAT를 연결하지 않았다.
- AOS-CX Virtual Platform의 화면 고지에 따라 본 VM은 교육·시험용이며 운영 지원 장비로
  간주하지 않는다.

## 2. 신뢰 고정과 자격증명 경계

- HTTPS 인증서 SHA-256 pin:
  `7a13d90345b418a28cc2c01f2bb1dcac8fdee60dffb6fe377dc29d6dd3146cb0`
- TLS 최소 버전은 1.2로 제한했다.
- SSH host key는 별도 `known_hosts`에 고정했다.
- 비밀번호와 SNMP 인증·암호화 키는 Windows DPAPI 파일에서 실행 중에만 복호화했다.
- 자격증명은 명령행 인자·환경 변수·검증 문서·로그에 기록하지 않았다.
- running-config 원문은 저장하지 않고 메모리에서 즉시 SHA-256으로 축소했다.

## 3. 안전 구성

다음 설정을 콘솔에서 적용하고 startup-config에 저장한 뒤 전원이 꺼진 상태로
`secai-aruba-safe-readonly` 스냅샷을 생성했다.

- 관리 VRF의 SSH와 HTTPS REST 활성화
- `https-server rest access-mode read-only`
- HTTPS session timeout 10분
- CLI session timeout 10분, 사용자별 최대 세션 2개
- 관리 VRF의 SNMP, SNMPv3-only, 인증·암호화가 적용된 읽기 전용 SNMPv3 사용자
- Host-only 수집 주소를 원격 syslog 대상으로 설정
- Host-only 수집 주소를 NTP 서버로 설정하고 NTP client와 관리 VRF 활성화

SNMP 사용자 이름 외의 SNMP 비밀값과 장비 자격증명은 기록하지 않았다.

## 4. 취약 구성과 스냅샷

안전 상태에서 관리 IP·SSH·HTTPS·REST read-only는 보존한 채 다음 항목을 제거하거나
비활성화했다.

- SNMPv3 사용자와 SNMPv3-only 제한
- 원격 syslog 대상
- NTP 서버와 NTP client 활성화
- CLI session timeout·사용자별 세션 제한
- HTTPS idle session timeout

적용 뒤 startup-config에 저장하고 전원이 꺼진 상태로
`secai-aruba-vulnerable-readonly` 스냅샷을 생성했다. 최종 실행 상태는 안전 스냅샷으로
복귀했다.

확인된 스냅샷은 다음 두 개다.

1. `secai-aruba-safe-readonly`
2. `secai-aruba-vulnerable-readonly`

## 5. REST 수집 계약

수집 구현은 AOS-CX 10.13 전용 Adapter에서 다음을 강제한다.

- 로그인·로그아웃 세션 생성/폐기 `POST` 외 설정 수집은 승인된 고정 `GET`만 사용
- `/rest`에서 API version을 확인하고 `v10.13`만 허용
- 현재 사용자, system, management VRF, SNMPv3 사용자, syslog remote, NTP association만 조회
- 임의 path·method, `PUT`, `PATCH`, `DELETE`, 구성 변경 호출 거부
- 인증서 pin 불일치 시 HTTP 요청 전 연결 차단
- 응답 JSON content type·크기·구조를 fail-closed로 검증
- 원문 JSON을 저장하지 않고 SW-01~06 boolean projection으로 즉시 축소

10.13.1170에서 `user_group`과 `ntp_config_vrf`가 URI map으로 반환되고, 관리 VRF NTP
설정 행이 default association 컬렉션에 나타나는 실제 응답 차이를 전용 정규화에 반영했다.

## 6. SW-01~06 실제 판정

| Control | 확인 항목 | 안전 Snapshot | 취약 Snapshot |
|---|---|---:|---:|
| SW-01 | 관리자 REST 인증 보호 | PASS | PASS |
| SW-02 | 관리 VRF SSH 활성화 | PASS | PASS |
| SW-03 | SNMPv3-only와 인증·암호화 사용자 | PASS | FAIL |
| SW-04 | 활성 원격 syslog | PASS | FAIL |
| SW-05 | 관리 VRF NTP 설정 | PASS | FAIL |
| SW-06 | CLI·HTTPS 유휴 세션 15분 이하 | PASS | FAIL |

- 안전 projection SHA-256:
  `11848e85d916d7d13607911b4486b31025842c0ff77d0e975aeaa5fa9f0baa9a`
- 취약 projection SHA-256:
  `0ffeefa6e0413ad748edafe546a3e7552a501ddbfb8d24affeaa14fff87a7ab9`
- 취약 running-config SHA-256:
  `c70112ac5fe0a1453bbd77a1fd83d3b2d61a7c2bdc232cb0b2347691ad4fa298`

SW-01·02는 취약 판정을 위한 관리 경로를 의도적으로 보존했으므로 두 스냅샷 모두
PASS가 기대값이다. 제거한 SW-03~06이 false PASS 없이 FAIL로 판정됐다.

## 7. 실패 경계 시험

| 시험 | 기대 결과 | 실제 결과 |
|---|---|---|
| 잘못된 인증정보 | 세션 거부 | `AUTHENTICATION_FAILED` |
| operators 그룹 제한 계정 | 관리자 판정 거부 | `INSUFFICIENT_PRIVILEGE` |
| 잘못된 TLS 인증서 pin | 요청 전 연결 차단 | `CERTIFICATE_MISMATCH` |
| Host-only 응답 없는 주소, 2초 | 제한시간 종료 | `TIMEOUT` |

네 시험은 모두 `REJECTED`로 종료됐고 SW Control을 PASS로 생성하지 않았다.

## 8. 점검 전후 설정 불변 Gate

안전 스냅샷 복귀 후 정상 REST 판정과 실패 경계 네 시험 직전·직후 동일한 읽기 전용
SSH 명령으로 running-config를 수집하고 원문 저장 없이 해시했다.

| 단계 | bytes | SHA-256 |
|---|---:|---|
| REST 시험 직전 | 2,162 | `f62dda277565edae463d41def476d705c8bc812fb2c47dcb6aba405a84a632e9` |
| REST 시험 직후 | 2,162 | `f62dda277565edae463d41def476d705c8bc812fb2c47dcb6aba405a84a632e9` |

결과: `MatchesBefore=True`. 읽기 전용 점검과 실패 경계 시험으로 장비 설정이 바뀌지
않았다.

## 9. 자동 검증

```powershell
docker compose --project-directory . `
  -f deploy\compose\compose.yml `
  -f deploy\compose\compose.dev.yml `
  --profile tools run --rm dev-tools `
  -m pytest tests/unit/test_aruba_aoscx_rest.py `
  tests/unit/test_multiplatform_foundation.py -q
```

- Pytest: `16 passed`
- Ruff: 변경 source·export·test `All checks passed`
- mypy strict: 변경 source·test `Success: no issues found`

## 10. 남은 Gate

- 본 결과는 Aruba AOS-CX 10.13.1170 단일 시험 VM의 개발용 실제 세로 기능이다.
- Cisco IOS XE 실제 구조화 API 수집과 두 벤더 교차 회귀는 남아 있다.
- SW-01~06의 공식 기준 출처 mapping, 서명된 Audit Pack, append-only Finding,
  장비 선택 UI, 진행 화면, PDF, AI 설명은 아직 운영 인수되지 않았다.
- 따라서 홈 화면의 네트워크 스위치 점검은 계속 `PREVIEW` 또는 `HIDDEN`이어야 하며
  `LIVE`로 표시하지 않는다.

## 11. 제조사 참고

- AOS-CX 10.13 REST GET:
  <https://developer.arubanetworks.com/aoscx/v10.13/docs/get>
- REST API methods:
  <https://developer.arubanetworks.com/aoscx/docs/api-methods-features>
- REST read-only access mode:
  <https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/rest_v10-0x/Content/Chp_ena_acc/https_serv_cmds/htt-ser-res-acc-mod-10.htm>
- SNMPv3 user:
  <https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/snmp_mib/Content/Chp_SNMP/SNMP_cmds/snm-use.htm>
- CLI session management:
  <https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/security_4100i-6000-6100/Content/Chp_Cnf_enh_sec/CLI_use_ses_mgmt_cmds/cli-ses-10.htm>
- NTP configuration:
  <https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/fundamentals_8400/Content/Chp_IniCfg/set-swi-tim-usi-ntp-cli.htm>
