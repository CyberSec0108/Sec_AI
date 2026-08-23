# SWITCH-06 AOS-CX N-01~N-38 REST 수집 범위 확장 검증

## 1. 목적

Aruba AOS-CX 결과에서 `확인 필요`가 과도하게 표시된 원인을 확인하고, 장비에서 실제로
읽을 수 있는 N-01~N-38 관련 값을 추가 수집한다. 조직 기준을 수집값처럼 채우거나 장비에
없는 값을 추정하지 않는다.

## 2. 원인

기존 수집기는 9개 고정 REST GET만 사용했고 결정론 규칙이 직접 소비하는 사실도 제한돼
있었다. 따라서 실제 REST 점검이 완료되어도 안전 합성 projection에서 38개 중 26개가
`REVIEW`였다. 이는 UI 기본값 문제가 아니라 Adapter 수집 범위의 한계였다.

## 3. 구현 결과

- 고정 GET을 9개에서 13개로 확대했다.
  - 기존: API version, 현재 사용자, system, management VRF, 전체 VRF, SNMPv3 사용자,
    원격 syslog, management/default VRF NTP
  - 추가: interfaces, user groups, ACLs, logging filters
- 원문 응답은 저장하지 않고 다음 비식별 사실만 canonical projection에 남긴다.
  - USB·Bluetooth 관리 차단, HTTPS 활성 VRF와 관리망 외 노출 수
  - 물리·라우팅 인터페이스 수, source lockdown, directed broadcast, proxy ARP
  - DNS server 수, built-in role·RBAC rule 수, ACL·logging filter 수
  - 감사 이벤트 포함 원격 syslog 수, 로그 영구 저장·임계 알림 구성, 사용자 CoPP 여부
- N-09·14·22·24·27·31·33·36을 실제 수집값으로 PASS/FAIL/REVIEW/N/A 판정한다.
- AOS-CX 10.13에서 구현하지 않는 Cisco 계열 legacy service N-26·28·29·32·35·37·38은
  `N/A`로 분리한다. SNMPv3 전용일 때 N-20도 기존처럼 `N/A`다.
- 활성 포트에 description이 있다는 이유만으로 용도가 승인됐다고 추정하지 않는다.
  미표시 활성 포트는 FAIL, 전체 물리 포트가 down이면 PASS, 설명이 있는 활성 포트는 조직
  용도대장 대조가 필요하므로 REVIEW다.
- 비밀번호 복잡성 객체가 configuration selector에서 생략되면 AOS-CX 기본 비활성으로
  처리해 N-02를 false PASS 없이 FAIL로 판정한다.

안전 합성 projection의 상태 분포는 다음과 같다.

| 상태 | 변경 전 | 변경 후 |
|---|---:|---:|
| PASS | 11 | 19 |
| FAIL | 0 | 0 |
| REVIEW | 26 | 11 |
| N/A | 1 | 8 |

실제 장비 결과는 장비의 현재 설정에 따라 PASS와 FAIL 개수가 달라진다.

## 4. 계속 REVIEW인 항목

> 2026-08-06 후속 상태: 아래 11개에는
> [`SWITCH-07 조직 보완 판정 기본값`](SWITCH_07_조직_보완_판정_기본값_검증_20260806.md)을
> 추가했다. 장비 REST 확인값은 유지하면서 별도 조직 입력으로만 상태를 보완한다.

다음 11개는 값 미수집을 숨긴 것이 아니라 장비 설정만으로 확정할 수 없거나 추가 source가
필요한 항목이다.

- 조직·운영 증적: N-04 계정 잠금 동작, N-05 업무별 권한 매핑, N-12 벤더 권고 검토 기록,
  N-13 로그 발생량 대비 버퍼, N-17 SNMP 업무 승인, N-23 외부 DDoS 방어
- 추가 read-only Adapter 필요: N-10 로그인 배너, N-16 timestamp 형식, N-21 TFTP 상태,
  N-25 TCP keepalive
- 구성에 따라 추가 제한 증적 필요: N-19 SNMP 접근 제한

조직별 Criteria Profile은 기대 기준에만 사용하며 위 수집값이나 상태를 임의 생성하지 않는다.

## 5. 검증

```powershell
docker compose --project-directory . -f deploy/compose/compose.yml -f deploy/compose/compose.dev.yml run --rm dev-tools `
  -m pytest tests/unit/test_aruba_aoscx_rest.py tests/unit/test_switch_product_flow.py -q

docker compose --project-directory . -f deploy/compose/compose.yml -f deploy/compose/compose.dev.yml run --rm dev-tools `
  -m ruff check src/security_audit/platforms/aruba_rest.py src/security_audit/platforms/kisa_network.py `
  tests/unit/test_aruba_aoscx_rest.py tests/unit/test_switch_product_flow.py

docker compose --project-directory . -f deploy/compose/compose.yml -f deploy/compose/compose.dev.yml run --rm dev-tools `
  -m mypy --strict src/security_audit/platforms/aruba_rest.py src/security_audit/platforms/kisa_network.py `
  tests/unit/test_aruba_aoscx_rest.py
```

- 집중 Pytest: 34 PASS
- Ruff: PASS
- mypy strict 대상 파일: PASS
- 개발 API: 확장 endpoint 13개 로드, container healthy
- 원격 장비 변경 요청: 0건. login/logout 외에는 고정 HTTPS GET만 허용
- credential·원격 주소·SNMP 사용자·ACL 원문 canonical 저장: 0건

## 6. 실행 상태와 남은 작업

- 개발 API에는 변경을 반영했다.
- 기존 append-only 결과는 수정하지 않는다. 화면의 이전 `REVIEW 26` 결과는 현재
  credential로 `다른 스위치 점검` 또는 재점검을 실행해야 새 분포로 생성된다.
- 현재 credential은 저장하지 않는 설계이므로 이번 변경 과정에서 실제 VM 재실행은 하지
  않았다. 다음 사용자 재점검에서 4개 추가 endpoint의 실제 응답과 상태 분포를 확인한다.
- 이 검증 시점 Adapter·판정은 `0.2.0-DRAFT`였고 후속 조직 보완 판정에서
  `0.3.0-DRAFT`로 갱신했다. 공식 Finding 승격은 별도 Gate다.
