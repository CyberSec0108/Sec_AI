# SWITCH-04 KISA N-01~N-38 전체 Coverage 검증

## 1. 결과

- KISA 2026 네트워크 장비 `N-01~N-38`을 빠짐없이 원문 순서로 반환한다.
- 출처는 로컬 정본 PDF p.391~466과 승인된 Guide Source Mapping을 사용한다.
- benchmark는 `SECAI-KISA-2026-N01-N38-AOSCX-DRAFT` `0.2.0-DRAFT`다.
- Guide Source 승인을 공식 Audit Pack 승인으로 승격하지 않으며 공식 Finding을 만들지 않는다.
- AOS-CX REST로 충분히 입증하지 못한 항목은 `PASS`로 추정하지 않고 `REVIEW` 또는 `N/A`로 표시한다.

## 2. 판정 경계

현재 구조화 REST projection으로 자동 판정하는 영역은 관리자 비밀번호 인증, 비밀번호 복잡성,
AOS-CX 비밀번호 보호 저장 특성, 관리 접속 허용 목록, 10분 이하 관리 세션, SSH/Telnet,
원격 syslog, NTP, SNMP 사용·v3/community 일부, CDP와 ICMP unreachable/redirect다.

조직 정책, 계정별 역할, 배너 문구, 패치 검토 기록, 로그 용량·정책, 외부 DDoS 장비,
인터페이스 용도대장 및 현재 REST projection에 없는 legacy service 상태는 `REVIEW`다.
SNMPv3 전용이고 v1/v2 community가 없는 경우 N-20은 `N/A`다.

합성 안전 projection의 기대 분포는 `PASS 11`, `REVIEW 26`, `N/A 1`, `FAIL 0`이다.
이는 장비의 전체 안전 판정이 아니라 현재 증적 범위의 false PASS 방지 기준선이다.

## 3. 사용자 화면과 AI

- 점검 입력·진행·결과 화면을 6개에서 38개로 변경했다.
- 카드마다 무엇을 확인했는지, 실제 확인값, KISA page가 포함된 안전 기준, 항목별 판정 이유를 표시한다.
- 38개 합성 결과의 확인값 38종과 판정 이유 38종이 모두 서로 다름을 회귀 시험으로 고정했다.
- AI 출처 `[2]`는 KISA 공식 원문과 개발용 AOS-CX 판정 매핑을 함께 표시한다.
- 과거 SW-01~06 V1 AI cache는 유지하고 N-01~N-38은 V2 key만 append-only로 저장한다.

## 4. 데이터베이스

- 신규 migration: `0027_switch_n01_n38_ai_keys`
- 개발 DB head: `0027_switch_n01_n38_ai_keys`
- 기존 `0026` migration은 수정하지 않았다.
- 기존 V1 `SW-01~06|SUMMARY`와 신규 V2 `N-01~N-38|SUMMARY`만 허용한다.

## 5. 검증

```text
Pytest 집중 회귀(Guide Mapping·38개 확인값·판정 이유 고유성 포함): 36 PASS
Ruff 변경 파일: PASS
mypy 변경 10개 Python 파일: PASS
DB migration 0026 → 0027: PASS
API auto-reload와 startup: PASS
```

추가 확장 회귀는 55건을 통과했고, 현재 변경과 무관한 기존 홈 UI 기대값 1건만 실패했다.
해당 시험은 이미 제거된 `header-help-link`를 계속 요구하는 기존 불일치로 이번 범위에서
기대값을 약화하거나 화면 기능을 복원하지 않았다.

## 6. 남은 Gate

- 실제 AOS-CX에서 새 N-01~N-38 실행은 사용자가 입력하는 현재 REST credential이 필요하다.
- `REVIEW` 항목을 확정하려면 추가 구조화 REST endpoint, 승인된 고정 SSH show command,
  조직 정책·인터페이스 용도대장·외부 방어장비 증적을 각각 연결해야 한다.
- 공식 Audit Pack 승인·서명, append-only Finding, Switch PDF와 Cisco 실제 장비 교차 E2E는 미완료다.
