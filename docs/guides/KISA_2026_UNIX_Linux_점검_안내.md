# KISA UNIX U-01~U-67 Linux 점검 안내

## 현재 범위

Sec_AI는 KISA UNIX 서버 항목 U-01~U-67을 Linux용 증적과 개발 규칙으로 연결합니다. 중앙 SSH 점검과 Linux 원샷 점검이 같은 항목 구조를 사용하지만 결과와 신뢰 수준은 서로 섞지 않습니다.

- 중앙 활성 지원: Ubuntu 22.04·24.04, Debian 12, Rocky Linux 9, AlmaLinux 9 x86_64
- Pilot Catalog: RHEL 9 x86_64(공식 구독 이미지 실제 인수 전)
- 판정 상태: 개발용 `DRAFT`
- 수집 방식: 고정 allowlist의 읽기 전용 명령

## 처리 순서

```text
OS·version·architecture 자동 식별
→ 지원 Catalog exact 일치 확인
→ 고정 Probe 실행
→ 원문·정규화·명령 Manifest hash 확인
→ U-01~U-67 규칙 평가
→ 결과·기준 snapshot·AI 입력 저장
```

Ubuntu 계열과 RHEL 계열의 파일 위치·명령 출력 차이는 Adapter가 처리합니다. 사용자가 배포판을 직접 선택하지 않습니다.

## 상태 의미

| 상태 | 의미 |
|---|---|
| `PASS` | 이번 실행의 개발 기준과 실제 수집값이 일치 |
| `FAIL` | 개발 기준과 불일치 |
| `REVIEW` | 조직 정책 또는 추가 자료가 필요 |
| `ERROR` | 권한·연결·형식 문제로 판정 자료 부족 |
| `N/A` | 해당 플랫폼 또는 구성에 적용되지 않음 |

부분 증적, 권한 부족 또는 timeout을 `PASS`로 바꾸지 않습니다.

## 기준 수정

사용자는 비밀번호 기간·길이, 잠금 횟수, 세션 timeout과 승인 관리자·포트·SUID 경로만 수정할 수 있습니다. shell, 명령, 정규식과 판정 코드는 입력할 수 없습니다.

점검을 시작하면 해당 기준 version과 SHA-256이 결과에 고정됩니다. 나중에 기준을 바꿔도 과거 결과를 다시 쓰지 않습니다.

## 결과와 AI

- 결과 화면은 전체·양호·취약·확인 필요·오류·해당 없음 수를 구분합니다.
- 각 항목은 실제 확인값, 판정 이유와 출처를 표시합니다.
- PDF는 사용자용과 권한이 필요한 기술 검증용으로 나뉩니다.
- AI 설명은 사용자가 요청할 때 stream으로 생성되며 완료본을 저장합니다.
- AI는 U-01~U-67 상태나 결과 hash를 변경하지 않습니다.

## 실제 VM 인수 상태

- Ubuntu 22.04와 Debian 12는 공식 cloud image를 확인값과 대조한 뒤 U-01~U-67을
  두 번 실행해 결과 hash 일치와 설정 hash 무변경을 확인했습니다.
- AlmaLinux 9도 같은 반복성과 설정 무변경을 확인했습니다. 최소 cloud image에
  `firewalld`와 DNF 보안 cache가 없으면 관련 Probe는 `ERROR`로 표시되며 이를 양호로
  바꾸지 않습니다.
- RHEL 9는 Adapter와 안전한 VM 입력 경로는 준비됐지만 Red Hat 구독으로 받은 공식
  qcow2와 SHA-256 인수가 남아 있어 `PILOT`입니다.

## 운영 전 남은 것

- RHEL 9 공식 구독 이미지와 배포판별 정상·권한 부족·timeout snapshot 반복시험
- 권한 부족·timeout·locale·출력 상한 공격 시험
- 조직 서명과 Audit Pack 승인
- 운영 KMS/HSM과 SSH 키 회전
- 실제 운영 서버 변경 전후 설정 diff 0 확인

수집기 변경 방법은 [`../maintenance/수집기_구조_판정_기준_유지보수_상세가이드.md`](../maintenance/수집기_구조_판정_기준_유지보수_상세가이드.md)를 확인합니다.
