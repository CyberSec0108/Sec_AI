# Linux SSH 서버 등록 구현 현황·잔여 계획

## 목표

관리자만 Linux 서버를 등록하고, 일반 사용자는 활성 서버 별칭만 선택해 점검합니다. 배포판·version·architecture는 시스템이 SSH 사전 확인으로 자동 식별합니다.

## 현재 완료

- 관리자 운영 화면의 `Linux 서버 관리`
- 별칭·승인 IPv4·SSH 포트·점검 전용 계정 입력
- 서버별 Ed25519 키 자동 생성과 공개키 전달
- DB에 private key 컬럼을 두지 않는 runtime key store
- 관리자가 별도 경로로 확인한 Ed25519 host key 등록
- `/etc/os-release`·`uname -m` 자동 식별
- Ubuntu 22.04·24.04, Debian 12, Rocky·AlmaLinux 9 x86_64 exact 활성화
- 등록·활성화·중지 이벤트 append-only 저장
- 조직 scope와 RLS, runtime UPDATE·DELETE 차단
- 활성 자산만 일반 Linux 점검 목록에 표시

## 남은 단계

### LINUX-REG-08 실제 VM E2E

- Ubuntu 24.04 정상·취약 snapshot 등록과 2회 반복
- Rocky Linux 9 정상·취약 snapshot 등록과 2회 반복
- 권한 부족 계정에서 `ERROR/REVIEW` 확인
- 점검 전후 설정 diff 0
- 결과·PDF·AI 복원과 타 사용자 비가시 확인

### LINUX-REG-09 공격 회귀

- 등록 후 host key 변조 차단
- 승인 CIDR 밖 IP 차단
- DNS rebinding·IPv4 표현 우회 차단
- 미지원·불완전·충돌 OS 식별 차단
- timeout·출력 상한·locale 변형 처리
- 공개키·계정 폐기 후 재접속 차단

### LINUX-REG-10 운영 key 관리

- KMS/HSM provider 연결
- 개인키 envelope encryption과 접근 감사
- 서버별 key version·회전·grace period
- 즉시 폐기와 비상 복구
- backup에서 private key 제외
- 조직 승인자와 운영 runbook

## 완료 기준

1. 실제 VM 정상·취약·오류 경로가 반복 재현됩니다.
2. 등록 전·host key 불일치·타 조직 접근은 실행 전에 차단됩니다.
3. 수집 allowlist와 설정 diff 0이 유지됩니다.
4. private key가 DB·API·로그·문서에 나타나지 않습니다.
5. KMS/HSM·회전·폐기·감사와 운영 승인을 완료합니다.

사용 절차는 [`../guides/회사_내부망_Linux_SSH_점검_UI_배포_운영_안내.md`](../guides/회사_내부망_Linux_SSH_점검_UI_배포_운영_안내.md)를 확인합니다.
