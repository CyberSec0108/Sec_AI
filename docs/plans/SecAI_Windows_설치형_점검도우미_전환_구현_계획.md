# SecAI Windows 설치형 점검 도우미 전환 계획

## 현재 상태

현재 Windows 파일은 사용자가 내려받아 직접 여는 portable EXE입니다. 설치 프로그램이 아니며 브라우저가 자동 실행하지 않습니다. Launcher 미연결 화면은 다운로드, 실행 방법, 연결 다시 확인과 점검 화면 복귀를 제공합니다.

설치형 Setup, 전용 URI, 자동 업데이트와 조직 Publisher 서명은 아직 구현하지 않았습니다.

## 목표 사용자 경험

1. 최초 한 번 조직 서명 Setup 설치
2. 브라우저에서 `Windows PC 점검` 선택
3. 전용 URI로 로컬 도우미 실행
4. session을 직접 노출하지 않는 일회성 handoff
5. 도우미가 자신의 version·서명을 확인
6. 일반 점검 실행
7. 필요할 때 별도 동의로 관리자 추가 점검
8. 업데이트는 서명·hash·호환성 Gate 통과 뒤 적용

## 구현 단계

### WIN-HELPER-01 설치 계약

- 설치 위치·사용자/장비 범위·서비스 사용 여부
- 설치·업데이트·삭제 시 관리자 권한 최소화
- 로그·cache·결과 위치와 제거 정책
- 기존 portable EXE와 호환·전환 기간

### WIN-HELPER-02 조직 서명

- 조직 Publisher 인증서·timestamp
- private key KMS/HSM 보관
- 서명 체인·폐기·rotation
- clean Windows 10·11의 SmartScreen·Defender 시험

### WIN-HELPER-03 Browser handoff

- 전용 URI protocol 등록
- 2분·1회성 nonce, 현재 사용자·조직·origin 결합
- URL·로그·shell history에 session token 금지
- replay·다른 사용자·다른 origin 차단

### WIN-HELPER-04 안전한 업데이트

- signed update manifest와 artifact SHA-256
- 현재 helper/API/Pack compatibility
- 취약점·악성코드·SBOM Release Gate
- atomic 교체와 실패 rollback
- silent downgrade 금지

### WIN-HELPER-05 설치·삭제 UX

- 설치 여부 자동 확인
- 설치 안 됨/오래된 version/실행 중/권한 거부 구분
- 사용자 데이터·감사 기록과 프로그램 파일 삭제 분리
- 조직 배포 도구용 무인 설치는 별도 승인

## 보안 경계

- 브라우저가 임의 command line을 전달하지 않습니다.
- helper는 허용된 점검 action과 signed manifest만 실행합니다.
- 관리자 권한은 다섯 추가 항목의 동의 범위에만 사용합니다.
- 업데이트 실패 시 기존 검증 version을 유지합니다.
- Setup이 방화벽·보안제품·업데이트 정책을 완화하지 않습니다.

## 완료 기준

- clean Windows 10·11 설치·실행·업데이트·삭제 E2E
- tampered Setup/manifest/update, expired signature, replay 차단
- 관리자 추가 점검의 별도 동의 유지
- 설치 전후 시스템 변경 목록과 rollback 확인
- 조직 Publisher·KMS/HSM·운영 승인 완료
