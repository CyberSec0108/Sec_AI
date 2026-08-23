# KISA 2026 UNIX 서버 Audit Pack 준비 영역

이 디렉터리는 KISA UNIX U-01~U-67 공통 Control Source와 Ubuntu 24.04·Rocky 9
전용 Adapter를 분리해 승인하기 위한 DRAFT 영역입니다.

현재는 실행 코드와 원문 매핑을 먼저 고정한 상태이며 승인·서명된 운영 Pack이
아닙니다. 따라서 실제 운영 Finding을 생성하거나 `APPROVED`로 표시하면 안 됩니다.

```text
KISA-2026-UNIX 공통 Control Source
├─ Ubuntu Server 24.04 Adapter / Fixture / 승인 hash
└─ Rocky Linux 9 Adapter / Fixture / 승인 hash
```

## 현재 개발 동작

- U-01~U-67은 비밀번호 최대 90일·최소 8자·잠금 10회·세션 600초,
  승인 관리자 `root`/`secai-lab`, 허용 포트 22, 승인 SUID/SGID 경로 없음의
  비어 있지 않은 안전 기본값으로 시작합니다.
- 사용자는 점검 시작 화면에서 숫자·계정명·포트·절대 경로만 조정하거나 기본값으로
  되돌릴 수 있습니다. 서버가 값을 재검증하고 실행 snapshot과 SHA-256을 남깁니다.
- 내부 `REVIEW`와 `ERROR` 의미는 보존하지만 사용자 결과 분류는 둘 다 `확인 필요`에
  포함합니다. 수집 실패나 기준 부족을 `PASS`로 바꾸지 않습니다.
- 결과·AI 통합 화면의 직접 출처는 `[1] 실제 확인값`, `[2] KISA 근거`,
  `[3] AI 일반 보안지식`입니다. 규칙 엔진은 AI 출처가 아니라 별도 DRAFT 판정
  권한입니다.
- `/etc/os-release` 사전 수집은 일시 실패 시 최대 2회 시도하고, 수집 실패·미지원
  배포판·실제 배포판 불일치를 구분합니다.

상세 구현과 현재 검증 상태는
[`../../docs/guides/KISA_2026_UNIX_Linux_점검_안내.md`](../../docs/guides/KISA_2026_UNIX_Linux_점검_안내.md)를
확인합니다. 2026-08-05 화면·AI·기준·시작 오류 검증은
[`../../deploy/verification/Linux_Windows_결과_AI_정합성_검증_20260805.md`](../../deploy/verification/Linux_Windows_결과_AI_정합성_검증_20260805.md)에
기록했습니다.
