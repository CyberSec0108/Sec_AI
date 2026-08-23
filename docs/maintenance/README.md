# Sec_AI 현재 유지보수 문서

이 디렉터리는 현재 source 구조를 파악하고 Windows·Linux·Switch·RAG·취약점 점검을 안전하게 변경하기 위한 문서를 모읍니다. 완료 상태는 [`../../구현_현황.md`](../../구현_현황.md), 실제 동작은 source·Schema·시험을 우선합니다.

| 문서 | 용도 |
|---|---|
| [`유지보수_가이드.md`](유지보수_가이드.md) | 변경 유형별 담당 파일, 보안 경계, 검증·장애 대응·문서 정리 절차 |
| [`수집기_구조_판정_기준_유지보수_상세가이드.md`](수집기_구조_판정_기준_유지보수_상세가이드.md) | Windows·Linux·Switch 수집기, Probe·Control 판정, 기준 변경·추가와 플랫폼별 유지보수 절차 |
| [`SecAI_Windows_실행파일_빌드_구성_재현_가이드.md`](SecAI_Windows_실행파일_빌드_구성_재현_가이드.md) | Windows 단일 EXE의 내부 구성, 처음부터 다시 만드는 build·서명·검증·다운로드 절차 |
| [`프로젝트_구조_및_파일_기능_카탈로그.md`](프로젝트_구조_및_파일_기능_카탈로그.md) | 폴더별 책임과 source·설정·시험·문서 파일별 기능·주요 정의·주의사항 |

파일 카탈로그는 source를 변경한 뒤 프로젝트 루트에서 다음 명령으로 갱신합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\generate-repository-catalog.ps1
```

실제 `.env`, `runtime/dev-secrets`, VM, 원본 증적, cache와 build 산출물은 카탈로그에 포함하지 않습니다. 이 제외는 누락이 아니라 비밀정보·Runtime 자료를 문서에 복제하지 않기 위한 보안 경계입니다.
