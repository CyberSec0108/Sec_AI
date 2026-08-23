# `docs` 영역 코딩 에이전트 지침

적용 범위는 사람이 읽는 ADR·계획·가이드·유지보수 문서다. 루트 지침과
[`README.md`](README.md)를 먼저 읽는다.

## 1. 문서 역할

| 위치 | 역할 |
|---|---|
| `adr` | 승인·제안된 설계 결정과 변경 경계 |
| `plans` | 아직 남은 단계, 순서, 완료 Gate |
| `guides` | 사용자·관리자·배포 담당자 실행 안내 |
| `maintenance` | 구조·파일·수집기·변경 절차 |
| `README.md` | 모든 문서의 통합 목차와 현재 요약 |

실행 증거는 `docs`가 아니라 `deploy/verification`, 현재 완료 상태는 루트
`구현_현황.md`, 기계 판독 계약은 `database/schemas`와 `guides`에 있다.

## 2. 수정 원칙

- 문서와 코드가 다르면 실제 동작은 코드를 확인하고 불일치를 명시한다.
- 계획을 구현 완료처럼 쓰지 않는다.
- `LIVE`, `DRAFT`, `APPROVED`, 운영/Pilot 상태를 분리한다.
- Guide 승인과 Audit Pack 승인을 혼동하지 않는다.
- 과거 ADR과 검증 기록의 주장을 현재에 맞춰 조용히 다시 쓰지 않는다.
- 새 결정이 기존 ADR 의미를 바꾸면 후속 ADR·version·승인 상태를 검토한다.
- 실제 secret, credential, 내부 식별자, 원본 증적을 예시로 복제하지 않는다.
- 명령과 경로는 프로젝트 루트 상대경로로 작성한다.
- 새 주석·설명은 한국어를 기본으로 하고 코드·API 고유명은 원문을 유지한다.

## 3. 문서 추가·삭제

새 문서를 추가하면 다음을 함께 확인한다.

1. `docs/README.md`의 역할별 목차
2. 해당 하위 폴더의 `README.md`
3. 루트 README 또는 `구현_현황.md`에서 참조해야 하는지
4. 상대 링크와 anchor 존재

문서를 삭제·이동하기 전에는 참조를 `rg -n`으로 모두 찾고, 대체 정본과 복구 가능성을
확인한다. 검증 기록은 삭제 대상으로 취급하지 않는다.

## 4. 생성 문서

`maintenance/프로젝트_구조_및_파일_기능_카탈로그.md`는 자동 생성 파일이다. 직접 수정하지
않고 다음 도구를 사용한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\generate-repository-catalog.ps1
```

생성 결과에 runtime, secret, VM, cache, build artifact가 포함되지 않는지 확인한다.

## 5. 검증

- 모든 상대 Markdown link의 대상 존재 여부
- 문서의 파일명·route·class·명령이 현재 source에 존재하는지
- `구현_현황.md`, `README.md`, `docs/README.md`의 상태 표현 충돌
- ADR index의 상태·기준일·hash 갱신 필요 여부
- 표와 code fence가 올바르게 닫혔는지
- 생성 문서라면 generator 재실행 결과와 수동 변경 0

문서만 바꾼 경우 전체 Python Gate는 필수가 아니지만, 문서에 적은 명령·경로·링크는
기계적으로 검증한다.
