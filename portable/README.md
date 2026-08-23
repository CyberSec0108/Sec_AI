# Sec_AI 이동용 묶음

Sec_AI가 실행하는 이미지는 모두 `sec-ai-mvp/<component>:<version>` 이름을 사용한다. PostgreSQL·Redis·AIStor는 승인된 공식 `tag@digest`를 그대로 상속하는 얇은 프로젝트 래퍼로 만들며, 원본 공급자와 digest는 Dockerfile·이미지 라벨·잠금표에 보존한다. 이동 묶음에는 프로젝트 래퍼와 재현에 필요한 공식 기반 이미지를 함께 기록한다.

이 기능은 Sec_AI의 소스·문서·잠금파일과 Docker 이미지를 하나의 directory 묶음으로 만들어
같은 조직의 다른 Windows 11 PC로 옮기기 위한 도구다. 대상 PC에는 Docker Desktop과 Windows
PowerShell이 필요하다. Python, Node, PostgreSQL, Redis, AIStor와 개발도구를 host에 따로
설치하지 않는다. 사전 준비, Secret·LLM 설정, 빈 Runtime 경로와 설치 후 검증은
[`docs/guides/다른_PC_설치_및_이전_안내.md`](../docs/guides/다른_PC_설치_및_이전_안내.md)를 따른다.

이동 묶음은 프로젝트 진행 중 자동으로 만들지 않는다. 프로젝트 종료 시점 또는 사용자가 명시적으로 요청한 경우에만 생성한다. 일상적인 build·test·container 재시작은 이동 묶음 생성을 유발하지 않는다.

## 이 폴더의 파일

| 파일·위치 | 역할 | 관리 방식 |
|---|---|---|
| `images.lock.txt` | 이동 묶음에 필요한 외부 base image exact digest | 공급자·platform·digest 검토 후 변경 |
| `import-portable-bundle.ps1` | manifest/hash 검증 후 image 적재와 source 해제 | 내용 있는 대상 폴더를 기본 거부 |
| `README.md` | 내보내기·가져오기와 제외 범위 | bundle에도 복사되는 사용자 안내 |
| `out/` | 생성된 일시적 묶음 | source 아님, Git·재귀 묶음에서 제외 |

내보내기 구현은 [`../tools/export-portable-bundle.ps1`](../tools/export-portable-bundle.ps1)에 있습니다. 생성 도구와 가져오기 도구 모두 경로를 정규화하고 project/bundle 경계 밖 덮어쓰기를 거부해야 합니다.

## 내보내기

Docker Desktop을 실행한 뒤 프로젝트 루트에서 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\export-portable-bundle.ps1
```

결과는 `portable\out\secai-portable-<UTC 시각>\`에 생성된다.

```text
secai-source.zip
secai-images.tar
BUNDLE-MANIFEST.json
SHA256SUMS.txt
import-portable-bundle.ps1
README.md
```

이미지가 필요 없는 온라인 PC용 source-only 묶음은 다음과 같이 만든다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\export-portable-bundle.ps1 -SourceOnly
```

## 다른 PC에서 가져오기

묶음 directory 전체를 이동식 저장장치나 승인된 내부 전송수단으로 옮긴 뒤 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\import-portable-bundle.ps1 -Destination D:\Sec_AI
Set-Location D:\Sec_AI
Copy-Item .env.example .env
New-Item -ItemType Directory -Force -Path .runtime\vmware | Out-Null
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

`-ExecutionPolicy Bypass`는 해당 명령 프로세스에만 적용되며 Windows의 전역 실행 정책은 바꾸지 않는다.

가져오기 도구는 먼저 모든 파일의 SHA-256을 확인하고, 이미지 TAR이 있으면 Docker에 적재한 뒤
소스를 푼다. 기본적으로 내용이 있는 대상 directory에는 덮어쓰지 않는다.

Core 기동 전에는 `tools\core.ps1 -Action Init`으로 DEV Secret을 만들고, AI 기능을 사용할
경우 승인된 설정 파일을 `tools\import-llm-settings.ps1`로 별도 반입한다. AIStor license와
Linux VM·SSH key는 자동 이전되지 않는다.

## 의도적으로 포함하지 않는 것

- 실제 `.env`, password, token, private key, OpenBao unseal share;
- AIStor license file, TLS·Authenticode certificate private key;
- 실제 증적, database dump, backup, Docker volume과 runtime cache;
- `portable/out`에 이전에 생성한 다른 묶음.

이 항목들은 일반 파일 이동이 아니라 승인된 Secret·Backup/Restore 절차로 이전해야 한다.
AIStor image는 동일 조직 내부 사용만 허용하며 묶음을 제3자에게 납품·판매·재배포하지 않는다.

## 무결성 확인 흐름

```text
내보내기
  → 제외 규칙 적용
  → secai-source.zip / 선택적 secai-images.tar
  → 파일별 SHA-256
  → BUNDLE-MANIFEST.json + SHA256SUMS.txt

가져오기
  → manifest와 모든 SHA-256 선검증
  → 비어 있는 대상 경로 확인
  → 선택적 Docker image load
  → source 해제
  → DEV secret 별도 생성
  → 표준 검증·Core Health
```

ZIP hash가 맞아도 생산자 신원이나 배포 승인을 증명하지 않습니다. 실제 조직 배포에는 승인된 전송수단, 서명, 보관 정책과 수령자 확인을 추가해야 합니다.

## 가져온 뒤 검증

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Init
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action UpWithoutAIStor
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

AIStor, LLM, 조직 인증서, Linux VM과 SSH key는 별도 승인 자료이므로 필요한 경우 각각의 반입 절차를 수행합니다. source 검증이 통과했다는 이유로 이 자료가 이전됐다고 가정하지 않습니다.

## 변경 체크리스트

- [ ] `runtime`, `.runtime`, `.env`, secret, license, Evidence와 기존 `portable/out`이 제외됩니다.
- [ ] source ZIP과 image TAR의 모든 hash가 manifest와 일치합니다.
- [ ] 외부 image는 exact platform digest로 잠겼습니다.
- [ ] 대상 폴더의 기존 파일을 묵시적으로 덮어쓰지 않습니다.
- [ ] bundle에 private key 또는 사용자 데이터가 없는지 검사했습니다.
- [ ] 가져온 환경에서 표준 Gate와 Health를 재실행했습니다.
