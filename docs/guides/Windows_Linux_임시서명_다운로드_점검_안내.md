# Windows·Linux 개발용 서명 다운로드 안내

## 먼저 알아둘 점

현재 다운로드는 `DEV-SIGNED-TEST` 개발시험 전용입니다. 조직의 운영 코드서명 인증서가 아니며 격리된 개발 PC와 시험 VM에서만 사용합니다.

다운로드할 때 시스템은 다음을 확인합니다.

- Ed25519 release Catalog 서명
- 파일 SHA-256
- release 만료 시각
- 로그인 사용자가 만든 10분·1회용 코드
- Windows 파일의 추가 Authenticode 개발 서명

하나라도 맞지 않으면 파일을 보내지 않습니다.

## Windows에서 받기

1. 로그인 후 `/ui/dev-downloads`를 엽니다.
2. `Windows 10·11 x64`에서 `브라우저로 다운로드`를 누릅니다.
3. 화면 SHA-256과 받은 파일 hash를 비교합니다.

```powershell
Get-FileHash -Algorithm SHA256 .\SecAI*.exe
```

4. 현재 EXE는 설치 프로그램이 아니므로 직접 실행합니다.

PowerShell로 받을 때는 `일회용 코드 만들기`를 누르고 화면에 표시된 명령을 사용합니다. 코드를 script나 shell history에 직접 적지 않습니다.

## Linux VM에서 받기

VM에 브라우저는 필요 없습니다. Windows 서비스가 localhost에만 열려 있으면 먼저 Windows PowerShell에서 reverse tunnel을 엽니다.

```powershell
ssh -N -R 18480:127.0.0.1:18480 <VM사용자>@<VM_IP>
```

그 다음:

1. Windows 다운로드 화면의 Linux 카드에서 `터미널 코드 만들기`를 누릅니다.
2. VM 터미널에 화면 명령을 붙여 넣습니다.
3. 프롬프트가 물을 때 일회용 코드를 입력합니다.
4. `sha256sum` 결과를 화면 값과 비교합니다.
5. 실행 권한을 주고 공용 파일을 실행합니다.

```bash
chmod 0755 ./secai-linux-check-x86_64
./secai-linux-check-x86_64 --server-url http://127.0.0.1:18480
```

## 자주 막히는 경우

| 증상 | 확인 사항 |
|---|---|
| 코드 만료 | 새 코드 발급. 기존 코드는 재사용 불가 |
| HTTP 연결 실패 | reverse tunnel 창, VM SSH 연결, Windows 서비스 health |
| SHA-256 불일치 | 실행 금지 후 파일 삭제, 새 코드로 다시 받기 |
| release 만료 | 관리자가 새 artifact를 build·검사·서명해야 함 |
| 실행 차단 | 운영체제·architecture Support Catalog 확인 |

## 운영 전환 때 바뀌어야 할 것

- 조직 Publisher 인증서와 승인 책임자
- timestamp와 서명 폐기·회전
- 최신 악성코드·취약점 DB Release Gate
- TLS hostname과 VM에서 접근 가능한 승인 주소
- KMS/HSM private key 보관
- 다운로드 감사·속도 제한·운영 보존정책

임시 서명을 운영 경고 해제 수단으로 사용하지 않습니다.
