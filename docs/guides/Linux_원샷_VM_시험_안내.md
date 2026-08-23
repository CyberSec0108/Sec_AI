# Linux 원샷 VM 시험 안내

## 가장 쉬운 방법

Windows에서 다운로드 화면을 열고, Linux VM에서는 터미널만 사용합니다. VM에 웹브라우저를 설치할 필요가 없습니다.

현재 중앙 서비스가 Windows의 `127.0.0.1:18480`에만 열려 있으면 reverse SSH tunnel을 유지해야 VM의 `127.0.0.1:18480`이 Windows 서비스로 연결됩니다.

## 자동 시험 VM 준비

VMware Workstation과 Docker가 있는 개발 PC에서는 프로젝트 루트에서 다음 명령으로
공식 cloud image 확인, VMDK 변환, NoCloud 초기화, SSH 키 생성과 초기 snapshot 생성을
자동화할 수 있습니다. VM은 화면을 열지 않고 백그라운드로 실행됩니다.

```powershell
# Ubuntu 22.04
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\deploy\vmware\ubuntu-lab.ps1 -Action Prepare -Version 22.04

# Debian 12 또는 AlmaLinux 9
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\deploy\vmware\rocky-lab.ps1 -Action Prepare -Distribution Debian12
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\deploy\vmware\rocky-lab.ps1 -Action Prepare -Distribution AlmaLinux9
```

Ubuntu·Debian·AlmaLinux 공개 image는 각 기관의 checksum 목록과 자동 대조합니다. RHEL 9는
구독 로그인을 우회해 내려받지 않으며, Red Hat에서 받은 qcow2와 별도로 확인한 SHA-256을
함께 지정해야 합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\deploy\vmware\rocky-lab.ps1 -Action Prepare -Distribution RHEL9 `
  -SourceImagePath <공식-qcow2-경로> -SourceImageSha256 <64자리-SHA256>
```

자동화는 `.runtime/vmware` 아래에만 VM·키·다운로드를 만들며 이 경로의 파일을 source나
배포 산출물로 취급하지 않습니다. RHEL 입력이나 checksum이 없거나 다르면 VM 생성 전에
중단합니다.

## 1. Windows에서 준비

1. Sec_AI에 로그인합니다.
2. `/ui/dev-downloads`를 엽니다.
3. 안내된 reverse tunnel 명령을 Windows PowerShell에서 실행합니다.

```powershell
ssh -N -R 18480:127.0.0.1:18480 <VM사용자>@<VM_IP>
```

이 PowerShell 창은 다운로드와 online 제출이 끝날 때까지 열어 둡니다. 이것은 개발용 localhost 우회 방법이며 운영 배치 방식이 아닙니다.

## 2. VM에서 파일 받기

1. 다운로드 화면의 `Linux 서버 x86_64` 카드에서 `터미널 코드 만들기`를 누릅니다.
2. 화면에 나온 명령을 VM 터미널에 붙여 넣습니다.
3. 일회용 코드는 명령행에 넣지 말고 프롬프트가 물을 때 입력합니다.
4. 화면 SHA-256과 VM의 `sha256sum` 결과가 같은지 확인합니다.

코드는 로그인한 사용자가 만들며 10분 동안 한 번만 사용할 수 있습니다.

## 3. 실행

```bash
chmod 0755 ./secai-linux-check-x86_64
./secai-linux-check-x86_64 --server-url http://127.0.0.1:18480
```

프로그램은 `/etc/os-release`와 architecture로 배포판을 자동 식별합니다. 사용자는 Ubuntu/Rocky를 선택하지 않습니다.

일반 권한으로 가능한 자료를 먼저 모으고 추가 권한이 필요한 39개 자료를 목록으로 보여 줍니다. 동의하면 `sudo`가 비밀번호를 직접 처리합니다. Sec_AI는 비밀번호를 읽거나 저장하지 않습니다.

## 4. 자동 제출이 안 될 때

프로그램이 만든 Evidence ZIP과 같은 이름의 descriptor JSON을 Windows로 옮깁니다. `Linux 원샷 자가 점검` 화면의 `오프라인 결과 수동 업로드`에서 두 파일을 함께 선택합니다.

offline 업로드는 장치 신원을 중앙이 자동 확인하지 못하므로 결과 보증 수준이 `LOW`입니다.

## 5. 정상·취약 반복시험

VM마다 다음 snapshot을 준비합니다.

1. `clean`: 설치 직후 기준
2. `safe`: 의도한 안전 설정 적용
3. `vulnerable`: 시험 대상 설정만 의도적으로 약화
4. `permission-denied`: 점검 계정 읽기 권한 일부 제거

각 snapshot에서 다음을 두 번 반복합니다.

1. snapshot 복원
2. 파일 SHA-256 확인
3. 점검 실행
4. online 또는 offline 제출
5. Package 서명·hash·Schema 검증 확인
6. 결과 개수와 상태 비교
7. 점검 전후 설정 hash 또는 diff 0 확인

같은 snapshot의 결과가 반복 실행에서 달라지면 locale, 시간, 명령 출력 순서와 정규화 규칙을 먼저 확인합니다.

## 6. 반드시 실패해야 하는 시험

- 파일 hash 변조
- 만료되거나 재사용한 다운로드 코드
- 미지원 OS·architecture
- `/etc/os-release` 충돌
- Package 또는 descriptor 변조
- 권한 부족을 양호로 처리하려는 경우
- timeout·출력 크기 초과
- 타 사용자의 run에 upload

## 7. 현재 경계

개발용 `DEV-SIGNED-TEST` 파일은 격리된 시험 VM에서만 사용합니다. 실제 운영 배포에는 조직 Publisher 서명, 폐기 목록, KMS/HSM, 악성코드·취약점 Release Gate와 담당자 승인이 필요합니다.
