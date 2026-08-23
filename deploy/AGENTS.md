# `deploy` 영역 코딩 에이전트 지침

적용 범위는 Compose, Dockerfile, Gateway, dependency lock, VM 자료와 검증 기록이다.
인프라·배포 설정은 사용자가 명시적으로 요청하지 않으면 수정하지 않는다. 루트 지침과
[`README.md`](README.md)를 먼저 읽는다.

## 1. 하위 영역

| 위치 | 책임 | 주의 |
|---|---|---|
| `compose` | 서비스, network, volume, secret, healthcheck | production 영향·권한 확대 검토 |
| `docker` | 잠긴 component image | base tag@digest, non-root, read-only |
| `gateway` | localhost reverse proxy·SSE timeout/header | 인증 우회·buffer/cache 금지 |
| `locks` | container·도구 공급망 기준 | tag-only·`latest` 금지 |
| `verification` | 과거 실행·보안·공급망 검증 기록 | append-only 역사, 조용한 수정 금지 |
| `vmware` | 비식별 VM 시험 계약 | 실제 credential·VM image 반입 금지 |
| `security` | SBOM·취약점·악성코드 결과 | exact artifact/hash 연결 |

## 2. Docker·Secret 규칙

- image 이름은 `sec-ai-mvp/<component>:<version>`을 유지한다.
- 외부 제품은 승인된 공식 `tag@digest`를 상속하는 얇은 wrapper를 사용한다.
- secret 원문은 Compose environment가 아니라 `*_FILE`과 Docker secret으로 전달한다.
- 실제 `.env`, `runtime/dev-secrets`, license, private key를 image·문서·로그에 넣지 않는다.
- API·DB·Redis 같은 내부 서비스 port를 불필요하게 host에 공개하지 않는다.
- health와 ready의 의미를 구분한다.
- local vLLM 준비 image가 있다고 자동 시작하거나 완료 상태로 바꾸지 않는다.
- orphan container나 volume을 사용자 승인 없이 정리하지 않는다.

## 3. 검증 기록

- 과거 검증 기록은 당시 artifact·명령·결과의 증거다.
- 현재 코드와 다르다는 이유로 기존 기록을 덮어쓰거나 삭제하지 않는다.
- 새 단계는 새 파일로 기록하고 source·image·Schema·Pack version/hash를 연결한다.
- 실행하지 않은 actual VM, 외부 모델, 악성코드, 취약점 검사를 `PASS`로 쓰지 않는다.
- 실제 credential, IP, 사용자·조직 식별 정보는 비식별 처리한다.

## 4. 변경 후 검증

1. `tools/core.ps1 -Action Config`
2. 변경 image build
3. service status와 health/ready
4. network·port·volume·secret mount 확인
5. 관련 실제 HTTP·SSE·Worker redelivery 시험
6. SBOM·취약점·악성코드·서명 Gate가 필요한 artifact 확인

전체 환경을 재시작하거나 production 설정을 바꾸기 전 사용자 승인과 정확한 영향 범위를
확인한다.

