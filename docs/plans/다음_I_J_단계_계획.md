# 과거 단계 I·J와 현재 계획 연결

## 문서 역할

단계 I·J와 `IMP-036~062`는 Windows 중심 MVP를 만들 때 사용한 과거 작업 번호입니다. 현재 작업 순서를 결정하는 문서가 아닙니다. 정확한 현재 상태와 다음 작업은 [`../../구현_현황.md`](../../구현_현황.md)를 따릅니다.

## 과거 단계에서 현재 남은 결과

| 과거 목표 | 현재 결과 |
|---|---|
| Windows 현재 OS 수집·결과 | PC-01~18과 관리자 5개, 결과·PDF·AI 구현 |
| 사용자 중심 UI | Windows·Linux·Switch 홈·결과·가이드·도움말 구현 |
| Guide RAG | 통합 8종·pgvector·BGE-M3·citation 구현 |
| 결과 AI | 세 플랫폼 stream·cache·후속 질문 구현 |
| 복수 기준 | Windows Profile, Linux·Switch 제한 기준 구현 |
| clean VM·운영 배포 | 일부 시험만 완료, 조직 서명·KMS·전체 인수 대기 |
| 로컬 vLLM | image·gateway 계약 준비, 운영 인수 대기 |

## 현재 우선순위

1. Linux 등록 서버 실제 Ubuntu/Rocky E2E
2. 권한 부족·host key 변조·CIDR 차단 회귀
3. 운영 KMS/HSM·SSH 키 회전·조직 승인
4. Linux one-shot 조직 서명과 취소·장애 Release Gate
5. RAG 검색 품질 benchmark
6. Windows clean VM·조직 Publisher·설치형 helper
7. Aruba 제품 E2E와 Cisco 실제 장비
8. 알려진 취약점 공급자 확정·Offline Feed Bundle·Linux/Switch 확장
9. 로컬 vLLM 운영 인수
10. 승인형 Agent/MCP `PLAN_ONLY`

## 과거 기록 확인

과거 IMP의 당시 통과 결과는 이 문서에서 다시 설명하지 않습니다. [`../../deploy/verification/`](../../deploy/verification/)의 해당 기록을 보존하며, 현재 code와 다르더라도 과거 검증 기록을 수정하지 않습니다.
