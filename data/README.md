# 원문 데이터 관리 안내

이 폴더는 점검 기준과 가이드 검색의 출처가 되는 사용자가 제공한 원문 파일을 보관합니다. 현재 등록 파일은 KISA의 `주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf` 한 건입니다.

## 이 폴더에 두는 것

- 출처·판본·이용 범위를 확인한 원문 문서
- Catalog에서 exact SHA-256과 상대경로로 식별할 수 있는 파일
- 조직 내부 사용 승인을 받은 정적 기준 자료

## 이 폴더에 두지 않는 것

- 실제 점검 Evidence, 사용자 업로드, Package와 보고서
- PostgreSQL dump, Object Storage 자료와 backup
- OCR·chunk·embedding·검색 cache 같은 파생 runtime 자료
- 비밀번호, token, 인증서, private key, license file
- 인터넷에서 출처 확인 없이 내려받은 파일

실행 중 만들어지는 자료는 `runtime/` 또는 서비스의 관리 volume에 두고 source와 섞지 않습니다.

## 원문과 Catalog의 관계

```text
data/<원문 파일>
  → guides/catalog.json                    파일명·판본·SHA-256·이용 조건
  → guides/page_maps/*.json                PDF 물리 페이지와 내용 지문
  → guides/mappings/*.json                 Control 출처 연결
  → 승인된 범위만 내부 검색·인용
```

정본은 파일명만이 아니라 Catalog에 기록된 exact SHA-256입니다. 같은 이름의 파일로 교체하지 않습니다. 새 판본을 반입하면 새 파일, 새 Catalog version, 새 Page Map과 새 Mapping으로 관리합니다.

## 원문 추가 절차

1. 공식 출처, 문서명, 발행 기관, 발행일·판본과 이용 조건을 확인합니다.
2. 파일을 격리된 위치에서 악성코드 검사합니다.
3. SHA-256, byte 크기, PDF 페이지 수와 추출 품질을 계산합니다.
4. [`../guides/catalog.json`](../guides/catalog.json)에 새 문서 또는 새 version을 등록합니다.
5. 필요한 페이지 범위만 Page Map과 Control Source Mapping에 연결합니다.
6. valid/invalid Schema와 원문 검증 시험을 실행합니다.
7. 내부 검색·파생 저장·외부 전송·재배포 각각의 승인 범위를 기록합니다.

원문을 추가했다는 사실만으로 검색이나 Audit Pack 사용이 승인되지 않습니다. Guide Catalog, Control Source Mapping과 Audit Pack 승인은 서로 독립적입니다.

## 보안·저작권 주의

- 원문 전체나 긴 문구를 로그·Fixture·AI prompt·검증 기록에 복사하지 않습니다.
- 허용된 내부 검색 범위를 넘어 외부 모델에 원문을 전송하지 않습니다.
- 이동 묶음이나 Collector 실행 파일에 원문을 자동 포함하지 않습니다.
- 재배포 권한이 확인되지 않은 문서는 조직 외부에 제공하지 않습니다.
- 검증 결과에는 파일 내용 대신 hash, 크기, 페이지 수와 통과 여부만 남깁니다.

## 현재 원문 재검증

잠긴 개발 container에서 다음 명령을 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp047-guide-source.ps1
```

실제 적재와 내부 검색 검증:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp048-guide-store.ps1
```

자세한 등록 상태와 승인 경계는 [`../guides/README.md`](../guides/README.md)를 확인합니다.
