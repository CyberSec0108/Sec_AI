# IMP-009 합성 패키지 Fixture

이 디렉터리의 자료는 실제 PC 증적을 포함하지 않는다. `imp009_cases.json`은 고정 case ID와 기대 오류 코드를 정의하고, 단위시험이 매 실행마다 임시 ZIP byte를 생성해 공격 조건을 재현한다.

Binary ZIP을 저장소에 고정하지 않는 이유는 ZIP timestamp·header 차이를 공급망 artifact로 오해하지 않도록 하기 위해서다. 정상 package hash Fixture는 이후 `IMP-012` PC-07 PASS/FAIL/ERROR Fixture에서 canonical 생성 도구와 함께 고정한다.
