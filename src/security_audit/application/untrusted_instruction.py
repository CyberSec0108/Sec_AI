"""세 플랫폼이 공유하는 지시문 주입 차단 규칙.

수집한 파일명·설정값·장비 응답에는 사용자가 통제하지 못하는 문자열이 섞일 수
있습니다. Windows·Linux·Switch 설명 경로가 같은 위험을 지므로 차단 규칙을 한
곳에 모아 셋이 같은 기준을 쓰게 합니다.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

UNTRUSTED_INSTRUCTION_PATTERNS = (
    re.compile(r"ignore\s+(all\s+)?previous\s+(system\s+)?instructions?", re.I),
    re.compile(r"시스템\s*(지침|명령|프롬프트).{0,24}(무시|삭제|덮어)", re.I),
    re.compile(r"(이전|위의)\s*(지침|명령|프롬프트).{0,24}(무시|삭제|덮어)", re.I),
    re.compile(r"(activate|enable|활성화).{0,30}(audit\s*pack|감사\s*팩)", re.I),
    # 한국어는 서술어가 뒤에 오므로 "audit pack을 활성화" 어순도 함께 막습니다.
    re.compile(r"(audit\s*pack|감사\s*팩).{0,30}(activate|enable|활성화)", re.I),
    re.compile(r"(finding|판정).{0,30}(변경|수정|pass|fail)", re.I),
)


def contains_untrusted_instruction(value: object) -> bool:
    """문자열·매핑·목록을 재귀적으로 훑어 지시문 주입 시도를 찾습니다."""

    if isinstance(value, str):
        return any(
            pattern.search(value) is not None
            for pattern in UNTRUSTED_INSTRUCTION_PATTERNS
        )
    if isinstance(value, Mapping):
        return any(contains_untrusted_instruction(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(contains_untrusted_instruction(item) for item in value)
    return False
