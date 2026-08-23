"""정식 KISA UNIX U-01~U-67 Linux 점검 경로의 호환 진입점.

과거 ``LIN-01~06`` 초안 경로는 더 이상 별도 판정을 수행하지 않습니다. 기존
호출자가 갑자기 깨지지 않도록 이름은 유지하되, 수집 계획과 판정은 모두 배포판별
정식 U-01~U-67 구현으로 위임합니다.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime

from .contracts import DeviceControlResult
from .linux_adapters import UBUNTU_24_04, LinuxDistribution, linux_adapter_for
from .linux_kisa import KisaUnixAssessmentProfile, evaluate_kisa_unix

# 이전 공개 이름을 사용하는 호출자를 위한 호환값입니다. 신규 코드는 반드시
# ``linux_adapter_for(distribution).plan``을 사용해야 합니다.
LINUX_PLAN = UBUNTU_24_04.plan


def evaluate_linux_baseline(
    outputs: Mapping[str, bytes],
    *,
    captured_at: datetime,
    distribution: LinuxDistribution = LinuxDistribution.UBUNTU_24_04,
    profile: KisaUnixAssessmentProfile | None = None,
    password_maximum_age_days: int | None = None,
    password_minimum_length: int | None = None,
) -> tuple[DeviceControlResult, ...]:
    """기존 이름으로 정식 KISA UNIX 67개 판정을 실행합니다.

    두 과거 숫자 인자는 호출 호환성만 유지합니다. 기준값은 단일
    ``KisaUnixAssessmentProfile``에서 관리하여 초안과 정식 판정이 갈라지지 않게
    합니다.
    """

    selected = profile or KisaUnixAssessmentProfile()
    if password_maximum_age_days is not None or password_minimum_length is not None:
        selected = replace(
            selected,
            password_maximum_age_days=(
                password_maximum_age_days
                if password_maximum_age_days is not None
                else selected.password_maximum_age_days
            ),
            password_minimum_length=(
                password_minimum_length
                if password_minimum_length is not None
                else selected.password_minimum_length
            ),
        )
    linux_adapter_for(distribution)
    return evaluate_kisa_unix(
        outputs,
        captured_at=captured_at,
        distribution=distribution,
        profile=selected,
    )
