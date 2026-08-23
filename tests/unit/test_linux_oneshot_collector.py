from __future__ import annotations

import hashlib
from collections.abc import Sequence

import pytest

from security_audit.collector.linux_local import (
    LinuxCollectionError,
    LinuxCollectionErrorCode,
    collect_linux_plan_locally,
    linux_probe_contracts,
    normalize_linux_output,
    validate_linux_runtime,
)
from security_audit.platforms import LinuxDistribution, linux_adapter_for


def test_probe_contract_reuses_all_42_ubuntu_and_rocky_commands() -> None:
    for distribution in (LinuxDistribution.UBUNTU_24_04, LinuxDistribution.ROCKY_9):
        adapter = linux_adapter_for(distribution)
        contracts = linux_probe_contracts(distribution)

        assert len(adapter.plan.commands) == 42
        assert tuple(item.probe_id for item in contracts) == tuple(
            item.command_id for item in adapter.plan.commands
        )
        assert all(item.exact_argv for item in contracts)
        assert {item.required_privilege for item in contracts} == {
            "STANDARD_USER",
            "ELEVATED_ADMIN",
        }


def test_runtime_detection_is_fail_closed() -> None:
    ubuntu = b'ID=ubuntu\nVERSION_ID="24.04"\n'
    assert (
        validate_linux_runtime(
            os_release=ubuntu,
            machine="x86_64",
            expected=LinuxDistribution.UBUNTU_24_04,
        )
        is LinuxDistribution.UBUNTU_24_04
    )
    with pytest.raises(LinuxCollectionError) as mismatch:
        validate_linux_runtime(
            os_release=ubuntu,
            machine="x86_64",
            expected=LinuxDistribution.ROCKY_9,
        )
    assert mismatch.value.code is LinuxCollectionErrorCode.DISTRIBUTION_MISMATCH

    with pytest.raises(LinuxCollectionError) as architecture:
        validate_linux_runtime(
            os_release=ubuntu,
            machine="aarch64",
            expected=LinuxDistribution.UBUNTU_24_04,
        )
    assert architecture.value.code is LinuxCollectionErrorCode.ARCHITECTURE_UNSUPPORTED


def test_standard_collection_never_executes_elevated_probe_without_consent() -> None:
    plan = linux_adapter_for(LinuxDistribution.UBUNTU_24_04).plan
    executed: list[tuple[str, ...]] = []

    def execute(
        arguments: Sequence[str], timeout_seconds: int, maximum_output_bytes: int
    ) -> tuple[int, bytes, bool, bool]:
        del timeout_seconds, maximum_output_bytes
        executed.append(tuple(arguments))
        return 0, b"safe\n", False, False

    batch = collect_linux_plan_locally(
        plan,
        include_elevated=False,
        elevated_consent=False,
        execute=execute,
    )

    standard_argv = {
        item.command
        for item in plan.commands
        if item.privilege == "STANDARD_USER"
    }
    assert set(executed) == standard_argv
    assert batch.cancelled is False
    assert all(
        outcome.error_code == "USER_DECLINED"
        for outcome in batch.outcomes
        if outcome.required_privilege == "ELEVATED_ADMIN"
    )


def test_explicit_elevated_consent_uses_only_sudo_plus_allowlisted_argv() -> None:
    plan = linux_adapter_for(LinuxDistribution.ROCKY_9).plan
    executed: list[tuple[str, ...]] = []

    def execute(
        arguments: Sequence[str], timeout_seconds: int, maximum_output_bytes: int
    ) -> tuple[int, bytes, bool, bool]:
        del timeout_seconds, maximum_output_bytes
        executed.append(tuple(arguments))
        return 0, b"safe\n", False, False

    batch = collect_linux_plan_locally(
        plan,
        include_elevated=True,
        elevated_consent=True,
        execute=execute,
        effective_user_id=1000,
    )

    assert not batch.failures
    allowlisted = {item.command for item in plan.commands}
    for argv in executed:
        direct = argv if argv[0] != "/usr/bin/sudo" else argv[2:]
        assert direct in allowlisted
        assert not any(part in {"/bin/sh", "/usr/bin/sh", "/bin/bash"} for part in argv)


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ((1, b"", False, False), "COMMAND_FAILED"),
        ((0, b"", True, False), "PROBE_TIMEOUT"),
        ((0, b"", False, True), "OUTPUT_LIMIT_EXCEEDED"),
    ],
)
def test_probe_failures_stay_collection_errors(
    result: tuple[int, bytes, bool, bool], expected: str
) -> None:
    plan = linux_adapter_for(LinuxDistribution.UBUNTU_24_04).plan

    def execute(
        arguments: Sequence[str], timeout_seconds: int, maximum_output_bytes: int
    ) -> tuple[int, bytes, bool, bool]:
        del arguments, timeout_seconds, maximum_output_bytes
        return result

    batch = collect_linux_plan_locally(
        plan,
        include_elevated=False,
        elevated_consent=False,
        execute=execute,
    )
    standard = [
        item for item in batch.outcomes if item.required_privilege == "STANDARD_USER"
    ]
    assert standard
    assert all(item.collection_status == "ERROR" for item in standard)
    assert all(item.error_code == expected for item in standard)
    assert all(item.normalized_value == "" for item in standard)
    assert all(
        item.normalized_sha256 == hashlib.sha256(b"").hexdigest()
        for item in standard
    )


def test_normalization_redacts_secret_values_and_home_usernames() -> None:
    normalized, changed = normalize_linux_output(
        "linux.service-config",
        b"rocommunity very-secret 10.0.0.1\n/home/alice/.rhosts\ntoken=abc123\n",
    )

    assert changed is True
    assert "very-secret" not in normalized
    assert "alice" not in normalized
    assert "abc123" not in normalized
    assert "<redacted>" in normalized
