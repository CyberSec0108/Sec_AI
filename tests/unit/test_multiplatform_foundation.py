from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from security_audit.common.canonical_json import JsonValue, canonical_sha256
from security_audit.platforms import (
    AssetContext,
    DeviceAuditResult,
    PlatformContractError,
    SshReadOnlyTarget,
    build_device_ai_context,
    build_device_ai_messages,
    collect_plan_over_ssh,
    evaluate_linux_baseline,
    evaluate_switch_baseline,
)
from security_audit.platforms.readonly_plan import ReadOnlyCommand, ReadOnlyCommandPlan
from security_audit.platforms.switch import adapter_for

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _linux_outputs() -> dict[str, bytes]:
    values = json.loads(
        (PROJECT_ROOT / "tests/fixtures/platforms/linux/ubuntu_24_04_pass.json").read_text(
            encoding="utf-8"
        )
    )
    return {key: value.encode("utf-8") for key, value in values.items()}


def test_ssh_collector_executes_only_the_fixed_plan_without_forwarding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = tmp_path / "id_ed25519"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("test-only", encoding="utf-8")
    known_hosts.write_text("test-only", encoding="utf-8")
    captured: list[list[str]] = []
    monkeypatch.setattr(
        "security_audit.platforms.ssh_executor.shutil.which",
        lambda _name: "/usr/bin/ssh",
    )

    def fake_execute(
        arguments: list[str],
        timeout_seconds: int,
        maximum_output_bytes: int,
    ) -> tuple[int, bytes, bool]:
        assert timeout_seconds <= 60
        assert maximum_output_bytes <= 1024 * 1024
        captured.append(arguments)
        return 0, b"collected", False

    batch = collect_plan_over_ssh(
        adapter_for("CISCO_IOS").plan,
        SshReadOnlyTarget(
            host="switch-lab.local",
            username="secai",
            private_key=key,
            known_hosts=known_hosts,
        ),
        execute=fake_execute,
    )

    assert len(batch.outputs) == 4
    assert not batch.failures
    assert all("BatchMode=yes" in call for call in captured)
    assert all("ClearAllForwardings=yes" in call for call in captured)
    assert all(call[-1].startswith("show ") for call in captured)
    assert all(";" not in call[-1] for call in captured)


def test_ssh_collector_keeps_expected_inactive_service_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = tmp_path / "id_ed25519"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("test-only", encoding="utf-8")
    known_hosts.write_text("test-only", encoding="utf-8")
    monkeypatch.setattr(
        "security_audit.platforms.ssh_executor.shutil.which",
        lambda _name: "/usr/bin/ssh",
    )

    def fake_execute(
        arguments: list[str],
        timeout_seconds: int,
        maximum_output_bytes: int,
    ) -> tuple[int, bytes, bool]:
        del arguments, timeout_seconds, maximum_output_bytes
        return 3, b"inactive\n", False

    batch = collect_plan_over_ssh(
        ReadOnlyCommandPlan(
            platform="LINUX",
            commands=(
                ReadOnlyCommand(
                    "linux.service",
                    ("/usr/bin/systemctl", "is-active", "auditd"),
                    "ROOT",
                    10,
                    4_096,
                    (0, 3, 4),
                ),
            ),
        ),
        SshReadOnlyTarget(
            host="linux-lab.local",
            username="secai",
            private_key=key,
            known_hosts=known_hosts,
        ),
        execute=fake_execute,
    )

    assert batch.outputs == {"linux.service": b"inactive\n"}
    assert not batch.failures


def _audit_result() -> DeviceAuditResult:
    controls = evaluate_linux_baseline(_linux_outputs(), captured_at=NOW)
    return DeviceAuditResult(
        schema_version="1.0.0",
        run_id=uuid4(),
        asset=AssetContext(
            asset_id=uuid4(),
            asset_type="LINUX_SERVER",
            platform="LINUX",
            platform_version="Ubuntu 24.04",
            vendor="Canonical",
            product_family="Ubuntu Server",
        ),
        benchmark_id="SEC_AI_LINUX_BASELINE_DRAFT",
        benchmark_version="1.0.0",
        criteria_profile_id=None,
        criteria_sha256="a" * 64,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=4),
        controls=controls,
    )


def test_linux_compatibility_entrypoint_produces_67_hashed_read_only_results() -> None:
    results = evaluate_linux_baseline(_linux_outputs(), captured_at=NOW)

    assert [item.control_id for item in results] == [f"U-{number:02d}" for number in range(1, 68)]
    assert all(item.status in {"PASS", "FAIL", "ERROR", "REVIEW", "N/A"} for item in results)
    serialized = [item.to_json() for item in results]
    evidence = [cast(list[dict[str, JsonValue]], item["evidence"]) for item in serialized]
    assert all(item["status_authority"] == "RULE_ENGINE" for item in serialized)
    assert all(item[0]["raw_output_included"] is False for item in evidence)
    assert all(len(str(item[0]["raw_output_sha256"])) == 64 for item in evidence)


def test_linux_missing_command_is_error_not_false_pass() -> None:
    outputs = _linux_outputs()
    del outputs["linux.sshd-effective"]

    results = evaluate_linux_baseline(outputs, captured_at=NOW)

    affected = [
        item
        for item in results
        if any(trace.probe_id == "linux.sshd-effective" for trace in item.evidence)
    ]
    assert affected
    assert all(item.status == "ERROR" for item in affected)
    assert all(item.result_code.endswith("_COLLECTION_FAILED") for item in affected)


def test_linux_missing_required_setting_is_fail_not_collection_error() -> None:
    outputs = _linux_outputs()
    outputs["linux.login-defs"] = b"PASS_MAX_DAYS 99999\n"
    outputs["linux.pam-policy"] = b"pam_pwquality.so minlen=12\n"

    result = next(
        item
        for item in evaluate_linux_baseline(outputs, captured_at=NOW)
        if item.control_id == "U-02"
    )

    assert result.status == "FAIL"
    assert result.result_code == "U_02_NON_COMPLIANT"
    assert "최대 사용 기간 99999일" in result.observed_summary


@pytest.mark.parametrize(
    ("platform", "command_id", "config"),
    (
        (
            "CISCO_IOS",
            "cisco.running-config",
            b"""
enable secret 9 REDACTED
service password-encryption
line vty 0 4
 transport input ssh
snmp-server group SEC v3 priv
logging host 192.0.2.10
ntp server 192.0.2.20
""",
        ),
        (
            "ARUBA_AOS_CX",
            "aruba.running-config",
            b"""
user admin group administrators password ciphertext REDACTED
ssh server vrf default
snmpv3 user sec auth sha auth-pass ciphertext REDACTED
logging 192.0.2.10
ntp server 192.0.2.20
session-timeout 10
""",
        ),
    ),
)
def test_switch_adapters_share_results_but_keep_vendor_commands(
    platform: str,
    command_id: str,
    config: bytes,
) -> None:
    results = evaluate_switch_baseline(
        platform,
        {command_id: config},
        captured_at=NOW,
    )

    assert [item.control_id for item in results] == [
        "SW-01",
        "SW-02",
        "SW-03",
        "SW-04",
        "SW-05",
        "SW-06",
    ]
    assert all(item.status == "PASS" for item in results)
    assert adapter_for(platform).running_config_command_id == command_id
    assert "REDACTED" not in str([item.to_json() for item in results])


def test_unknown_switch_and_arbitrary_command_are_fail_closed() -> None:
    with pytest.raises(PlatformContractError):
        adapter_for("UNKNOWN_SWITCH")
    with pytest.raises(PlatformContractError):
        adapter_for("CISCO_IOS").plan.command("show arbitrary user command")


def test_common_result_hash_binds_asset_criteria_and_controls() -> None:
    result = _audit_result()
    body = result.to_json()

    result_sha256 = body.pop("result_sha256")
    assert result_sha256 == canonical_sha256(cast(JsonValue, body))
    assert body["raw_evidence_included"] is False
    assert body["status_authority"] == "RULE_ENGINE"


def test_device_ai_context_preserves_rule_authority_and_omits_raw_output() -> None:
    context = build_device_ai_context(
        _audit_result(),
        evidence_sources=(
            {
                "source_grade": "APPROVED_GUIDE",
                "document_title": "Linux 서버 보안 기준",
                "page": 12,
            },
        ),
    )

    instructions = cast(dict[str, JsonValue], context["instructions"])
    assert instructions["may_change_status"] is False
    assert instructions["may_execute_remediation"] is False
    assert context["raw_evidence_included"] is False
    assert len(str(context["context_sha256"])) == 64

    messages = build_device_ai_messages(
        _audit_result(),
        evidence_sources=(
            {
                "source_grade": "APPROVED_GUIDE",
                "document_title": "Linux 서버 보안 기준",
                "page": 12,
            },
        ),
    )
    assert "Linux" in messages.system_prompt
    assert "RULE_ENGINE" in messages.system_prompt
    assert '"raw_output_included":false' in messages.user_payload
    assert "REDACTED" not in messages.user_payload


def test_common_device_schema_is_registered() -> None:
    catalog = json.loads(
        (PROJECT_ROOT / "database/schemas/schema-catalog.json").read_text(encoding="utf-8")
    )
    names = {item["file"] for item in catalog["schemas"]}

    assert "device_audit_result.schema.json" in names
    assert _audit_result().to_json()["result_sha256"]


def test_readonly_command_allows_long_filesystem_scans_up_to_three_minutes() -> None:
    accepted = ReadOnlyCommand(
        "linux.ownerless",
        ("/usr/bin/find", "/etc", "-xdev", "-nouser", "-print"),
        "ROOT",
        180,
        524_288,
        (0, 1),
    )

    assert accepted.timeout_seconds == 180

    with pytest.raises(PlatformContractError):
        ReadOnlyCommand(
            "linux.ownerless",
            ("/usr/bin/find", "/etc", "-xdev", "-nouser", "-print"),
            "ROOT",
            181,
            524_288,
            (0, 1),
        )
