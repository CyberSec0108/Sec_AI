from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_audit.platforms import (
    KISA_2026_UNIX_CONTROLS,
    KisaUnixAssessmentProfile,
    LinuxDistribution,
    detect_linux_distribution,
    evaluate_kisa_unix,
    linux_adapter_for,
)

NOW = datetime(2026, 8, 2, 12, 0, tzinfo=UTC)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_kisa_unix_mapping_covers_all_67_controls_and_exact_pdf() -> None:
    mapping_path = (
        PROJECT_ROOT / "guides/mappings/kisa_2026_unix_control_sources.json"
    )
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))

    assert mapping["guide"]["source_sha256"] == (
        "44fe393981b244147be6af7423d99dc15633c089fad0bcb296cbe2371dde812d"
    )
    assert mapping["guide"]["pdf_page_start"] == 12
    assert mapping["guide"]["pdf_page_end"] == 171
    assert len(mapping["mappings"]) == 67
    assert [item["control_id"] for item in mapping["mappings"]] == [
        f"U-{number:02d}" for number in range(1, 68)
    ]
    assert [item.control_id for item in KISA_2026_UNIX_CONTROLS] == [
        f"U-{number:02d}" for number in range(1, 68)
    ]
    assert [
        (
            item.control_id,
            item.severity,
            item.category.split(". ", maxsplit=1)[1],
            item.title,
            item.page_start,
            item.page_end,
        )
        for item in KISA_2026_UNIX_CONTROLS
    ] == [
        (
            item["control_id"],
            item["severity"],
            item["category"],
            item["title"],
            item["page_start"],
            item["page_end"],
        )
        for item in mapping["mappings"]
    ]
    assert mapping["mappings"][0]["title"] == "root 계정 원격 접속 제한"
    assert mapping["mappings"][-1]["title"] == (
        "로그 디렉터리 소유자 및 권한 설정"
    )
    assert Counter(item.category for item in KISA_2026_UNIX_CONTROLS) == {
        "1. 계정 관리": 13,
        "2. 파일 및 디렉토리 관리": 20,
        "3. 서비스 관리": 30,
        "4. 패치 관리": 1,
        "5. 로그 관리": 3,
    }


@pytest.mark.parametrize(
    ("os_release", "expected"),
    (
        (
            b'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n',
            LinuxDistribution.UBUNTU_24_04,
        ),
        (
            b'NAME="Rocky Linux"\nID="rocky"\nVERSION_ID="9.6"\n',
            LinuxDistribution.ROCKY_9,
        ),
    ),
)
def test_distribution_detection_is_exact(
    os_release: bytes,
    expected: LinuxDistribution,
) -> None:
    assert detect_linux_distribution(os_release) is expected


def test_ubuntu_and_rocky_keep_separate_read_only_commands() -> None:
    ubuntu = linux_adapter_for(LinuxDistribution.UBUNTU_24_04)
    rocky = linux_adapter_for(LinuxDistribution.ROCKY_9)

    ubuntu_commands = {item.command_id: item.command for item in ubuntu.plan.commands}
    rocky_commands = {item.command_id: item.command for item in rocky.plan.commands}

    assert ubuntu_commands["linux.pam-policy"] != rocky_commands["linux.pam-policy"]
    assert ubuntu_commands["linux.package-inventory"][0] == "/usr/bin/dpkg-query"
    assert rocky_commands["linux.package-inventory"][0] == "/usr/bin/rpm"
    assert ubuntu_commands["linux.firewall-state"][0] == "/usr/sbin/ufw"
    assert rocky_commands["linux.firewall-state"][0] == "/usr/bin/firewall-cmd"
    assert ubuntu_commands["linux.profile-policy"] != rocky_commands["linux.profile-policy"]
    assert "/etc/bash.bashrc" in ubuntu_commands["linux.profile-policy"]
    assert "/etc/bashrc" in rocky_commands["linux.profile-policy"]
    assert ubuntu_commands["linux.listening-sockets"][0] == "/usr/bin/ss"
    assert rocky_commands["linux.listening-sockets"][0] == "/usr/bin/ss"
    assert "--cacheonly" in rocky_commands["linux.pending-security-updates"]
    assert len(ubuntu_commands) == len(ubuntu.plan.commands)
    assert len(rocky_commands) == len(rocky.plan.commands)
    assert set(ubuntu_commands) == set(rocky_commands)
    assert all(item.privilege in {"STANDARD_USER", "ROOT"} for item in ubuntu.plan.commands)
    assert all(item.privilege in {"STANDARD_USER", "ROOT"} for item in rocky.plan.commands)


def test_kisa_evaluator_always_returns_67_traceable_results() -> None:
    adapter = linux_adapter_for(LinuxDistribution.UBUNTU_24_04)
    outputs = {item.command_id: b"" for item in adapter.plan.commands}
    outputs.update(
        {
            "linux.os-release": b'ID=ubuntu\nVERSION_ID="24.04"\n',
            "linux.sshd-effective": b"permitrootlogin no\n",
            "linux.passwd-db": b"root:x:0:0:root:/root:/bin/bash\n",
            "linux.group-db": b"root:x:0:\nsudo:x:27:root\n",
            "linux.login-defs": (
                b"PASS_MAX_DAYS 90\nPASS_MIN_LEN 10\n"
                b"UMASK 027\nENCRYPT_METHOD YESCRYPT\n"
            ),
            "linux.pam-policy": b"pam_faillock.so deny=5\npam_pwquality.so minlen=10\n",
            "linux.pam-su": b"auth required pam_wheel.so use_uid group=sudo\n",
            "linux.passwd-mode": b"644:root:root\n",
            "linux.shadow-mode": b"640:root:shadow\n",
            "linux.hosts-mode": b"644:root:root\n",
            "linux.services-mode": b"644:root:root\n",
            "linux.time-sync": b"yes\n",
            "linux.auditd-state": b"active\n",
            "linux.logging-state": b"active\n",
            "linux.firewall-state": b"Status: active\n",
            "linux.pending-security-updates": b"0\n",
        }
    )

    results = evaluate_kisa_unix(
        outputs,
        captured_at=NOW,
        distribution=LinuxDistribution.UBUNTU_24_04,
    )

    assert len(results) == 67
    assert [item.control_id for item in results] == [
        f"U-{number:02d}" for number in range(1, 68)
    ]
    assert all(item.evidence for item in results)
    assert all(item.status in {"PASS", "FAIL", "ERROR", "REVIEW", "N/A"} for item in results)
    assert all(item.to_json()["official_finding_write_allowed"] is False for item in results)


def test_missing_probe_is_error_and_never_false_pass() -> None:
    results = evaluate_kisa_unix(
        {},
        captured_at=NOW,
        distribution=LinuxDistribution.ROCKY_9,
    )

    assert len(results) == 67
    assert all(item.status == "ERROR" for item in results)


def test_rocky_fixture_exercises_all_67_controls_without_missing_probe() -> None:
    fixture_path = (
        PROJECT_ROOT / "tests/fixtures/platforms/linux/rocky_9_kisa_sample.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    adapter = linux_adapter_for(LinuxDistribution.ROCKY_9)
    outputs = {item.command_id: b"" for item in adapter.plan.commands}
    outputs.update(
        {key: value.encode() for key, value in fixture["outputs"].items()}
    )

    results = evaluate_kisa_unix(
        outputs,
        captured_at=NOW,
        distribution=LinuxDistribution.ROCKY_9,
    )

    assert fixture["fixture_type"] == "SYNTHETIC"
    assert len(results) == 67
    assert not [item for item in results if item.status == "ERROR"]


def test_uid_zero_check_does_not_depend_on_passwd_row_order() -> None:
    adapter = linux_adapter_for(LinuxDistribution.UBUNTU_24_04)
    outputs = {item.command_id: b"" for item in adapter.plan.commands}
    outputs["linux.passwd-db"] = (
        b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        b"root:x:0:0:root:/root:/bin/bash\n"
    )

    result = evaluate_kisa_unix(
        outputs,
        captured_at=NOW,
        distribution=LinuxDistribution.UBUNTU_24_04,
    )[4]

    assert result.control_id == "U-05"
    assert result.status == "PASS"


def test_anonymous_share_control_fails_on_explicit_unsafe_setting() -> None:
    adapter = linux_adapter_for(LinuxDistribution.ROCKY_9)
    outputs = {item.command_id: b"" for item in adapter.plan.commands}
    outputs.update(
        {
            "linux.active-services": b"vsftpd.service loaded active running\n",
            "linux.enabled-services": b"vsftpd.service enabled\n",
            "linux.service-config": b"anonymous_enable=YES\n",
        }
    )

    result = evaluate_kisa_unix(
        outputs,
        captured_at=NOW,
        distribution=LinuxDistribution.ROCKY_9,
    )[34]

    assert result.control_id == "U-35"
    assert result.status == "FAIL"


@pytest.mark.parametrize(
    ("log_metadata", "expected"),
    (
        (b"644:root:adm:/var/log/auth.log\n600:root:root:/var/log/private.log\n", "PASS"),
        (b"644:service:adm:/var/log/service.log\n", "FAIL"),
        (b"664:root:adm:/var/log/group-writable.log\n", "FAIL"),
    ),
)
def test_log_file_owner_and_mode_follow_u67(
    log_metadata: bytes,
    expected: str,
) -> None:
    adapter = linux_adapter_for(LinuxDistribution.UBUNTU_24_04)
    outputs = {item.command_id: b"" for item in adapter.plan.commands}
    outputs["linux.log-metadata"] = log_metadata

    result = evaluate_kisa_unix(
        outputs,
        captured_at=NOW,
        distribution=LinuxDistribution.UBUNTU_24_04,
    )[-1]

    assert result.control_id == "U-67"
    assert result.status == expected


@pytest.mark.parametrize("service", ("postfix", "named"))
def test_service_version_controls_require_vendor_version_confirmation(
    service: str,
) -> None:
    adapter = linux_adapter_for(LinuxDistribution.UBUNTU_24_04)
    outputs = {item.command_id: b"" for item in adapter.plan.commands}
    outputs.update(
        {
            "linux.active-services": f"{service}.service active running\n".encode(),
            "linux.package-inventory": f"{service}\t1.0\n".encode(),
            "linux.pending-security-updates": b"0 upgraded, 0 newly installed\n",
        }
    )

    results = evaluate_kisa_unix(
        outputs,
        captured_at=NOW,
        distribution=LinuxDistribution.UBUNTU_24_04,
    )
    result = results[44] if service == "postfix" else results[48]

    assert result.status == "REVIEW"


def test_unsupported_distribution_is_rejected() -> None:
    with pytest.raises(ValueError):
        detect_linux_distribution(b"ID=opensuse-leap\nVERSION_ID=15.6\n")


def test_linux_product_default_resolves_account_and_port_policy_without_review() -> None:
    fixture = json.loads(
        (PROJECT_ROOT / "tests/fixtures/platforms/linux/rocky_9_kisa_sample.json").read_text(
            encoding="utf-8"
        )
    )
    results = evaluate_kisa_unix(
        {key: value.encode() for key, value in fixture["outputs"].items()},
        captured_at=NOW,
        distribution=LinuxDistribution.ROCKY_9,
    )
    by_id = {item.control_id: item for item in results}

    assert by_id["U-07"].status in {"PASS", "FAIL"}
    assert by_id["U-08"].status in {"PASS", "FAIL"}
    assert by_id["U-28"].status in {"PASS", "FAIL"}


def test_linux_product_criteria_accepts_only_safe_structured_values() -> None:
    values = KisaUnixAssessmentProfile().public_values()
    values.update(
        {
            "password_minimum_length": 12,
            "approved_admin_accounts": ["root", "security-admin"],
            "approved_listening_ports": [22, 443],
        }
    )

    profile = KisaUnixAssessmentProfile.from_values(values)

    assert profile.password_minimum_length == 12
    assert profile.approved_admin_accounts == ("root", "security-admin")
    assert profile.approved_listening_ports == (22, 443)


def test_linux_product_criteria_rejects_command_like_input() -> None:
    values = KisaUnixAssessmentProfile().public_values()
    values["approved_admin_accounts"] = ["root; shutdown"]

    with pytest.raises(ValueError, match="LINUX_CRITERIA_VALUE_INVALID"):
        KisaUnixAssessmentProfile.from_values(values)


def test_filesystem_scan_probes_get_measured_timeouts_and_others_stay_short() -> None:
    plan = linux_adapter_for(LinuxDistribution.UBUNTU_24_04).plan
    timeouts = {
        command.command_id: command.timeout_seconds for command in plan.commands
    }

    assert timeouts["linux.ownerless"] == 150
    assert timeouts["linux.suid-sgid"] == 60
    assert timeouts["linux.world-writable"] == 60
    assert timeouts["linux.passwd-db"] == 30
    assert max(timeouts.values()) == 150
