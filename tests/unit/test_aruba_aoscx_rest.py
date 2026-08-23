from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from security_audit.platforms.aruba_rest import (
    ArubaRestCollectionError,
    ArubaRestTarget,
    collect_aruba_rest_projection,
    evaluate_aruba_rest_baseline,
)
from security_audit.platforms.contracts import PlatformContractError
from security_audit.platforms.kisa_network import (
    KISA_NETWORK_CONTROLS,
    NETWORK_CRITERIA_FIELDS,
    NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS,
    KisaNetworkAssessmentProfile,
)

NOW = datetime(2026, 8, 6, tzinfo=UTC)
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class FakeSession:
    def __init__(self, payloads: dict[str, object], *, privilege: int = 15) -> None:
        self.payloads = payloads
        self.privilege = privilege
        self.calls: list[tuple[str, str]] = []

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *args: object) -> None:
        self.calls.append(("CLOSE", "session"))

    def login(self) -> int:
        self.calls.append(("POST", "login"))
        return self.privilege

    def get_json(self, endpoint_id: str) -> object:
        self.calls.append(("GET", endpoint_id))
        return self.payloads[endpoint_id]

    def get_text(self, endpoint_id: str) -> str:
        self.calls.append(("GET_TEXT", endpoint_id))
        value = self.payloads[endpoint_id]
        assert isinstance(value, str)
        return value

    def logout(self) -> None:
        self.calls.append(("POST", "logout"))


def _secure_payloads() -> dict[str, object]:
    return {
        "api_versions": {"latest": {"version": "v10.13"}},
        "system": {
            "enable_snmpv3_only": True,
            "ssh_maximum_authentication_attempts": 3,
            "password_complexity": {"enable": True, "minimum_length": 8},
            "ssh_server_allowlist_enable": True,
            "ssh_server_allowlist_ips": ["192.168.11.0/24"],
            "usb_disable": True,
            "bluetooth_mgmt_disable": True,
            "snmp_communities": {},
            "snmp_community_acls": {},
            "cdp_mode": "disable",
            "icmp_unreachable_disable": True,
            "icmp_redirect_disable": True,
            "cli_session": {"timeout": 10, "max_per_user": 2},
            "http_session": {"timeout": 10},
            "ntp_config": {"enable": True},
            "ntp_config_vrf": {"mgmt": "/rest/v10.13/system/vrfs/mgmt"},
            "hw_default_copp_policy": "/rest/v10.13/system/copp_policies/default",
        },
        "system_status": {
            "software_version": "Virtual.10.13.1170",
        },
        "current_user": {
            "user_name": "secai-lab-admin",
            "user_group": {
                "administrators": "/rest/v10.13/system/user_groups/administrators"
            },
        },
        "mgmt_vrf": {
            "name": "mgmt",
            "type": "management",
            "ssh_enable": True,
            "snmp_enable": True,
            "https_server": {"enable": True},
            "dns_name_servers": {},
        },
        "vrfs": {
            "mgmt": {
                "name": "mgmt",
                "type": "management",
                "ssh_enable": True,
                "telnet_server_enable": False,
                "snmp_enable": True,
                "https_server": {"enable": True},
                "dns_name_servers": {},
            },
            "default": {
                "name": "default",
                "type": "default",
                "ssh_enable": False,
                "telnet_server_enable": False,
                "snmp_enable": False,
                "https_server": {"enable": False},
                "dns_name_servers": {},
            },
        },
        "interfaces": {
            "1/1/1": {
                "name": "1/1/1",
                "type": "system",
                "admin": "down",
                "description": None,
                "routing": False,
                "ip_directed_broadcast": False,
                "ip_proxy_arp": False,
            },
            "vlan1": {
                "name": "vlan1",
                "type": "vlan",
                "admin": "up",
                "description": "관리 VLAN",
                "routing": True,
                "ipv4_source_lockdown_enable": True,
                "ipv6_source_lockdown_enable": True,
                "ip_directed_broadcast": False,
                "ip_proxy_arp": False,
            },
        },
        "user_groups": {
            "administrators": {"name": "administrators", "origin": "built-in"},
            "operators": {"name": "operators", "origin": "built-in"},
            "auditors": {"name": "auditors", "origin": "built-in"},
        },
        "users": {
            "secai-lab-admin": {
                "user_name": "secai-lab-admin",
                "user_group": {
                    "administrators": "/rest/v10.13/system/user_groups/administrators"
                },
                "password": "MUST_NOT_LEAK",
            },
            "secai-auditor": {
                "user_name": "secai-auditor",
                "user_group": {
                    "auditors": "/rest/v10.13/system/user_groups/auditors"
                },
            },
        },
        "acls": {},
        "logging_filters": {},
        "snmpv3_users": {
            "secai-snmp": {
                "user_name": "secai-snmp",
                "auth_protocol": "sha256",
                "priv_protocol": "aes256",
                "access_level": "ro",
                "auth_pass_phrase": "MUST_NOT_LEAK",
            }
        },
        "syslog_remotes": {
            "192.168.11.1": {
                "remote_host": "192.168.11.1",
                "disable": False,
                "include_auditable_events": True,
            }
        },
        # 10.13.1170은 관리 VRF를 지정해도 구성 서버 행을 default 컬렉션에 반환합니다.
        "ntp_associations": {},
        "ntp_associations_default": {
            "192.168.11.1": {"address": "192.168.11.1", "iburst": True}
        },
        "hot_patches": {},
        "event_logs": {
            "1": {
                "timestamp": "2026-08-06T11:01:42.498813+00:00",
                "message": "MUST_NOT_LEAK",
            }
        },
        "running_config": (
            "banner motd ^\nAuthorized access only. Activity is monitored.\n^\n"
            "logging persistent-storage severity info\n"
            "snmp-server vrf mgmt\n"
            "user secai-lab-admin group administrators password ciphertext MUST_NOT_LEAK\n"
        ),
    }


def test_aruba_rest_target_rejects_invalid_identity_and_hides_password() -> None:
    target = ArubaRestTarget(
        "192.168.11.10",
        "secai-lab-admin",
        "secret-value",
        "a" * 64,
    )

    assert "secret-value" not in repr(target)
    with pytest.raises(PlatformContractError):
        ArubaRestTarget(
            "192.168.11.10/path",
            "admin",
            "secret-value",
            "a" * 64,
        )
    with pytest.raises(PlatformContractError):
        ArubaRestTarget(
            "192.168.11.10",
            "admin",
            "secret-value",
            "wrong",
        )


def test_aruba_rest_collection_uses_only_fixed_gets_and_redacts_secrets() -> None:
    fake = FakeSession(_secure_payloads())
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: fake,
    )

    assert fake.calls == [
        ("POST", "login"),
        ("GET", "api_versions"),
        ("GET", "current_user"),
        ("GET", "system"),
        ("GET", "system_status"),
        ("GET", "mgmt_vrf"),
        ("GET", "vrfs"),
        ("GET", "interfaces"),
        ("GET", "user_groups"),
        ("GET", "users"),
        ("GET", "acls"),
        ("GET", "logging_filters"),
        ("GET", "snmpv3_users"),
        ("GET", "syslog_remotes"),
        ("GET", "ntp_associations"),
        ("GET", "ntp_associations_default"),
        ("GET", "hot_patches"),
        ("GET", "event_logs"),
        ("GET_TEXT", "running_config"),
        ("POST", "logout"),
        ("CLOSE", "session"),
    ]
    assert projection.controls == {
        "SW-01": True,
        "SW-02": True,
        "SW-03": True,
        "SW-04": True,
        "SW-05": True,
        "SW-06": True,
    }
    assert "MUST_NOT_LEAK" not in projection.canonical_bytes.decode()
    assert "192.168.11.0/24" not in projection.canonical_bytes.decode()
    assert "secret" not in repr(projection)


def test_kisa_network_catalog_covers_n01_through_n38_in_source_order() -> None:
    assert [item.control_id for item in KISA_NETWORK_CONTROLS] == [
        f"N-{index:02d}" for index in range(1, 39)
    ]
    assert KISA_NETWORK_CONTROLS[0].source_pages == "391~394"
    assert KISA_NETWORK_CONTROLS[-1].source_pages == "466"
    assert {item.severity for item in KISA_NETWORK_CONTROLS} == {"상", "중", "하"}


def test_kisa_network_catalog_matches_approved_source_mapping() -> None:
    payload = json.loads(
        (PROJECT_ROOT / "guides/mappings/kisa_2026_all_control_sources.json").read_text(
            encoding="utf-8"
        )
    )
    mapped = {
        item["control_id"]: item
        for item in payload["mappings"]
        if str(item["control_id"]).startswith("N-")
    }

    assert list(mapped) == [f"N-{index:02d}" for index in range(1, 39)]
    for definition in KISA_NETWORK_CONTROLS:
        source = mapped[definition.control_id]
        assert source["control_title"] == definition.title
        assert source["mapping_status"] == "APPROVED_SOURCE"
        expected_pages = str(source["page_start"])
        if source["page_end"] != source["page_start"]:
            expected_pages += f"~{source['page_end']}"
        assert definition.source_pages == expected_pages


def test_switch_criteria_defaults_are_closed_structured_values() -> None:
    profile = KisaNetworkAssessmentProfile()
    values = profile.public_values()

    assert len(NETWORK_CRITERIA_FIELDS) == 26
    assert len(NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS) == 2
    assert set(values) == {
        item.key
        for item in (
            *NETWORK_CRITERIA_FIELDS,
            *NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS,
        )
    }
    assert values["login_failure_lock_threshold"] == 5
    assert values["tftp_disabled"] is True
    assert {
        values[item.key] for item in NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS
    } == {"PASS"}
    with pytest.raises(ValueError, match="SWITCH_CRITERIA_KEYS_INVALID"):
        KisaNetworkAssessmentProfile.from_values({"raw_command": "show run"})
    invalid = dict(values)
    invalid["login_failure_lock_threshold"] = 0
    with pytest.raises(ValueError, match="SWITCH_CRITERIA_VALUE_INVALID"):
        KisaNetworkAssessmentProfile.from_values(invalid)
    invalid = dict(values)
    invalid["n12_patch_advisory_assessment"] = "MUST_NOT_LEAK"
    with pytest.raises(ValueError, match="SWITCH_SUPPLEMENTAL_VALUE_INVALID"):
        KisaNetworkAssessmentProfile.from_values(invalid)


def test_supplemental_assessment_changes_verdict_without_overwriting_observation() -> None:
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: FakeSession(_secure_payloads()),
    )

    defaults = evaluate_aruba_rest_baseline(
        projection,
        captured_at=NOW,
        criteria_profile=KisaNetworkAssessmentProfile(),
    )
    changed_values = KisaNetworkAssessmentProfile().public_values()
    changed_values["n12_patch_advisory_assessment"] = "FAIL"
    changed = evaluate_aruba_rest_baseline(
        projection,
        captured_at=NOW,
        criteria_profile=KisaNetworkAssessmentProfile.from_values(changed_values),
    )
    default_by_id = {item.control_id: item for item in defaults}
    changed_by_id = {item.control_id: item for item in changed}

    assert default_by_id["N-04"].status == "PASS"
    assert default_by_id["N-21"].status == "N/A"
    assert changed_by_id["N-21"].status == "N/A"
    assert default_by_id["N-12"].status == "PASS"
    assert changed_by_id["N-12"].status == "FAIL"
    assert default_by_id["N-12"].observed_summary == changed_by_id["N-12"].observed_summary
    assert "Virtual.10.13.1170" in default_by_id["N-12"].observed_summary
    assert "조직 보완 판정: 충족" in default_by_id["N-12"].expected_summary
    assert "조직 보완 판정: 미충족" in changed_by_id["N-12"].expected_summary
    assert default_by_id["N-12"].result_code.endswith("_ORGANIZATION_INPUT")
    assert changed_by_id["N-12"].result_code.endswith("_ORGANIZATION_INPUT")
    assert default_by_id["N-12"].evidence[0].source_label == "AOS-CX 구조화 보안 설정"


def test_missing_profile_keeps_supplemental_controls_in_review() -> None:
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: FakeSession(_secure_payloads()),
    )

    by_id = {
        item.control_id: item
        for item in evaluate_aruba_rest_baseline(projection, captured_at=NOW)
    }

    assert by_id["N-04"].status == "PASS"
    assert by_id["N-10"].status == "PASS"
    assert by_id["N-12"].status == "REVIEW"
    assert by_id["N-17"].status == "REVIEW"
    assert by_id["N-25"].status == "N/A"
    assert not by_id["N-04"].result_code.endswith("_ORGANIZATION_INPUT")


def test_default_profile_judges_all_controls_with_only_two_organization_inputs() -> None:
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: FakeSession(_secure_payloads()),
    )

    results = evaluate_aruba_rest_baseline(
        projection,
        captured_at=NOW,
        criteria_profile=KisaNetworkAssessmentProfile(),
    )
    organization_controls = {
        item.control_id
        for item in results
        if item.result_code.endswith("_ORGANIZATION_INPUT")
    }

    assert all(item.status != "REVIEW" for item in results)
    assert organization_controls == {"N-12", "N-17"}


def test_aruba_rest_kisa_network_evaluation_covers_all_without_false_pass() -> None:
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: FakeSession(_secure_payloads()),
    )

    results = evaluate_aruba_rest_baseline(projection, captured_at=NOW)
    by_id = {item.control_id: item for item in results}

    assert list(by_id) == [f"N-{index:02d}" for index in range(1, 39)]
    assert len(results) == 38
    assert by_id["N-01"].status == "PASS"
    assert by_id["N-06"].status == "PASS"
    assert by_id["N-07"].status == "PASS"
    assert by_id["N-08"].status == "PASS"
    assert by_id["N-12"].status == "REVIEW"
    assert by_id["N-20"].status == "N/A"
    assert by_id["N-09"].status == "PASS"
    assert by_id["N-14"].status == "PASS"
    assert by_id["N-22"].status == "PASS"
    assert by_id["N-24"].status == "PASS"
    assert by_id["N-27"].status == "PASS"
    assert by_id["N-30"].status == "PASS"
    assert by_id["N-31"].status == "PASS"
    assert by_id["N-33"].status == "PASS"
    assert by_id["N-34"].status == "PASS"
    assert by_id["N-36"].status == "PASS"
    assert {item.control_id for item in results if item.status == "REVIEW"} == {
        "N-12", "N-17"
    }
    assert {
        item.control_id for item in results if item.status == "N/A"
    } == {
        "N-13", "N-20", "N-21", "N-25", "N-26", "N-28",
        "N-29", "N-32", "N-35", "N-37", "N-38",
    }


def test_aruba_rest_baseline_returns_all_kisa_network_controls() -> None:
    fake = FakeSession(_secure_payloads())
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: fake,
    )

    results = evaluate_aruba_rest_baseline(projection, captured_at=NOW)

    assert [item.control_id for item in results] == [
        f"N-{index:02d}" for index in range(1, 39)
    ]
    assert {item.status for item in results} >= {"PASS", "REVIEW", "N/A"}
    assert "MUST_NOT_LEAK" not in str([item.to_json() for item in results])


def test_aruba_rest_baseline_preserves_distinct_redacted_values_per_control() -> None:
    fake = FakeSession(_secure_payloads())
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: fake,
    )

    results = evaluate_aruba_rest_baseline(projection, captured_at=NOW)
    observed = {item.control_id: item.observed_summary for item in results}

    assert observed["N-01"] == "관리자 비밀번호 인증: 성공"
    assert observed["N-07"] == "CLI 유휴 제한: 10분, 웹 관리 유휴 제한: 10분"
    assert observed["N-11"] == "활성 원격 syslog 서버: 1개"
    assert observed["N-10"] == "로그인 경고 배너: 설정, 시스템 식별정보 노출: 없음"
    assert observed["N-12"] == (
        "실행 소프트웨어: Virtual.10.13.1170, 설치 hot patch: 0개, "
        "벤더 권고 검토 이력은 조직 증적 필요"
    )
    assert observed["N-16"] == "최근 이벤트 로그 timestamp: 확인"
    assert observed["N-15"] == "NTP client: 활성화, 구성 서버: 1개"
    assert observed["N-22"] == "라우팅 인터페이스: 1개, source lockdown 적용: 1개"
    assert observed["N-24"] == (
        "물리 인터페이스: 1개, 활성: 0개, 활성·용도 미표시: 0개"
    )
    assert observed["N-30"] == "CDP 동작 모드: disable"
    assert observed["N-31"] == "Directed broadcast 활성 인터페이스: 0개"
    assert observed["N-33"] == "Proxy ARP 활성 인터페이스: 0개"
    assert len(set(observed.values())) > 20
    serialized = str(projection).casefold()
    assert "192.168.11.1" not in serialized
    assert "secai-snmp" not in serialized
    assert "must_not_leak" not in serialized


def test_direct_device_collection_rejects_missing_banner_and_timestamp() -> None:
    payloads = _secure_payloads()
    payloads["running_config"] = "logging persistent-storage severity info\n"
    payloads["event_logs"] = {"1": {"message": "no timestamp"}}
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: FakeSession(payloads),
    )

    by_id = {
        item.control_id: item
        for item in evaluate_aruba_rest_baseline(projection, captured_at=NOW)
    }

    assert by_id["N-10"].status == "FAIL"
    assert by_id["N-16"].status == "FAIL"


def test_direct_device_collection_rejects_admin_only_accounts_and_open_snmp() -> None:
    payloads = _secure_payloads()
    users = payloads["users"]
    assert isinstance(users, dict)
    users.pop("secai-auditor")
    vrfs = payloads["vrfs"]
    assert isinstance(vrfs, dict)
    default_vrf = vrfs["default"]
    assert isinstance(default_vrf, dict)
    default_vrf["snmp_enable"] = True
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: FakeSession(payloads),
    )

    by_id = {
        item.control_id: item
        for item in evaluate_aruba_rest_baseline(projection, captured_at=NOW)
    }

    assert by_id["N-05"].status == "FAIL"
    assert by_id["N-19"].status == "FAIL"


def test_aruba_rest_insecure_payloads_fail_without_false_pass() -> None:
    payloads = _secure_payloads()
    payloads["system"] = {
        "enable_snmpv3_only": False,
        "cli_session": {"timeout": 0},
        "http_session": {"timeout": 0},
        "ntp_config": {"enable": False},
    }
    payloads["snmpv3_users"] = {}
    payloads["syslog_remotes"] = {}
    payloads["ntp_associations"] = {}
    payloads["ntp_associations_default"] = {}
    fake = FakeSession(payloads)
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: fake,
    )

    results = evaluate_aruba_rest_baseline(projection, captured_at=NOW)

    by_id = {item.control_id: item for item in results}
    assert by_id["N-02"].status == "FAIL"
    assert by_id["N-06"].status == "REVIEW"
    assert by_id["N-11"].status == "FAIL"
    assert by_id["N-15"].status == "FAIL"
    assert by_id["N-18"].status != "PASS"
    assert by_id["N-07"].status == "FAIL"
    assert by_id["N-34"].status == "REVIEW"


def test_aruba_rest_expanded_facts_fail_insecure_device_values() -> None:
    payloads = _secure_payloads()
    system = payloads["system"]
    assert isinstance(system, dict)
    system["usb_disable"] = False
    system["bluetooth_mgmt_disable"] = False
    vrfs = payloads["vrfs"]
    assert isinstance(vrfs, dict)
    default_vrf = vrfs["default"]
    assert isinstance(default_vrf, dict)
    default_vrf["https_server"] = {"enable": True}
    default_vrf["dns_name_servers"] = {"1": "MUST_NOT_LEAK"}
    interfaces = payloads["interfaces"]
    assert isinstance(interfaces, dict)
    routed = interfaces["vlan1"]
    assert isinstance(routed, dict)
    routed["ipv4_source_lockdown_enable"] = False
    routed["ipv6_source_lockdown_enable"] = False
    routed["ip_directed_broadcast"] = True
    routed["ip_proxy_arp"] = True
    physical = interfaces["1/1/1"]
    assert isinstance(physical, dict)
    physical["admin"] = "up"
    syslogs = payloads["syslog_remotes"]
    assert isinstance(syslogs, dict)
    first_syslog = next(iter(syslogs.values()))
    assert isinstance(first_syslog, dict)
    first_syslog["include_auditable_events"] = False

    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: FakeSession(payloads),
    )
    by_id = {
        item.control_id: item
        for item in evaluate_aruba_rest_baseline(projection, captured_at=NOW)
    }

    for control_id in ("N-09", "N-14", "N-22", "N-24", "N-27", "N-31", "N-33", "N-36"):
        assert by_id[control_id].status == "FAIL"
    assert "MUST_NOT_LEAK" not in projection.canonical_bytes.decode()


def test_active_documented_interface_still_requires_business_inventory_review() -> None:
    payloads = _secure_payloads()
    interfaces = payloads["interfaces"]
    assert isinstance(interfaces, dict)
    physical = interfaces["1/1/1"]
    assert isinstance(physical, dict)
    physical["admin"] = "up"
    physical["description"] = "업무 서버 연결"
    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "secai-lab-admin", "secret", "a" * 64),
        session_factory=lambda _: FakeSession(payloads),
    )

    by_id = {
        item.control_id: item
        for item in evaluate_aruba_rest_baseline(projection, captured_at=NOW)
    }

    assert by_id["N-24"].status == "REVIEW"
    assert "실제 업무 용도대장 대조 필요" in by_id["N-24"].observed_summary


def test_aruba_rest_login_requires_administrator_privilege() -> None:
    fake = FakeSession(_secure_payloads(), privilege=1)

    with pytest.raises(ArubaRestCollectionError, match="INSUFFICIENT_PRIVILEGE"):
        collect_aruba_rest_projection(
            ArubaRestTarget("192.168.11.10", "operator", "secret", "a" * 64),
            session_factory=lambda _: fake,
        )


def test_aruba_builtin_admin_is_accepted_when_group_field_is_omitted() -> None:
    payloads = _secure_payloads()
    # AOS-CX 10.13.1170의 내장 admin REST 응답에는 user_group 필드가 없습니다.
    payloads["current_user"] = {
        "authorized_keys": {},
        "current_password": None,
        "password": None,
    }
    fake = FakeSession(payloads, privilege=-1)

    projection = collect_aruba_rest_projection(
        ArubaRestTarget("192.168.11.10", "admin", "secret", "a" * 64),
        session_factory=lambda _: fake,
    )

    assert projection.controls["SW-01"] is True


def test_aruba_admin_name_does_not_override_explicit_non_admin_group() -> None:
    payloads = _secure_payloads()
    payloads["current_user"] = {
        "user_group": {"operators": "/rest/v10.13/system/user_groups/operators"}
    }
    fake = FakeSession(payloads, privilege=-1)

    with pytest.raises(ArubaRestCollectionError, match="INSUFFICIENT_PRIVILEGE"):
        collect_aruba_rest_projection(
            ArubaRestTarget("192.168.11.10", "admin", "secret", "a" * 64),
            session_factory=lambda _: fake,
        )
