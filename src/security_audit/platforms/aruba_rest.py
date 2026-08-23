"""AOS-CX 10.13의 인증서 고정 REST GET 수집과 KISA N-01~N-38 판정."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import re
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from http.cookies import SimpleCookie
from typing import Protocol, cast
from urllib.parse import quote, unquote, urlencode

from security_audit.common.canonical_json import JsonValue, canonicalize_json

from .contracts import DeviceControlResult, PlatformContractError
from .kisa_network import KisaNetworkAssessmentProfile, evaluate_kisa_network_controls

_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|"
    r"\d{1,3}(?:\.\d{1,3}){3})$"
)
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")

_ENDPOINTS = {
    "api_versions": "/rest",
    "current_user": (
        "/rest/{version}/system/users/{username}?selector=configuration&depth=1"
    ),
    "system": "/rest/{version}/system?selector=configuration&depth=1",
    "system_status": "/rest/{version}/system?selector=status&depth=1",
    "mgmt_vrf": "/rest/{version}/system/vrfs/mgmt?selector=configuration&depth=1",
    "vrfs": "/rest/{version}/system/vrfs?selector=configuration&depth=2",
    "interfaces": "/rest/{version}/system/interfaces?selector=configuration&depth=2",
    "user_groups": "/rest/{version}/system/user_groups?selector=configuration&depth=3",
    "users": "/rest/{version}/system/users?selector=configuration&depth=2",
    "acls": "/rest/{version}/system/acls?selector=configuration&depth=3",
    "logging_filters": (
        "/rest/{version}/system/logging_filters?selector=configuration&depth=3"
    ),
    "snmpv3_users": (
        "/rest/{version}/system/snmpv3_users?selector=configuration&depth=2"
    ),
    "syslog_remotes": (
        "/rest/{version}/system/syslog_remotes?selector=configuration&depth=2"
    ),
    "ntp_associations": (
        "/rest/{version}/system/vrfs/mgmt/ntp_associations"
        "?selector=configuration&depth=2"
    ),
    "ntp_associations_default": (
        "/rest/{version}/system/vrfs/default/ntp_associations"
        "?selector=configuration&depth=2"
    ),
    "hot_patches": (
        "/rest/{version}/system/hot_patches?selector=configuration&depth=2"
    ),
    "event_logs": "/rest/{version}/logs/event?limit=1",
}

_TEXT_ENDPOINTS = {
    "running_config": "/rest/{version}/configs/running-config",
}


class ArubaRestCollectionError(PlatformContractError):
    """비밀값이나 요청 URL을 포함하지 않는 REST 수집 실패."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ArubaRestTarget:
    host: str
    username: str
    password: str = field(repr=False)
    certificate_sha256: str
    port: int = 443
    api_version: str = "v10.13"
    timeout_seconds: int = 15
    maximum_response_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        normalized_pin = self.certificate_sha256.strip().lower()
        object.__setattr__(self, "certificate_sha256", normalized_pin)
        if _HOST.fullmatch(self.host) is None:
            raise PlatformContractError("REST 대상 주소가 올바르지 않습니다.")
        if _USERNAME.fullmatch(self.username) is None:
            raise PlatformContractError("REST 사용자 이름이 올바르지 않습니다.")
        if not self.password or len(self.password) > 512:
            raise PlatformContractError("REST 자격증명이 올바르지 않습니다.")
        if _SHA256.fullmatch(normalized_pin) is None:
            raise PlatformContractError("REST 인증서 지문이 올바르지 않습니다.")
        if not 1 <= self.port <= 65_535:
            raise PlatformContractError("REST 포트가 올바르지 않습니다.")
        if self.api_version != "v10.13":
            raise PlatformContractError("승인되지 않은 AOS-CX REST API 버전입니다.")
        if not 1 <= self.timeout_seconds <= 60:
            raise PlatformContractError("REST 제한 시간이 올바르지 않습니다.")
        if not 4_096 <= self.maximum_response_bytes <= 4_194_304:
            raise PlatformContractError("REST 응답 크기 제한이 올바르지 않습니다.")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: ArubaRestTarget) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(
            target.host,
            target.port,
            timeout=target.timeout_seconds,
            context=context,
        )
        self._certificate_sha256 = target.certificate_sha256

    def connect(self) -> None:
        super().connect()
        if self.sock is None:
            raise ArubaRestCollectionError("TLS_CONNECTION_FAILED")
        certificate = self.sock.getpeercert(binary_form=True)
        if not isinstance(certificate, bytes):
            self.close()
            raise ArubaRestCollectionError("TLS_CERTIFICATE_MISSING")
        actual = hashlib.sha256(certificate).hexdigest()
        if not hmac.compare_digest(actual, self._certificate_sha256):
            self.close()
            raise ArubaRestCollectionError("CERTIFICATE_MISMATCH")


class ArubaRestSessionProtocol(Protocol):
    def __enter__(self) -> ArubaRestSessionProtocol: ...

    def __exit__(self, *args: object) -> None: ...

    def login(self) -> int: ...

    def get_json(self, endpoint_id: str) -> object: ...

    def get_text(self, endpoint_id: str) -> str: ...

    def logout(self) -> None: ...


class ArubaRestSession:
    """공식 login/logout POST 외에는 고정된 GET만 허용하는 짧은 세션."""

    def __init__(self, target: ArubaRestTarget) -> None:
        self._target = target
        self._connection = _PinnedHTTPSConnection(target)
        self._cookies: dict[str, str] = {}
        self._csrf_token = ""
        self._logged_in = False

    def __enter__(self) -> ArubaRestSession:
        return self

    def __exit__(self, *args: object) -> None:
        if self._logged_in:
            try:
                self.logout()
            except ArubaRestCollectionError:
                pass
        self._connection.close()

    def _read_response(self, response: http.client.HTTPResponse) -> bytes:
        body = response.read(self._target.maximum_response_bytes + 1)
        if len(body) > self._target.maximum_response_bytes:
            raise ArubaRestCollectionError("OUTPUT_LIMIT_EXCEEDED")
        return body

    def _request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, Mapping[str, str], bytes, list[tuple[str, str]]]:
        if method not in {"GET", "POST"}:
            raise ArubaRestCollectionError("METHOD_NOT_ALLOWED")
        try:
            self._connection.request(method, path, body=b"", headers=dict(headers or {}))
            response = self._connection.getresponse()
            raw_headers = response.getheaders()
            body = self._read_response(response)
            normalized_headers = {key.casefold(): value for key, value in raw_headers}
            return response.status, normalized_headers, body, raw_headers
        except ArubaRestCollectionError:
            raise
        except TimeoutError as exc:
            raise ArubaRestCollectionError("TIMEOUT") from exc
        except ssl.SSLError as exc:
            raise ArubaRestCollectionError("TLS_CONNECTION_FAILED") from exc
        except (OSError, http.client.HTTPException) as exc:
            raise ArubaRestCollectionError("CONNECTION_FAILED") from exc

    def _cookie_header(self) -> str:
        return "; ".join(f"{key}={value}" for key, value in sorted(self._cookies.items()))

    @staticmethod
    def _privilege_from_user_cookie(value: str) -> int:
        try:
            normalized = unquote(value)
            padded = normalized + "=" * (-len(normalized) % 4)
            decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
            payload = json.loads(decoded)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise ArubaRestCollectionError("INVALID_AUTH_COOKIE_ENCODING") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("level"), int):
            raise ArubaRestCollectionError("INVALID_AUTH_COOKIE_FIELDS")
        return cast(int, payload["level"])

    def login(self) -> int:
        query = urlencode({"username": self._target.username, "password": self._target.password})
        path = f"/rest/{self._target.api_version}/login?{query}"
        status, headers, _, raw_headers = self._request(
            "POST",
            path,
            headers={"accept": "application/json", "x-use-csrf-token": "true"},
        )
        if status == 401:
            raise ArubaRestCollectionError("AUTHENTICATION_FAILED")
        if status != 200:
            raise ArubaRestCollectionError("LOGIN_FAILED")
        for name, value in raw_headers:
            if name.casefold() != "set-cookie":
                continue
            parsed = SimpleCookie()
            parsed.load(value)
            for key, morsel in parsed.items():
                self._cookies[key] = morsel.value
        self._csrf_token = headers.get("x-csrf-token", "")
        if "id" not in self._cookies:
            raise ArubaRestCollectionError("INVALID_AUTH_RESPONSE")
        self._logged_in = True
        user_cookie = self._cookies.get("user")
        return self._privilege_from_user_cookie(user_cookie) if user_cookie else -1

    def get_json(self, endpoint_id: str) -> object:
        path_template = _ENDPOINTS.get(endpoint_id)
        if path_template is None:
            raise ArubaRestCollectionError("ENDPOINT_NOT_ALLOWED")
        if not self._logged_in:
            raise ArubaRestCollectionError("AUTHENTICATION_REQUIRED")
        path = path_template.format(
            version=self._target.api_version,
            username=quote(self._target.username, safe=""),
        )
        headers = {"accept": "application/json", "cookie": self._cookie_header()}
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token
        status, response_headers, body, _ = self._request("GET", path, headers=headers)
        if status == 401:
            raise ArubaRestCollectionError("AUTHENTICATION_FAILED")
        if status == 403:
            raise ArubaRestCollectionError("INSUFFICIENT_PRIVILEGE")
        if status != 200:
            raise ArubaRestCollectionError("GET_FAILED")
        content_type = response_headers.get("content-type", "")
        if "application/json" not in content_type.casefold():
            raise ArubaRestCollectionError("INVALID_CONTENT_TYPE")
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArubaRestCollectionError("INVALID_JSON") from exc

    def get_text(self, endpoint_id: str) -> str:
        path_template = _TEXT_ENDPOINTS.get(endpoint_id)
        if path_template is None:
            raise ArubaRestCollectionError("ENDPOINT_NOT_ALLOWED")
        if not self._logged_in:
            raise ArubaRestCollectionError("AUTHENTICATION_REQUIRED")
        path = path_template.format(version=self._target.api_version)
        headers = {
            "accept": "text/plain",
            "cookie": self._cookie_header(),
        }
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token
        status, response_headers, body, _ = self._request("GET", path, headers=headers)
        if status == 401:
            raise ArubaRestCollectionError("AUTHENTICATION_FAILED")
        if status == 403:
            raise ArubaRestCollectionError("INSUFFICIENT_PRIVILEGE")
        if status != 200:
            raise ArubaRestCollectionError("GET_FAILED")
        content_type = response_headers.get("content-type", "")
        if "text/plain" not in content_type.casefold():
            raise ArubaRestCollectionError("INVALID_CONTENT_TYPE")
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArubaRestCollectionError("INVALID_TEXT_ENCODING") from exc

    def logout(self) -> None:
        if not self._logged_in:
            return
        headers = {"cookie": self._cookie_header()}
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token
        path = f"/rest/{self._target.api_version}/logout"
        status, _, _, _ = self._request("POST", path, headers=headers)
        self._logged_in = False
        self._cookies.clear()
        self._csrf_token = ""
        if status != 200:
            raise ArubaRestCollectionError("LOGOUT_FAILED")


@dataclass(frozen=True, slots=True)
class ArubaRestProjection:
    api_version: str
    controls: dict[str, bool]
    canonical_bytes: bytes = field(repr=False)
    observed_summaries: dict[str, str] = field(default_factory=dict)
    facts: dict[str, JsonValue] = field(default_factory=dict)


def _require_object(value: object, endpoint_id: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ArubaRestCollectionError(f"INVALID_RESPONSE_{endpoint_id.upper()}")
    return cast(dict[str, object], value)


def _configured_rows(value: object, endpoint_id: str) -> tuple[dict[str, object], ...]:
    payload = _require_object(value, endpoint_id)
    rows: list[dict[str, object]] = []
    for row in payload.values():
        if isinstance(row, dict) and all(isinstance(key, str) for key in row):
            rows.append(cast(dict[str, object], row))
    return tuple(rows)


def _bounded_timeout(value: object, maximum: int = 15) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= maximum


def _configured_collection_count(value: object) -> int:
    if isinstance(value, (dict, list, tuple)):
        return len(value)
    return 0


def _nested_feature_enabled(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if not isinstance(value, dict):
        return False
    for key in ("enable", "enabled"):
        nested = value.get(key)
        if isinstance(nested, bool):
            return nested
    return bool(value)


def _interface_name(row: Mapping[str, object]) -> str:
    value = row.get("name")
    return value if isinstance(value, str) else ""


def _interface_proxy_arp_enabled(row: Mapping[str, object]) -> bool:
    return any(
        row.get(key) is True
        for key in (
            "ip_proxy_arp",
            "proxy_arp_enable",
            "local_proxy_arp",
            "ip_local_proxy_arp",
        )
    )


def _reference_name(value: object) -> str:
    if isinstance(value, str):
        return value.rstrip("/").rsplit("/", maxsplit=1)[-1].casefold()
    if isinstance(value, dict):
        for key, nested in value.items():
            if isinstance(key, str) and key:
                return key.casefold()
            if isinstance(nested, str):
                return nested.rstrip("/").rsplit("/", maxsplit=1)[-1].casefold()
    return ""


def _login_banner_facts(running_config: str) -> tuple[bool, bool]:
    """배너 원문은 저장하지 않고 설정 여부와 명백한 시스템 정보 노출만 남깁니다."""

    banner_match = re.search(
        r"(?im)^\s*banner\s+(?:motd|exec)\s+(?P<delimiter>\S)(?P<body>.*?)"
        r"^(?P=delimiter)\s*$",
        running_config,
        flags=re.DOTALL | re.MULTILINE | re.IGNORECASE,
    )
    if banner_match is None:
        return False, False
    body = banner_match.group("body")[:4_096]
    discloses_system_information = any(
        re.search(pattern, body, flags=re.IGNORECASE) is not None
        for pattern in (
            r"\b(?:AOS-CX|ArubaOS|serial(?:\s+number)?|hostname|firmware)\b",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b",
            r"\b\d{2}\.\d{2}\.\d{4}\b",
        )
    )
    return True, discloses_system_information


def _event_timestamp_present(value: object) -> bool:
    stack: list[object] = [value]
    visited = 0
    while stack and visited < 10_000:
        current = stack.pop()
        visited += 1
        if isinstance(current, dict):
            for key, nested in current.items():
                if (
                    isinstance(key, str)
                    and "timestamp" in key.casefold()
                    and isinstance(nested, (str, int, float))
                    and not isinstance(nested, bool)
                    and bool(str(nested).strip())
                ):
                    return True
                stack.append(nested)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return False


def _build_projection(
    payloads: Mapping[str, object],
    privilege: int,
    authenticated_username: str,
) -> ArubaRestProjection:
    versions = _require_object(payloads["api_versions"], "api_versions")
    latest = _require_object(versions.get("latest"), "api_versions_latest")
    api_version = latest.get("version")
    if api_version != "v10.13":
        raise ArubaRestCollectionError("UNSUPPORTED_API_VERSION")

    current_user = _require_object(payloads["current_user"], "current_user")
    system = _require_object(payloads["system"], "system")
    system_status = _require_object(payloads["system_status"], "system_status")
    mgmt_vrf = _require_object(payloads["mgmt_vrf"], "mgmt_vrf")
    vrf_rows = _configured_rows(payloads["vrfs"], "vrfs")
    interface_rows = _configured_rows(payloads["interfaces"], "interfaces")
    user_group_rows = _configured_rows(payloads["user_groups"], "user_groups")
    user_rows = _configured_rows(payloads["users"], "users")
    acl_rows = _configured_rows(payloads["acls"], "acls")
    logging_filter_rows = _configured_rows(payloads["logging_filters"], "logging_filters")
    cli_session = _require_object(system.get("cli_session", {}), "cli_session")
    http_session = _require_object(system.get("http_session", {}), "http_session")
    ntp_config = _require_object(system.get("ntp_config", {}), "ntp_config")
    snmp_rows = _configured_rows(payloads["snmpv3_users"], "snmpv3_users")
    syslog_rows = _configured_rows(payloads["syslog_remotes"], "syslog_remotes")
    ntp_rows = _configured_rows(payloads["ntp_associations"], "ntp_associations")
    ntp_default_rows = _configured_rows(
        payloads["ntp_associations_default"], "ntp_associations_default"
    )
    hot_patch_rows = _configured_rows(payloads["hot_patches"], "hot_patches")
    running_config = payloads.get("running_config")
    if not isinstance(running_config, str):
        raise ArubaRestCollectionError("INVALID_RESPONSE_RUNNING_CONFIG")
    password_complexity = _require_object(
        system.get("password_complexity", {}), "password_complexity"
    )

    secure_snmp_user_count = sum(
        row.get("auth_protocol") in {"sha256", "sha384", "sha512"}
        and row.get("priv_protocol") in {"aes256"}
        and row.get("access_level") in {None, "ro"}
        for row in snmp_rows
    )
    snmp_user_count = len(snmp_rows)
    secure_snmp_user = secure_snmp_user_count > 0
    active_syslog_count = sum(
        isinstance(row.get("remote_host"), str)
        and bool(str(row["remote_host"]).strip())
        and row.get("disable") is not True
        for row in syslog_rows
    )
    active_syslog = active_syslog_count > 0
    auditable_syslog_count = sum(
        isinstance(row.get("remote_host"), str)
        and bool(str(row["remote_host"]).strip())
        and row.get("disable") is not True
        and row.get("include_auditable_events") is True
        for row in syslog_rows
    )
    ntp_client_enabled = (
        ntp_config.get("enable") is True or ntp_config.get("enabled") is True
    )
    configured_ntp = bool(ntp_rows or ntp_default_rows) and ntp_client_enabled
    raw_ntp_vrf = system.get("ntp_config_vrf", "")
    if isinstance(raw_ntp_vrf, dict):
        ntp_uses_mgmt = "mgmt" in raw_ntp_vrf or any(
            isinstance(value, str) and value.rstrip("/").endswith("/mgmt")
            for value in raw_ntp_vrf.values()
        )
    else:
        ntp_vrf = str(raw_ntp_vrf).rstrip("/")
        ntp_uses_mgmt = not ntp_vrf or ntp_vrf == "mgmt" or ntp_vrf.endswith("/mgmt")
    if not ntp_uses_mgmt:
        configured_ntp = False
    ntp_server_count = (
        len(ntp_rows) + len(ntp_default_rows) if ntp_uses_mgmt else 0
    )
    telnet_enabled_vrf_count = sum(
        row.get("telnet_server_enable") is True for row in vrf_rows
    )
    snmp_enabled_vrf_count = sum(row.get("snmp_enable") is True for row in vrf_rows)
    snmp_non_management_vrf_count = sum(
        row.get("snmp_enable") is True
        and row.get("type") != "management"
        and row.get("name") != "mgmt"
        for row in vrf_rows
    )
    raw_allowlist = system.get("ssh_server_allowlist_ips", ())
    ssh_allowlist_count = (
        len(raw_allowlist) if isinstance(raw_allowlist, (list, tuple, dict)) else 0
    )
    raw_communities = system.get("snmp_communities", {})
    snmp_community_count = len(raw_communities) if isinstance(raw_communities, dict) else 0
    raw_community_acls = system.get("snmp_community_acls", {})
    snmp_community_acl_count = (
        len(raw_community_acls) if isinstance(raw_community_acls, dict) else 0
    )
    https_enabled_vrf_count = sum(
        _nested_feature_enabled(row.get("https_server")) for row in vrf_rows
    )
    https_non_management_vrf_count = sum(
        _nested_feature_enabled(row.get("https_server"))
        and row.get("type") != "management"
        and row.get("name") != "mgmt"
        for row in vrf_rows
    )
    dns_server_count = _configured_collection_count(system.get("dns_servers")) + sum(
        _configured_collection_count(row.get("dns_name_servers")) for row in vrf_rows
    )
    routed_interface_rows = tuple(row for row in interface_rows if row.get("routing") is True)
    source_lockdown_count = sum(
        row.get("ipv4_source_lockdown_enable") is True
        or row.get("ipv6_source_lockdown_enable") is True
        for row in routed_interface_rows
    )
    physical_interface_rows = tuple(
        row
        for row in interface_rows
        if re.fullmatch(r"\d+/\d+/\d+(?::\d+)?", _interface_name(row)) is not None
    )
    active_physical_interface_count = sum(
        str(row.get("admin", "")).casefold() not in {"down", "disabled"}
        for row in physical_interface_rows
    )
    active_undocumented_interface_count = sum(
        str(row.get("admin", "")).casefold() not in {"down", "disabled"}
        and not (
            isinstance(row.get("description"), str)
            and bool(str(row["description"]).strip())
        )
        for row in physical_interface_rows
    )
    directed_broadcast_enabled_count = sum(
        row.get("ip_directed_broadcast") is True for row in interface_rows
    )
    proxy_arp_enabled_count = sum(
        _interface_proxy_arp_enabled(row) for row in interface_rows
    )
    role_names = {
        str(row.get("name", "")).casefold()
        for row in user_group_rows
        if isinstance(row.get("name"), str)
    }
    builtin_role_count = len(role_names & {"administrators", "operators", "auditors"})
    rbac_rule_count = sum(
        _configured_collection_count(row.get("rbac_rules")) for row in user_group_rows
    )
    user_group_names = tuple(
        (
            "administrators"
            if _reference_name(row.get("user_group", row.get("group"))) == ""
            and row.get("user_name") == "admin"
            else _reference_name(row.get("user_group", row.get("group")))
        )
        for row in user_rows
    )
    user_count = len(user_rows)
    administrator_user_count = sum(
        group_name == "administrators" for group_name in user_group_names
    )
    non_administrator_user_count = sum(
        bool(group_name) and group_name != "administrators"
        for group_name in user_group_names
    )
    unknown_role_user_count = sum(not group_name for group_name in user_group_names)
    login_banner_configured, login_banner_discloses_system_information = (
        _login_banner_facts(running_config)
    )
    software_version = next(
        (
            value
            for key in (
                "software_version",
                "platform_version",
                "version",
                "system_description",
            )
            if isinstance((value := system_status.get(key)), str) and value.strip()
        ),
        "확인되지 않음",
    )
    event_timestamp_present = _event_timestamp_present(payloads["event_logs"])
    effective_copp_policy = bool(
        system.get("global_user_copp_policy")
        or system.get("hw_default_copp_policy")
        or system_status.get("global_user_copp_policy")
        or system_status.get("hw_default_copp_policy")
    )

    raw_user_group = current_user.get("user_group", current_user.get("group"))
    user_group_is_missing = raw_user_group in (None, "", {})
    if isinstance(raw_user_group, dict):
        user_group_is_administrator = "administrators" in raw_user_group or any(
            isinstance(value, str) and value.rstrip("/").endswith("/administrators")
            for value in raw_user_group.values()
        )
    else:
        user_group_is_administrator = str(raw_user_group).rstrip("/").endswith(
            "/administrators"
        )
    administrator_authenticated = privilege == 15 or (
        privilege == -1
        and (
            user_group_is_administrator
            # 10.13.1170은 내장 admin의 user_group을 REST 응답에서 생략합니다.
            or (authenticated_username == "admin" and user_group_is_missing)
        )
    )
    controls = {
        "SW-01": administrator_authenticated,
        "SW-02": mgmt_vrf.get("ssh_enable") is True,
        "SW-03": system.get("enable_snmpv3_only") is True and secure_snmp_user,
        "SW-04": active_syslog,
        "SW-05": configured_ntp,
        "SW-06": _bounded_timeout(cli_session.get("timeout"))
        and _bounded_timeout(http_session.get("timeout")),
    }
    cli_timeout = cli_session.get("timeout")
    http_timeout = http_session.get("timeout")

    def timeout_label(value: object) -> str:
        if isinstance(value, int) and not isinstance(value, bool):
            return f"{value}분"
        return "확인되지 않음"

    observed_summaries = {
        "SW-01": (
            "REST 관리자 권한 인증: 성공"
            if administrator_authenticated
            else "REST 관리자 권한 인증: 실패"
        ),
        "SW-02": (
            "관리 VRF SSH 서버: 활성화"
            if mgmt_vrf.get("ssh_enable") is True
            else "관리 VRF SSH 서버: 비활성화"
        ),
        "SW-03": (
            "SNMPv3 전용 모드: "
            f"{'활성화' if system.get('enable_snmpv3_only') is True else '비활성화'}, "
            f"인증·암호화 사용자: {secure_snmp_user_count}개"
        ),
        "SW-04": f"활성 원격 syslog 서버: {active_syslog_count}개",
        "SW-05": (
            "NTP client: "
            f"{'활성화' if ntp_client_enabled else '비활성화'}, "
            f"관리 VRF NTP 서버: {ntp_server_count}개"
        ),
        "SW-06": (
            f"CLI 유휴 제한: {timeout_label(cli_timeout)}, "
            f"HTTPS 유휴 제한: {timeout_label(http_timeout)}"
        ),
    }

    def configured_bool(container: Mapping[str, object], key: str) -> JsonValue:
        value = container.get(key)
        return value if isinstance(value, bool) else None

    # AOS-CX 10.13은 password complexity가 기본 비활성이고, 기본값은 구성 selector에서
    # 생략할 수 있습니다. 객체가 없거나 enable 키가 없으면 비활성으로 판정합니다.
    complexity_enabled: JsonValue = False
    for complexity_key in ("enable", "enabled"):
        complexity_value = password_complexity.get(complexity_key)
        if isinstance(complexity_value, bool):
            complexity_enabled = complexity_value
            break
    facts: dict[str, JsonValue] = {
        "auth.admin_password_set": administrator_authenticated,
        "identity.password_complexity_enabled": complexity_enabled,
        # AOS-CX v10.13은 구성 조회에서 평문 비밀번호를 반환하지 않고 보호 형식으로 저장합니다.
        "identity.password_storage_encrypted": True,
        "identity.builtin_role_count": builtin_role_count,
        "identity.rbac_rule_count": rbac_rule_count,
        "identity.user_count": user_count,
        "identity.administrator_user_count": administrator_user_count,
        "identity.non_administrator_user_count": non_administrator_user_count,
        "identity.unknown_role_user_count": unknown_role_user_count,
        "identity.ssh_maximum_authentication_attempts": cast(
            JsonValue, system.get("ssh_maximum_authentication_attempts")
        ),
        "management.ssh_allowlist_enabled": configured_bool(
            system, "ssh_server_allowlist_enable"
        ),
        "management.ssh_allowlist_count": ssh_allowlist_count,
        "management.cli_timeout_minutes": cast(JsonValue, cli_timeout),
        "management.web_timeout_minutes": cast(JsonValue, http_timeout),
        "management.mgmt_ssh_enabled": configured_bool(mgmt_vrf, "ssh_enable"),
        "management.telnet_enabled_vrf_count": telnet_enabled_vrf_count,
        "management.usb_auxiliary_disabled": system.get("usb_disable") is True,
        "management.bluetooth_disabled": system.get("bluetooth_mgmt_disable") is True,
        "management.login_banner_configured": login_banner_configured,
        "management.login_banner_discloses_system_information": (
            login_banner_discloses_system_information
        ),
        "management.https_enabled_vrf_count": https_enabled_vrf_count,
        "management.https_non_management_vrf_count": https_non_management_vrf_count,
        "logging.remote_server_count": active_syslog_count,
        "logging.auditable_remote_server_count": auditable_syslog_count,
        "logging.filter_count": len(logging_filter_rows),
        "logging.persistent_storage_configured": bool(
            system.get("logging_persistent_storage")
        ),
        "logging.notification_threshold_configured": bool(
            system.get("log_notification_threshold")
        ),
        "logging.event_timestamp_present": event_timestamp_present,
        "time.ntp_client_enabled": ntp_client_enabled,
        "time.ntp_server_count": ntp_server_count,
        "snmp.enabled_vrf_count": snmp_enabled_vrf_count,
        "snmp.v3_only": system.get("enable_snmpv3_only") is True,
        "snmp.community_count": snmp_community_count,
        "snmp.community_acl_count": snmp_community_acl_count,
        "snmp.user_count": snmp_user_count,
        "snmp.secure_read_only_user_count": secure_snmp_user_count,
        "snmp.non_management_vrf_count": snmp_non_management_vrf_count,
        "discovery.cdp_mode": cast(JsonValue, system.get("cdp_mode")),
        "network.icmp_unreachable_disabled": configured_bool(
            system, "icmp_unreachable_disable"
        ),
        "network.icmp_redirect_disabled": configured_bool(
            system, "icmp_redirect_disable"
        ),
        "network.routed_interface_count": len(routed_interface_rows),
        "network.source_lockdown_interface_count": source_lockdown_count,
        "network.physical_interface_count": len(physical_interface_rows),
        "network.active_physical_interface_count": active_physical_interface_count,
        "network.active_undocumented_interface_count": active_undocumented_interface_count,
        "network.directed_broadcast_enabled_count": directed_broadcast_enabled_count,
        "network.proxy_arp_enabled_count": proxy_arp_enabled_count,
        "network.dns_server_count": dns_server_count,
        "network.acl_count": len(acl_rows),
        "network.copp_policy_configured": bool(system.get("global_user_copp_policy")),
        "network.copp_effective_policy": effective_copp_policy,
        "platform.software_version": software_version,
        "platform.hot_patch_count": len(hot_patch_rows),
        "platform.family": "AOS-CX",
    }
    canonical: dict[str, JsonValue] = {
        "schema_version": "secai.aruba-aos-cx.rest-projection.v5",
        "api_version": "v10.13",
        "controls": cast(JsonValue, controls),
        "observed_summaries": cast(JsonValue, observed_summaries),
        "facts": facts,
        "redaction_applied": True,
        "raw_configuration_included": False,
    }
    return ArubaRestProjection(
        api_version="v10.13",
        controls=controls,
        canonical_bytes=canonicalize_json(canonical),
        observed_summaries=observed_summaries,
        facts=facts,
    )


SessionFactory = Callable[[ArubaRestTarget], ArubaRestSessionProtocol]


def collect_aruba_rest_projection(
    target: ArubaRestTarget,
    *,
    session_factory: SessionFactory = ArubaRestSession,
) -> ArubaRestProjection:
    """고정 GET 응답을 즉시 비식별 N-01~N-38 projection으로 축소합니다."""

    with session_factory(target) as session:
        privilege = session.login()
        if privilege not in {-1, 15}:
            raise ArubaRestCollectionError("INSUFFICIENT_PRIVILEGE")
        payloads = {endpoint_id: session.get_json(endpoint_id) for endpoint_id in _ENDPOINTS}
        payloads.update(
            {
                endpoint_id: session.get_text(endpoint_id)
                for endpoint_id in _TEXT_ENDPOINTS
            }
        )
        session.logout()
    projection = _build_projection(payloads, privilege, target.username)
    if not projection.controls["SW-01"]:
        raise ArubaRestCollectionError("INSUFFICIENT_PRIVILEGE")
    return projection


def evaluate_aruba_rest_baseline(
    projection: ArubaRestProjection,
    *,
    captured_at: datetime,
    criteria_profile: KisaNetworkAssessmentProfile | None = None,
) -> tuple[DeviceControlResult, ...]:
    """비식별 REST projection에 결정론적 KISA N-01~N-38 규칙을 적용합니다."""

    if not isinstance(captured_at, datetime):
        raise PlatformContractError("REST 증적 시각이 올바르지 않습니다.")
    return evaluate_kisa_network_controls(
        projection.facts,
        canonical_bytes=projection.canonical_bytes,
        captured_at=captured_at,
        criteria_profile=criteria_profile,
    )
