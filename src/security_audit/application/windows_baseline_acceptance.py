"""IMP-036 de-identified current Windows development-host baseline."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from security_audit.collector.safety import (
    CollectorSafetyPolicy,
    WindowsSafetySnapshotter,
)

CORE_SERVICES = (
    "postgres",
    "redis",
    "aistor",
    "clamav",
    "api",
    "worker",
    "scheduler",
    "gateway",
)
BASELINE_SCRIPT_SHA256 = (
    "dce067e96e173769bd5d1e19789d8b098fbbac52252d384169ecb59f01ac80e0"
)


class BaselineReceiptError(RuntimeError):
    """Fail-closed IMP-036 acceptance error without host identifiers."""


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise BaselineReceiptError(f"Invalid {field}.")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise BaselineReceiptError(f"Invalid {field}.")
    return value


def _mapping(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise BaselineReceiptError(f"Invalid {field}.")
    return cast(Mapping[str, object], value)


def build_windows_baseline_receipt(
    *,
    observed_at_utc: str,
    operating_system: Mapping[str, object],
    token: Mapping[str, object],
    security_products: Sequence[Mapping[str, object]],
    collector: Mapping[str, object],
    docker_services: Sequence[Mapping[str, object]],
    snapshot_surfaces: Sequence[str],
    settings_before_after_equal: bool,
    settings_diff_count: int,
) -> dict[str, Any]:
    """Build the strict, display-safe receipt; reject incomplete safety evidence."""

    if (
        not observed_at_utc.endswith("Z")
        or len(observed_at_utc) > 32
        or settings_before_after_equal is not True
        or settings_diff_count != 0
    ):
        raise BaselineReceiptError("Windows settings safety evidence is invalid.")

    os_receipt = {
        "edition": _text(operating_system.get("edition"), "OS edition"),
        "display_version": _text(
            operating_system.get("display_version"), "OS display version"
        ),
        "build": _text(operating_system.get("build"), "OS build"),
        "architecture": _text(
            operating_system.get("architecture"), "OS architecture"
        ),
    }
    token_level = _text(token.get("level"), "token level")
    if token_level not in {"STANDARD_USER", "ADMINISTRATOR"}:
        raise BaselineReceiptError("Invalid token level.")
    token_receipt = {
        "level": token_level,
        "integrity_level": _text(
            token.get("integrity_level"), "token integrity level"
        ),
        "automatic_elevation": False,
    }

    product_receipts: list[dict[str, str]] = []
    for product in security_products:
        product_receipts.append(
            {
                "name": _text(product.get("name"), "security product name"),
                "state": _text(product.get("state"), "security product state"),
                "detail": _text(product.get("detail"), "security product detail"),
            }
        )

    collector_receipt = {
        "artifact": _text(collector.get("artifact"), "Collector artifact"),
        "self_check": _text(collector.get("self_check"), "Collector self-check"),
        "release_channel": _text(
            collector.get("release_channel"), "Collector release channel"
        ),
        "download_enabled": False,
        "production_release_ready": False,
    }
    if collector_receipt["self_check"] != "PASS":
        raise BaselineReceiptError("Collector executable self-check did not pass.")

    services: list[dict[str, object]] = []
    service_names: set[str] = set()
    for service in docker_services:
        name = _text(service.get("service"), "Docker Core service")
        if name in service_names:
            raise BaselineReceiptError("Docker Core service is duplicated.")
        service_names.add(name)
        services.append(
            {
                "service": name,
                "running": _boolean(service.get("running"), "Docker running state"),
                "healthy": _boolean(service.get("healthy"), "Docker health state"),
            }
        )
    if service_names != set(CORE_SERVICES) or not all(
        item["running"] is True and item["healthy"] is True for item in services
    ):
        raise BaselineReceiptError("Docker Core service set is not fully healthy.")
    services.sort(key=lambda item: CORE_SERVICES.index(cast(str, item["service"])))

    surfaces = tuple(snapshot_surfaces)
    if (
        len(surfaces) != len(set(surfaces))
        or any(not isinstance(item, str) or not item for item in surfaces)
    ):
        raise BaselineReceiptError("Invalid settings snapshot surface.")

    return {
        "imp": "IMP-036",
        "acceptance_status": "PASS",
        "observed_at_utc": observed_at_utc,
        "environment": {
            "kind": "CURRENT_WINDOWS_DEVELOPMENT_HOST",
            "clean_vm_verified": False,
            "vm_acceptance_deferred_to": "IMP-052",
            "operating_system": os_receipt,
        },
        "token": token_receipt,
        "security_products": product_receipts,
        "collector": collector_receipt,
        "docker_core": {
            "state": "READY",
            "expected_services": len(CORE_SERVICES),
            "running_services": len(services),
            "healthy_services": len(services),
            "services": services,
        },
        "settings_safety": {
            "snapshot_surfaces": list(surfaces),
            "before_after_equal": True,
            "settings_diff_count": 0,
            "raw_snapshot_values_disclosed": False,
            "snapshot_digests_disclosed": False,
        },
        "privacy": {
            "sid_disclosed": False,
            "computer_name_disclosed": False,
            "user_name_disclosed": False,
            "volume_identifiers_disclosed": False,
            "sensitive_values_disclosed": False,
        },
        "boundaries": {
            "read_only": True,
            "automatic_uac": False,
            "clean_vm_claimed": False,
            "draft_pack_only": True,
        },
        "official_finding_created": False,
        "portable_bundle_created": False,
        "next_imp": "IMP-037",
    }


def _docker_core_status(project_root: Path) -> list[dict[str, object]]:
    command = [
        "docker",
        "compose",
        "--project-directory",
        str(project_root),
        "-f",
        str(project_root / "deploy" / "compose" / "compose.yml"),
        "-f",
        str(project_root / "deploy" / "compose" / "compose.dev.yml"),
        "ps",
        "-a",
        "--format",
        "json",
    ]
    completed = subprocess.run(  # noqa: S603 - fixed Docker Compose command
        command,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0 or len(completed.stdout) > 256 * 1024:
        raise BaselineReceiptError("Docker Core status is unavailable.")
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BaselineReceiptError("Docker Core status is invalid.") from exc
    rows = raw if isinstance(raw, list) else [raw]
    by_service: dict[str, dict[str, object]] = {}
    for raw_row in rows:
        row = _mapping(raw_row, "Docker Core status row")
        service = row.get("Service")
        if not isinstance(service, str) or service not in CORE_SERVICES:
            continue
        state = str(row.get("State", "")).casefold()
        health = str(row.get("Health", "")).casefold()
        by_service[service] = {
            "service": service,
            "running": state == "running",
            "healthy": health == "healthy",
        }
    return [by_service[name] for name in CORE_SERVICES if name in by_service]


def _collector_status(project_root: Path) -> dict[str, object]:
    candidates = sorted(
        (project_root / "runtime" / "imp035-artifacts").glob(
            "acceptance-*/imp035-acceptance.json"
        ),
        reverse=True,
    )
    if not candidates:
        raise BaselineReceiptError("Collector acceptance record is unavailable.")
    acceptance = cast(
        dict[str, Any],
        json.loads(candidates[0].read_text(encoding="utf-8")),
    )
    artifact = candidates[0].parent / "SecAI-Collector-Windows-x64.exe"
    if not artifact.is_file():
        raise BaselineReceiptError("Collector executable is unavailable.")
    completed = subprocess.run(  # noqa: S603 - fixed accepted Collector artifact
        [str(artifact), "self-check"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0 or len(completed.stdout) > 64 * 1024:
        raise BaselineReceiptError("Collector executable self-check failed.")
    try:
        self_check = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BaselineReceiptError("Collector self-check output is invalid.") from exc
    artifact_info = _mapping(acceptance.get("artifact"), "Collector artifact")
    return {
        "artifact": _text(artifact_info.get("name"), "Collector artifact name"),
        "self_check": _text(self_check.get("status"), "Collector self-check"),
        "release_channel": _text(
            artifact_info.get("release_channel"), "Collector release channel"
        ),
    }


def _windows_baseline_facts(script_path: Path) -> Mapping[str, object]:
    try:
        digest = hashlib.sha256(script_path.read_bytes()).hexdigest()
    except OSError as exc:
        raise BaselineReceiptError("Windows baseline Probe is unavailable.") from exc
    if digest != BASELINE_SCRIPT_SHA256:
        raise BaselineReceiptError("Windows baseline Probe integrity check failed.")
    system_root = Path(str(__import__("os").environ.get("SystemRoot", "")))
    powershell = (
        system_root
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    ).resolve()
    if not powershell.is_file():
        raise BaselineReceiptError("Trusted Windows PowerShell is unavailable.")
    completed = subprocess.run(  # noqa: S603 - integrity-pinned fixed Probe
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script_path.resolve()),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode != 0 or len(completed.stdout) > 64 * 1024:
        raise BaselineReceiptError("Windows baseline Probe did not complete.")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BaselineReceiptError("Windows baseline Probe output is invalid.") from exc
    return _mapping(value, "Windows baseline facts")


def run_windows_baseline_acceptance(
    project_root: Path,
    *,
    docker_services: Sequence[Mapping[str, object]] | None = None,
) -> dict[str, Any]:
    """Collect only the standard baseline facts between two safe snapshots."""

    contracts = project_root / "collectors" / "one_shot" / "contracts"
    scripts = (
        project_root
        / "collectors"
        / "one_shot"
        / "probes"
        / "windows"
        / "powershell"
    )
    safety_policy = CollectorSafetyPolicy.from_file(
        contracts / "imp030_safety_policy.json"
    )
    snapshotter = WindowsSafetySnapshotter(
        scripts / "imp030_safety_snapshot.ps1",
        safety_policy,
    )
    before = snapshotter.capture()
    facts = _windows_baseline_facts(scripts / "imp036_baseline.ps1")
    after = snapshotter.capture()
    if before.snapshot_sha256 != after.snapshot_sha256:
        raise BaselineReceiptError("Windows settings changed during baseline collection.")

    raw_products = facts.get("security_products")
    if not isinstance(raw_products, Sequence):
        raise BaselineReceiptError("Security product baseline is unavailable.")
    products: list[dict[str, str]] = []
    for raw_product in raw_products:
        product = _mapping(raw_product, "security product")
        code = _text(product.get("detail_code"), "security detail code")
        if code == "REALTIME_PROTECTION_ENABLED":
            detail = "실시간 보호 사용"
        elif code == "REALTIME_PROTECTION_DISABLED":
            detail = "실시간 보호 사용 안 함"
        elif code.startswith("PROFILES:"):
            parts = code.split(":")
            if len(parts) != 3 or not all(part.isdecimal() for part in parts[1:]):
                raise BaselineReceiptError("Firewall profile summary is invalid.")
            detail = f"확인한 프로필 {parts[1]}개 중 {parts[2]}개 사용"
        elif code == "STATUS_UNAVAILABLE":
            detail = "현재 권한으로 상태 정보를 확인하지 못함"
        else:
            raise BaselineReceiptError("Security product detail code is invalid.")
        products.append(
            {
                "name": _text(product.get("name"), "security product name"),
                "state": _text(product.get("state"), "security product state"),
                "detail": detail,
            }
        )
    context = _mapping(facts.get("operating_system"), "operating system")
    token = _mapping(facts.get("token"), "token")
    return build_windows_baseline_receipt(
        observed_at_utc=_text(facts.get("observed_at_utc"), "observation time"),
        operating_system={
            "edition": context.get("edition"),
            "display_version": context.get("display_version"),
            "build": context.get("build"),
            "architecture": context.get("architecture"),
        },
        token=token,
        security_products=products,
        collector=_collector_status(project_root),
        docker_services=(
            docker_services
            if docker_services is not None
            else _docker_core_status(project_root)
        ),
        snapshot_surfaces=safety_policy.settings_snapshot.surfaces,
        settings_before_after_equal=True,
        settings_diff_count=0,
    )
