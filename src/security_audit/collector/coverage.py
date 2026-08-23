"""IMP-031 Pack-to-Collector Probe and Adapter coverage verification."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Never, cast

from security_audit.analysis.package_validation import PackageValidationError, load_strict_json

from .allowlist import ProbeAllowlist


class CoverageContractError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    control_count: int
    native_probe_count: int
    standard_probe_count: int
    administrator_probe_count: int
    server_reference_probe_count: int
    allowed_host_adapters: tuple[str, ...]
    approval_status: str


def _reject(message: str) -> Never:
    raise CoverageContractError(message)


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject("IMP-031 coverage object is invalid.")
    return cast(Mapping[str, object], value)


def _array(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject("IMP-031 coverage array is invalid.")
    return cast(Sequence[object], value)


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        _reject("IMP-031 coverage string is invalid.")
    return value


def verify_imp031_coverage(
    *,
    pack_path: Path,
    allowlist_path: Path,
    coverage_policy_path: Path,
    adapter_catalog_path: Path,
) -> CoverageSummary:
    try:
        pack = _object(load_strict_json(pack_path.read_bytes()))
        policy = _object(load_strict_json(coverage_policy_path.read_bytes()))
        adapters = _object(load_strict_json(adapter_catalog_path.read_bytes()))
    except (OSError, PackageValidationError) as exc:
        raise CoverageContractError("IMP-031 coverage input is unavailable.") from exc
    allowlist = ProbeAllowlist.from_file(allowlist_path)
    if (
        pack.get("pack_profile") != "KISA-2026-PC-MVP"
        or pack.get("version") != "0.6.0"
        or pack.get("content_sha256")
        != _object(policy.get("pack_binding")).get("pack_content_sha256")
    ):
        _reject("IMP-031 Pack binding differs from the approved DRAFT source.")
    controls = _array(pack.get("controls"))
    expected_controls = tuple(f"PC-{number:02d}" for number in range(1, 19))
    actual_controls = tuple(
        _string(_object(control).get("control_id")) for control in controls
    )
    if actual_controls != expected_controls:
        _reject("IMP-031 Control coverage is not exactly PC-01~PC-18.")
    host_probe_controls: dict[str, set[str]] = {}
    server_references: set[str] = set()
    for raw_control in controls:
        control = _object(raw_control)
        control_id = _string(control.get("control_id"))
        for raw_requirement in _array(control.get("evidence_requirements")):
            requirement = _object(raw_requirement)
            for raw_probe_id in _array(requirement.get("probe_ids")):
                probe_id = _string(raw_probe_id)
                if probe_id.startswith("reference."):
                    server_references.add(probe_id)
                else:
                    host_probe_controls.setdefault(probe_id, set()).add(control_id)
    if set(allowlist.probe_ids) != set(host_probe_controls):
        _reject("IMP-031 native Probe allowlist does not cover the DRAFT Pack exactly.")
    for probe_id, controls_for_probe in host_probe_controls.items():
        contract = allowlist.get(probe_id)
        if contract is None or contract.control_ids != frozenset(controls_for_probe):
            _reject("IMP-031 Probe Control binding differs from the DRAFT Pack.")
    coverage = _object(policy.get("coverage"))
    expected_references = {
        _string(item)
        for item in _array(coverage.get("server_reference_probe_ids"))
    }
    standard = sum(
        allowlist.get(probe_id).required_privilege == "STANDARD_USER"  # type: ignore[union-attr]
        for probe_id in allowlist.probe_ids
    )
    administrator = sum(
        allowlist.get(probe_id).required_privilege == "ADMINISTRATOR"  # type: ignore[union-attr]
        for probe_id in allowlist.probe_ids
    )
    if (
        coverage.get("native_probe_count") != len(allowlist.probe_ids)
        or coverage.get("standard_probe_count") != standard
        or coverage.get("administrator_probe_count") != administrator
        or server_references != expected_references
    ):
        _reject("IMP-031 privilege or reference coverage count is invalid.")
    adapter_boundary = _object(policy.get("adapter_boundary"))
    if (
        adapters.get("catalog_id") != adapter_boundary.get("catalog_id")
        or adapters.get("version") != adapter_boundary.get("catalog_version")
        or adapters.get("content_sha256")
        != adapter_boundary.get("catalog_content_sha256")
        or _object(adapters.get("approval")).get("status")
        != adapter_boundary.get("approval_status")
    ):
        _reject("IMP-031 Adapter catalog binding is invalid.")
    allowed = tuple(
        _string(item)
        for item in _array(adapter_boundary.get("allowed_host_adapters"))
    )
    catalog_adapters = {
        f"{_string(adapter.get('adapter_id'))}@{_string(adapter.get('adapter_version'))}": adapter
        for raw_adapter in _array(adapters.get("adapters"))
        if (adapter := _object(raw_adapter))
    }
    for adapter_key in allowed:
        selected_adapter = catalog_adapters.get(adapter_key)
        if (
            selected_adapter is None
            or selected_adapter.get("synthetic_test_only") is not False
        ):
            _reject("IMP-031 host Adapter is missing or synthetic-only.")
    if adapter_boundary.get("synthetic_adapter_host_execution_forbidden") is not True:
        _reject("IMP-031 synthetic Adapter host boundary is weakened.")
    return CoverageSummary(
        control_count=len(controls),
        native_probe_count=len(allowlist.probe_ids),
        standard_probe_count=standard,
        administrator_probe_count=administrator,
        server_reference_probe_count=len(server_references),
        allowed_host_adapters=allowed,
        approval_status=_string(adapter_boundary.get("approval_status")),
    )
