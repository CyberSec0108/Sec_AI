"""IMP-037 de-identified PC-01~18 host collection acceptance."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from security_audit.application.component_vulnerability_check import (
    validate_windows_component_inventory,
)
from security_audit.application.current_host_regression import ProbeObservation
from security_audit.collector import (
    ProbeAllowlist,
    SafetySnapshot,
    VerifiedExecutionPlan,
    VerifiedProbeRequest,
    WindowsCollectionCode,
    WindowsCollectionError,
    WindowsExecutionContext,
    WindowsReadOnlyCollector,
    WindowsSafetySnapshotter,
)
from security_audit.collector.expanded import (
    ADMINISTRATOR_PROBES,
    STANDARD_NON_STORAGE_PROBES,
    ExpandedProbeResult,
    ExpandedWindowsCollector,
)
from security_audit.collector.safety import CollectorSafetyPolicy
from security_audit.collector.vulnerability_inventory import (
    WindowsVulnerabilityInventoryCollector,
    WindowsVulnerabilityInventoryError,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256

STORAGE_PROBES = (
    "win.storage.disks",
    "win.storage.partitions",
    "win.storage.volumes",
)
STANDARD_PROBES = (*STANDARD_NON_STORAGE_PROBES, *STORAGE_PROBES)
ALL_PROBES = (*STANDARD_PROBES, *ADMINISTRATOR_PROBES)
_STATUSES = frozenset({"COLLECTED", "ERROR", "UNSUPPORTED"})
_ERROR_CODES = frozenset(
    {
        "NONE",
        "PERMISSION_DENIED",
        "SOURCE_UNAVAILABLE",
        "ADAPTER_UNSUPPORTED",
        "QUERY_FAILED",
    }
)
_VULNERABILITY_COMPONENT_TYPES = (
    "WINDOWS_PROGRAM",
    "WINDOWS_APPX",
    "WINDOWS_KB",
    "PYTHON_PACKAGE",
    "NODE_PACKAGE",
    "JAVA_PACKAGE",
)


class HostCollectionReceiptError(RuntimeError):
    """Fail-closed IMP-037 receipt error."""


class HostCollectionCancelled(RuntimeError):
    """IMP-041 cooperative cancellation at a safe collection boundary."""


type CollectionProgressCallback = Callable[[str, int, str], None]
type CollectionCancelCheck = Callable[[], bool]


def _ignore_progress(_: str, __: int, ___: str) -> None:
    return


def _never_cancel() -> bool:
    return False


def _checkpoint(
    progress_callback: CollectionProgressCallback,
    cancel_check: CollectionCancelCheck,
    *,
    step: str,
    percent: int,
    message: str,
) -> None:
    if cancel_check():
        raise HostCollectionCancelled
    progress_callback(step, percent, message)


def _verify_settings_unchanged(
    snapshotter: WindowsSafetySnapshotter,
    before: SafetySnapshot,
) -> None:
    after = snapshotter.capture()
    if before.snapshot_sha256 != after.snapshot_sha256:
        raise HostCollectionReceiptError(
            "Windows settings changed during standard collection."
        )


def _plan(
    allowlist: ProbeAllowlist,
    probe_ids: tuple[str, ...],
    *,
    suffix: str,
) -> VerifiedExecutionPlan:
    probes: list[VerifiedProbeRequest] = []
    for probe_id in probe_ids:
        contract = allowlist.get(probe_id)
        if contract is None:
            raise HostCollectionReceiptError("A fixed IMP-037 Probe is unavailable.")
        probes.append(
            VerifiedProbeRequest(
                probe_id=contract.probe_id,
                probe_version=contract.probe_version,
                control_ids=tuple(sorted(contract.control_ids)),
                required_privilege=contract.required_privilege,
                timeout_seconds=contract.max_timeout_seconds,
                max_output_bytes=contract.max_output_bytes,
                parameters=MappingProxyType(dict(contract.parameters)),
            )
        )
    return VerifiedExecutionPlan(
        manifest_id=f"37000000-0000-4000-8000-0000000000{suffix}1",
        manifest_sha256="3" * 64,
        job_id=f"37000000-0000-4000-8000-0000000000{suffix}2",
        asset_id=f"37000000-0000-4000-8000-0000000000{suffix}3",
        nonce=f"SU1QLTAzNy1ob3N0LWNvbGxlY3Rpb24t{suffix}",
        verified_at=datetime.now(UTC),
        probes=tuple(probes),
    )


def _paths(project_root: Path) -> tuple[Path, Path, Path]:
    contracts = project_root / "collectors" / "one_shot" / "contracts"
    scripts = (
        project_root
        / "collectors"
        / "one_shot"
        / "probes"
        / "windows"
        / "powershell"
    )
    return (
        contracts,
        scripts,
        contracts / "imp031_probe_allowlist.json",
    )


def _expanded_summary(
    result: ExpandedProbeResult,
    *,
    privilege: str,
    collected_at_utc: str,
) -> dict[str, object]:
    normalized_sha256 = canonical_sha256(
        cast(JsonValue, [dict(item) for item in result.records])
    )
    return {
        "probe_id": result.probe_id,
        "control_ids": list(result.control_ids),
        "privilege": privilege,
        "collection_status": result.collection_status,
        "error_code": result.error_code,
        "record_count": len(result.records),
        "collected_at_utc": collected_at_utc,
        "normalized_records_sha256": normalized_sha256,
        "raw_evidence_available": False,
    }


def _report_completed_controls(
    progress_callback: CollectionProgressCallback,
    control_ids: Sequence[str],
    *,
    start_percent: int,
    end_percent: int,
) -> None:
    unique_control_ids = sorted(set(control_ids))
    if not unique_control_ids:
        return
    percent_span = max(0, end_percent - start_percent)
    for index, control_id in enumerate(unique_control_ids, start=1):
        percent = start_percent + (percent_span * index // len(unique_control_ids))
        progress_callback(
            f"CONTROL_{control_id.replace('-', '_')}",
            percent,
            f"{control_id}에 필요한 Windows 설정을 확인했습니다.",
        )


def _base_vulnerability_inventory(
    expanded_context: WindowsExecutionContext,
) -> dict[str, object]:
    return {
        "os_name": f"Windows {expanded_context.os_version}",
        "display_version": expanded_context.display_version,
        "build_number": expanded_context.build_number,
        "ubr": expanded_context.ubr,
        "architecture": expanded_context.architecture,
    }


def _unavailable_vulnerability_inventory(
    base: Mapping[str, object],
) -> dict[str, JsonValue]:
    return validate_windows_component_inventory(
        {
            **dict(base),
            "components": [],
            "collection": {
                "status": "UNAVAILABLE",
                "truncated": False,
                "errors": [
                    "PROGRAMS_UNAVAILABLE",
                    "APPX_UNAVAILABLE",
                    "KB_UNAVAILABLE",
                    "PYTHON_UNAVAILABLE",
                    "NODE_UNAVAILABLE",
                    "JAVA_UNAVAILABLE",
                ],
                "counts": {
                    component_type: 0
                    for component_type in _VULNERABILITY_COMPONENT_TYPES
                },
            },
        }
    )


def run_standard_host_collection(
    project_root: Path,
    *,
    progress_callback: CollectionProgressCallback = _ignore_progress,
    cancel_check: CollectionCancelCheck = _never_cancel,
    include_evaluation_values: bool = False,
) -> dict[str, object]:
    """Run 15 standard-user Probes and persist no raw Windows values."""

    _checkpoint(
        progress_callback,
        cancel_check,
        step="PREPARING",
        percent=5,
        message="점검 항목과 안전 기준을 확인하고 있습니다.",
    )
    contracts, scripts, allowlist_path = _paths(project_root)
    allowlist = ProbeAllowlist.from_file(allowlist_path)
    safety_policy = CollectorSafetyPolicy.from_file(
        contracts / "imp030_safety_policy.json"
    )
    snapshotter = WindowsSafetySnapshotter(
        scripts / "imp030_safety_snapshot.ps1",
        safety_policy,
    )
    _checkpoint(
        progress_callback,
        cancel_check,
        step="SAFETY_BASELINE",
        percent=15,
        message="점검 전 Windows 설정 상태를 확인하고 있습니다.",
    )
    before = snapshotter.capture()
    _checkpoint(
        progress_callback,
        cancel_check,
        step="ACCOUNT_AND_PROTECTION",
        percent=30,
        message="계정·서비스·보호 설정 12개를 확인하고 있습니다.",
    )
    expanded = ExpandedWindowsCollector(
        scripts / "imp031_standard_controls.ps1",
        privilege="STANDARD_USER",
    ).execute(_plan(allowlist, STANDARD_NON_STORAGE_PROBES, suffix="1"))
    results = [
        _expanded_summary(
            result,
            privilege="STANDARD_USER",
            collected_at_utc=expanded.context.collected_at_utc,
        )
        for result in expanded.results
    ]
    _report_completed_controls(
        progress_callback,
        [
            control_id
            for result in expanded.results
            for control_id in result.control_ids
        ],
        start_percent=32,
        end_percent=65,
    )
    evaluation_observations = (
        [
            ProbeObservation(
                probe_id=result.probe_id,
                collection_status=result.collection_status,
                error_code=result.error_code,
                adapter_id=result.adapter_id,
                adapter_version=result.adapter_version,
                privilege="STANDARD_USER",
                collected_at=expanded.context.collected_at_utc,
                records=tuple(
                    cast(Mapping[str, JsonValue], item)
                    for item in result.records
                ),
                user_sid=(
                    expanded.context.process_sid
                    if result.probe_id == "win.user.screensaver-policy"
                    else None
                ),
            )
            for result in expanded.results
        ]
        if include_evaluation_values
        else []
    )
    if cancel_check():
        _verify_settings_unchanged(snapshotter, before)
        raise HostCollectionCancelled
    progress_callback(
        "STORAGE",
        70,
        "저장 장치 설정 3개를 확인하고 있습니다.",
    )
    try:
        storage = WindowsReadOnlyCollector(
            scripts / "pc07_storage_context.ps1"
        ).execute(_plan(allowlist, STORAGE_PROBES, suffix="2"))
    except WindowsCollectionError as exc:
        error_code = (
            "PERMISSION_DENIED"
            if exc.code is WindowsCollectionCode.PERMISSION_DENIED
            else "QUERY_FAILED"
        )
        for probe_id in STORAGE_PROBES:
            contract = allowlist.get(probe_id)
            if contract is None:
                raise HostCollectionReceiptError(
                    "A fixed storage Probe is unavailable."
                ) from exc
            results.append(
                {
                    "probe_id": probe_id,
                    "control_ids": sorted(contract.control_ids),
                    "privilege": "STANDARD_USER",
                    "collection_status": "ERROR",
                    "error_code": error_code,
                    "record_count": 0,
                    "collected_at_utc": expanded.context.collected_at_utc,
                    "normalized_records_sha256": canonical_sha256([]),
                    "raw_evidence_available": False,
                }
            )
            if include_evaluation_values:
                evaluation_observations.append(
                    ProbeObservation(
                        probe_id=probe_id,
                        collection_status="ERROR",
                        error_code=error_code,
                        adapter_id="secai.windows-storage-native",
                        adapter_version="0.1.0",
                        privilege="STANDARD_USER",
                        collected_at=expanded.context.collected_at_utc,
                        records=(),
                    )
                )
    else:
        for result in storage.results:
            payload = result.payload
            if not isinstance(payload, Sequence) or isinstance(
                payload, (str, bytes, bytearray)
            ):
                raise HostCollectionReceiptError(
                    "Storage Probe summary is invalid."
                )
            results.append(
                {
                    "probe_id": result.probe_id,
                    "control_ids": list(result.control_ids),
                    "privilege": "STANDARD_USER",
                    "collection_status": result.collection_status,
                    "error_code": "NONE",
                    "record_count": len(payload),
                    "collected_at_utc": storage.context.collected_at_utc,
                    "normalized_records_sha256": canonical_sha256(
                        cast(JsonValue, list(payload))
                    ),
                    "raw_evidence_available": False,
                }
            )
            if include_evaluation_values:
                evaluation_observations.append(
                    ProbeObservation(
                        probe_id=result.probe_id,
                        collection_status=result.collection_status,
                        error_code="NONE",
                        adapter_id="secai.windows-storage-native",
                        adapter_version=result.probe_version,
                        privilege="STANDARD_USER",
                        collected_at=storage.context.collected_at_utc,
                        records=tuple(
                            cast(Mapping[str, JsonValue], item)
                            for item in cast(Sequence[object], payload)
                        ),
                    )
                )
    _report_completed_controls(
        progress_callback,
        ["PC-07"],
        start_percent=72,
        end_percent=85,
    )
    base_vulnerability_inventory = _base_vulnerability_inventory(expanded.context)
    if cancel_check():
        _verify_settings_unchanged(snapshotter, before)
        raise HostCollectionCancelled
    progress_callback(
        "SOFTWARE_INVENTORY",
        87,
        "설치 프로그램·업데이트·개발 라이브러리를 읽기 전용으로 확인하고 있습니다.",
    )
    try:
        vulnerability_inventory = WindowsVulnerabilityInventoryCollector(
            scripts / "vulnerability_inventory.ps1"
        ).collect(base_vulnerability_inventory)
    except WindowsVulnerabilityInventoryError:
        # 이 보조 수집 실패는 기존 PC-01~18의 FAIL로 바꾸지 않습니다.
        vulnerability_inventory = _unavailable_vulnerability_inventory(
            base_vulnerability_inventory
        )
    if not cancel_check():
        progress_callback(
            "SAFETY_VERIFICATION",
            90,
            "점검 중 PC 설정이 바뀌지 않았는지 확인하고 있습니다.",
        )
    _verify_settings_unchanged(snapshotter, before)
    if cancel_check():
        raise HostCollectionCancelled
    _checkpoint(
        progress_callback,
        cancel_check,
        step="SUMMARIZING",
        percent=95,
        message="개인 설정값을 남기지 않고 점검 결과를 정리하고 있습니다.",
    )
    receipt: dict[str, object] = {
        "observed_at_utc": expanded.context.collected_at_utc,
        # 계정·호스트명·설치 경로 없이 versioned 구성요소만 전달합니다.
        "vulnerability_inventory": vulnerability_inventory,
        "settings_diff_count": 0,
        "results": results,
    }
    if include_evaluation_values:
        receipt["_evaluation_observations"] = tuple(evaluation_observations)
    return receipt


def run_administrator_host_collection(
    project_root: Path,
    *,
    explicit_consent: bool,
) -> dict[str, object]:
    """Run the five administrator Probes only after explicit consent."""

    return run_selected_administrator_host_collection(
        project_root,
        selected_probe_ids=ADMINISTRATOR_PROBES,
        explicit_consent=explicit_consent,
    )


def run_selected_administrator_host_collection(
    project_root: Path,
    *,
    selected_probe_ids: Sequence[str],
    explicit_consent: bool,
    include_evaluation_values: bool = False,
) -> dict[str, object]:
    """Run only the consented administrator Probe subset in allowlist order."""

    if not explicit_consent:
        raise HostCollectionReceiptError(
            "Explicit administrator Probe consent is required."
        )
    selected = tuple(selected_probe_ids)
    expected = tuple(
        probe_id for probe_id in ADMINISTRATOR_PROBES if probe_id in selected
    )
    if (
        not selected
        or len(set(selected)) != len(selected)
        or selected != expected
    ):
        raise HostCollectionReceiptError(
            "Administrator Probe selection is invalid or reordered."
        )
    contracts, scripts, allowlist_path = _paths(project_root)
    allowlist = ProbeAllowlist.from_file(allowlist_path)
    safety_policy = CollectorSafetyPolicy.from_file(
        contracts / "imp030_safety_policy.json"
    )
    snapshotter = WindowsSafetySnapshotter(
        scripts / "imp030_safety_snapshot.ps1",
        safety_policy,
    )
    before = snapshotter.capture()
    expanded = ExpandedWindowsCollector(
        scripts / "imp031_administrator_controls.ps1",
        privilege="ADMINISTRATOR",
    ).execute(_plan(allowlist, selected, suffix="3"))
    after = snapshotter.capture()
    if before.snapshot_sha256 != after.snapshot_sha256:
        raise HostCollectionReceiptError(
            "Windows settings changed during administrator collection."
        )
    receipt: dict[str, object] = {
        "observed_at_utc": expanded.context.collected_at_utc,
        "explicit_consent": True,
        "selected_probe_ids": list(selected),
        "settings_diff_count": 0,
        "results": [
            _expanded_summary(
                result,
                privilege="ADMINISTRATOR",
                collected_at_utc=expanded.context.collected_at_utc,
            )
            for result in expanded.results
        ],
    }
    if include_evaluation_values:
        receipt["_evaluation_observations"] = tuple(
            ProbeObservation(
                probe_id=result.probe_id,
                collection_status=result.collection_status,
                error_code=result.error_code,
                adapter_id=result.adapter_id,
                adapter_version=result.adapter_version,
                privilege="ADMINISTRATOR",
                collected_at=expanded.context.collected_at_utc,
                records=tuple(
                    cast(Mapping[str, JsonValue], item)
                    for item in result.records
                ),
            )
            for result in expanded.results
        )
    return receipt


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise HostCollectionReceiptError(f"Invalid {field}.")
    return value


def _result(
    value: Mapping[str, object],
    *,
    expected_probe: str,
    expected_privilege: str,
) -> dict[str, object]:
    required_fields = frozenset(
        {
            "probe_id",
            "control_ids",
            "privilege",
            "collection_status",
            "error_code",
            "record_count",
        }
    )
    deidentified_metadata_fields = frozenset(
        {
            "collected_at_utc",
            "normalized_records_sha256",
            "raw_evidence_available",
        }
    )
    fields = frozenset(value)
    if fields not in {
        required_fields,
        required_fields | deidentified_metadata_fields,
    }:
        raise HostCollectionReceiptError("Collection result fields are invalid.")
    if deidentified_metadata_fields <= fields:
        collected_at = value.get("collected_at_utc")
        normalized_sha256 = value.get("normalized_records_sha256")
        if (
            not isinstance(collected_at, str)
            or not collected_at.endswith("Z")
            or len(collected_at) > 32
            or not isinstance(normalized_sha256, str)
            or len(normalized_sha256) != 64
            or any(character not in "0123456789abcdef" for character in normalized_sha256)
            or value.get("raw_evidence_available") is not False
        ):
            raise HostCollectionReceiptError(
                "Collection result metadata is invalid."
            )
    if not required_fields <= fields:
        raise HostCollectionReceiptError("Collection result fields are invalid.")
    probe_id = _text(value.get("probe_id"), "Probe ID")
    privilege = _text(value.get("privilege"), "privilege")
    status = _text(value.get("collection_status"), "collection status")
    error_code = _text(value.get("error_code"), "collection error code")
    controls = value.get("control_ids")
    count = value.get("record_count")
    if (
        probe_id != expected_probe
        or privilege != expected_privilege
        or not isinstance(controls, Sequence)
        or isinstance(controls, (str, bytes, bytearray))
        or not controls
        or any(not isinstance(item, str) or not item for item in controls)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        or status not in _STATUSES
        or error_code not in _ERROR_CODES
        or (status == "COLLECTED") != (error_code == "NONE")
        or (status == "COLLECTED" and count == 0)
        or (status != "COLLECTED" and count != 0)
    ):
        raise HostCollectionReceiptError("Collection result contract is invalid.")
    return {
        "probe_id": probe_id,
        "control_ids": list(controls),
        "privilege": privilege,
        "collection_status": status,
        "error_code": error_code,
        "record_count": count,
    }


def build_host_collection_receipt(
    *,
    observed_at_utc: str,
    standard_results: Sequence[Mapping[str, object]],
    administrator_results: Sequence[Mapping[str, object]],
    administrator_consent: bool,
    automatic_uac: bool,
    standard_settings_diff_count: int,
    administrator_settings_diff_count: int,
) -> dict[str, Any]:
    """Preserve collection outcomes without turning them into findings."""

    if not administrator_consent:
        raise HostCollectionReceiptError(
            "Explicit administrator Probe consent is required."
        )
    if (
        automatic_uac
        or standard_settings_diff_count != 0
        or administrator_settings_diff_count != 0
        or not observed_at_utc.endswith("Z")
        or len(observed_at_utc) > 32
    ):
        raise HostCollectionReceiptError("Collection safety evidence is invalid.")
    if (
        tuple(item.get("probe_id") for item in standard_results)
        != STANDARD_PROBES
        or tuple(item.get("probe_id") for item in administrator_results)
        != ADMINISTRATOR_PROBES
    ):
        raise HostCollectionReceiptError("Probe coverage is incomplete or reordered.")

    rows = [
        _result(
            item,
            expected_probe=probe_id,
            expected_privilege="STANDARD_USER",
        )
        for item, probe_id in zip(
            standard_results,
            STANDARD_PROBES,
            strict=True,
        )
    ]
    rows.extend(
        _result(
            item,
            expected_probe=probe_id,
            expected_privilege="ADMINISTRATOR",
        )
        for item, probe_id in zip(
            administrator_results,
            ADMINISTRATOR_PROBES,
            strict=True,
        )
    )
    status_counts = {
        "collected": sum(row["collection_status"] == "COLLECTED" for row in rows),
        "permission_denied": sum(
            row["error_code"] == "PERMISSION_DENIED" for row in rows
        ),
        "unsupported": sum(
            row["collection_status"] == "UNSUPPORTED" for row in rows
        ),
        "query_failed": sum(
            row["error_code"] in {"SOURCE_UNAVAILABLE", "QUERY_FAILED"}
            for row in rows
        ),
    }
    return {
        "imp": "IMP-037",
        "acceptance_status": "PASS",
        "observed_at_utc": observed_at_utc,
        "environment": {
            "kind": "CURRENT_WINDOWS_DEVELOPMENT_HOST",
            "clean_vm_verified": False,
        },
        "summary": {
            "total": len(rows),
            "standard": len(standard_results),
            "administrator": len(administrator_results),
            **status_counts,
        },
        "administrator": {
            "explicit_consent": True,
            "separate_process": True,
            "probe_count": len(administrator_results),
            "cancel_available_before_start": True,
        },
        "safety": {
            "read_only": True,
            "automatic_uac": False,
            "timeout_seconds": 30,
            "max_output_bytes": 65_536,
            "settings_diff_count": 0,
            "raw_values_persisted": False,
        },
        "results": rows,
        "privacy": {
            "sid_disclosed": False,
            "computer_name_disclosed": False,
            "user_name_disclosed": False,
            "volume_identifiers_disclosed": False,
            "sensitive_values_disclosed": False,
        },
        "official_finding_created": False,
        "portable_bundle_created": False,
        "next_imp": "IMP-038",
    }
