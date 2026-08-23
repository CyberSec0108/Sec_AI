from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from security_audit.application.current_host_regression import (
    ProbeObservation,
    evaluate_current_host_observations,
)
from security_audit.application.windows_host_collection_acceptance import (
    STORAGE_PROBES,
    _paths,
    _plan,
)
from security_audit.collector import (
    ProbeAllowlist,
    WindowsCollectionCode,
    WindowsCollectionError,
    WindowsReadOnlyCollector,
    WindowsSafetySnapshotter,
)
from security_audit.collector.expanded import (
    STANDARD_NON_STORAGE_PROBES,
    ExpandedWindowsCollector,
)
from security_audit.collector.safety import CollectorSafetyPolicy
from security_audit.common.canonical_json import JsonValue


def _administrator_observations(
    document: Mapping[str, object],
) -> list[ProbeObservation]:
    results = document.get("results")
    observed_at = document.get("observed_at_utc")
    if (
        document.get("explicit_consent") is not True
        or not isinstance(results, Sequence)
        or isinstance(results, (str, bytes, bytearray))
        or not isinstance(observed_at, str)
    ):
        raise RuntimeError("IMP-037 administrator evidence is invalid.")
    observations: list[ProbeObservation] = []
    for value in results:
        if not isinstance(value, Mapping):
            raise RuntimeError("Administrator Probe result is invalid.")
        observations.append(
            ProbeObservation(
                probe_id=cast(str, value["probe_id"]),
                collection_status=cast(str, value["collection_status"]),
                error_code=cast(str, value["error_code"]),
                adapter_id={
                    "win.security.password-policy": "secai.windows-account-policy",
                    "win.network.smb-shares": "secai.windows-smb-native",
                    "win.software.messengers": (
                        "secai.windows-installed-software-inventory"
                    ),
                    "win.boot.entries": "secai.windows-bcdedit-native",
                    "win.update.compliance": (
                        "secai.windows-update-history-build"
                    ),
                }[cast(str, value["probe_id"])],
                adapter_version="0.1.0",
                privilege="ADMINISTRATOR",
                collected_at=observed_at,
                records=(),
            )
        )
    return observations


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    if len(sys.argv) not in {2, 3}:
        raise RuntimeError("The prior administrator evidence path is required.")
    administrator_path = Path(sys.argv[1]).resolve()
    runtime_root = (project_root / "runtime").resolve()
    if runtime_root not in administrator_path.parents:
        raise RuntimeError("Administrator evidence must be inside project runtime.")
    administrator = cast(
        Mapping[str, object],
        json.loads(administrator_path.read_text(encoding="utf-8")),
    )

    contracts, scripts, allowlist_path = _paths(project_root)
    allowlist = ProbeAllowlist.from_file(allowlist_path)
    snapshotter = WindowsSafetySnapshotter(
        scripts / "imp030_safety_snapshot.ps1",
        CollectorSafetyPolicy.from_file(contracts / "imp030_safety_policy.json"),
    )
    before = snapshotter.capture()
    standard = ExpandedWindowsCollector(
        scripts / "imp031_standard_controls.ps1",
        privilege="STANDARD_USER",
    ).execute(_plan(allowlist, STANDARD_NON_STORAGE_PROBES, suffix="8"))
    try:
        storage = WindowsReadOnlyCollector(
            scripts / "pc07_storage_context.ps1"
        ).execute(_plan(allowlist, STORAGE_PROBES, suffix="9"))
    except WindowsCollectionError as exc:
        storage = None
        storage_error = (
            "PERMISSION_DENIED"
            if exc.code is WindowsCollectionCode.PERMISSION_DENIED
            else "EVIDENCE_INCOMPLETE"
        )
    after = snapshotter.capture()
    if before.snapshot_sha256 != after.snapshot_sha256:
        raise RuntimeError("Windows settings changed during IMP-038 collection.")

    observations = [
        ProbeObservation(
            probe_id=result.probe_id,
            collection_status=result.collection_status,
            error_code=result.error_code,
            adapter_id=result.adapter_id,
            adapter_version=result.adapter_version,
            privilege="STANDARD_USER",
            collected_at=standard.context.collected_at_utc,
            records=tuple(
                cast(Mapping[str, JsonValue], item) for item in result.records
            ),
            user_sid=(
                standard.context.process_sid
                if result.probe_id == "win.user.screensaver-policy"
                else None
            ),
        )
        for result in standard.results
    ]
    if storage is None:
        observations.extend(
            ProbeObservation(
                probe_id=probe_id,
                collection_status="ERROR",
                error_code=storage_error,
                adapter_id="secai.windows-storage-native",
                adapter_version="0.1.0",
                privilege="STANDARD_USER",
                collected_at=standard.context.collected_at_utc,
                records=(),
            )
            for probe_id in STORAGE_PROBES
        )
    else:
        observations.extend(
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
                    for item in cast(Sequence[object], result.payload)
                ),
            )
            for result in storage.results
        )
    observations.extend(_administrator_observations(administrator))

    lifecycle = next(
        item
        for item in standard.results
        if item.probe_id == "win.os.lifecycle"
    )
    lifecycle_record = (
        lifecycle.records[0] if lifecycle.records else {}
    )
    report = evaluate_current_host_observations(
        project_root,
        observations=observations,
        host={
            "os_family": "WINDOWS",
            "product_name": standard.context.product_name,
            "edition": cast(str, lifecycle_record.get("edition_group", "UNKNOWN")),
            "display_version": standard.context.display_version,
            "build": int(standard.context.build_number),
            "ubr": standard.context.ubr,
            "architecture": "x86_64",
            "timezone": "Asia/Seoul",
            "clock_status": "UNKNOWN",
        },
    )
    serialized = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    lowered = serialized.casefold()
    if (
        standard.context.process_sid.casefold() in lowered
        or "vol-001" in lowered
        or report["summary"]["false_pass_count"] != 0  # type: ignore[index]
    ):
        raise RuntimeError("IMP-038 privacy or false-PASS invariant failed.")
    if len(sys.argv) != 3 or sys.argv[2] != "-":
        destination = (
            Path(sys.argv[2]).resolve()
            if len(sys.argv) == 3
            else project_root / "apps" / "web" / "data" / "imp038_evaluation.json"
        )
        destination.write_text(serialized + "\n", encoding="utf-8", newline="\n")
    print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
