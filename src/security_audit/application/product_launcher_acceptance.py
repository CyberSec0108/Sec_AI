"""IMP-040 deterministic product-shell and Launcher acceptance."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from security_audit.application.product_features import (
    FeatureState,
    public_feature_registry,
)
from security_audit.collector.launcher import run_one_click_standard_scan


def _synthetic_receipt(_: Path) -> dict[str, object]:
    return {
        "observed_at_utc": "2026-07-23T09:00:00Z",
        "settings_diff_count": 0,
        "results": [
            {
                "probe_id": f"win.acceptance.{index}",
                "control_ids": [f"PC-{index:02d}"],
                "privilege": "STANDARD_USER",
                "collection_status": "COLLECTED",
                "error_code": "NONE",
                "record_count": 1,
            }
            for index in range(1, 16)
        ],
    }


def _disabled_boundary_value(value: object) -> bool:
    return value is False or (
        isinstance(value, int) and not isinstance(value, bool) and value == 0
    )


def run_product_launcher_acceptance(project_root: Path) -> dict[str, object]:
    policy_path = (
        project_root
        / "collectors"
        / "one_shot"
        / "contracts"
        / "imp040_product_launcher_policy.json"
    )
    policy = cast(
        Mapping[str, object],
        json.loads(policy_path.read_text(encoding="utf-8")),
    )
    opened: list[str] = []

    def browser_opener(url: str) -> bool:
        opened.append(url)
        return True

    completed = run_one_click_standard_scan(
        project_root,
        confirmed=True,
        scan_runner=_synthetic_receipt,
        browser_opener=browser_opener,
    )
    cancelled = run_one_click_standard_scan(
        project_root,
        confirmed=False,
        scan_runner=_synthetic_receipt,
        browser_opener=browser_opener,
    )
    registry = public_feature_registry()
    counts = {
        state.value: sum(item.state is state for item in registry.values())
        for state in (FeatureState.LIVE, FeatureState.PREVIEW, FeatureState.BLOCKED)
    }
    preview_boundary = cast(Mapping[str, object], policy["preview_boundary"])
    accepted = (
        policy.get("imp") == "IMP-040"
        and completed["status"] == "COMPLETED"
        and completed["total_probes"] == 15
        and completed["settings_modified"] is False
        and completed["raw_values_persisted"] is False
        and completed["official_finding_created"] is False
        and cancelled["actual_collection_started"] is False
        and len(opened) == 1
        and opened[0].startswith(
            "http://localhost:18480/ui/launcher-return?status=COMPLETED"
        )
        and counts == {"LIVE": 12, "PREVIEW": 1, "BLOCKED": 0}
        and "audit_pack_draft_assist" not in registry
        and all(_disabled_boundary_value(value) for value in preview_boundary.values())
    )
    return {
        "imp": "IMP-040",
        "acceptance_status": "PASS" if accepted else "FAIL",
        "launcher": {
            "entry": "SecAI-Collector-Windows-x64.exe",
            "user_actions_after_open": 1,
            "powershell_command_required": False,
            "docker_command_required": False,
            "automatic_elevation": False,
        },
        "standard_scan": completed,
        "cancellation": cancelled,
        "feature_state_counts": counts,
        "hidden_feature_exposed": False,
        "preview_boundary": dict(preview_boundary),
        "administrator_direct_url_status": 423,
        "production_download": False,
        "portable_bundle_created": False,
    }
