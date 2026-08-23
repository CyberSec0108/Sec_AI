"""Safe command boundary for the frozen Windows Collector artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import webbrowser
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from security_audit import __version__
from security_audit.application.administrator_scan import CONSENT_VERSION
from security_audit.collector.criteria_contract import (
    CriteriaContractError,
    decode_criteria_execution_context,
)
from security_audit.collector import __all__ as collector_exports
from security_audit.collector.administrator_launcher import (
    run_administrator_result_bridge,
)
from security_audit.collector.expanded import ADMINISTRATOR_PROBES
from security_audit.collector.launcher import (
    LauncherPortInUseError,
    run_launcher_bridge,
)

EXPECTED_PYTHON = (3, 14, 6)
EXPECTED_MACHINE = "AMD64"
RESOURCE_MANIFEST = Path("resources") / "embedded-resources.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bundle_root() -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if isinstance(frozen_root, str):
        return Path(frozen_root)
    return Path(__file__).resolve().parents[3]


def _collection_root() -> Path:
    root = _bundle_root()
    return root / "resources" if bool(getattr(sys, "frozen", False)) else root


def verify_embedded_resources(bundle_root: Path) -> tuple[int, list[str]]:
    manifest_path = bundle_root / RESOURCE_MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0, ["RESOURCE_MANIFEST_INVALID"]
    records = manifest.get("files")
    if not isinstance(records, list) or not records:
        return 0, ["RESOURCE_MANIFEST_INVALID"]
    failures: list[str] = []
    verified = 0
    for record in records:
        if not isinstance(record, dict):
            failures.append("RESOURCE_RECORD_INVALID")
            continue
        relative_path = record.get("path")
        expected_hash = record.get("sha256")
        expected_bytes = record.get("bytes")
        if (
            not isinstance(relative_path, str)
            or not isinstance(expected_hash, str)
            or not isinstance(expected_bytes, int)
            or Path(relative_path).is_absolute()
            or ".." in Path(relative_path).parts
        ):
            failures.append("RESOURCE_RECORD_INVALID")
            continue
        candidate = bundle_root / "resources" / relative_path
        try:
            matches = (
                candidate.is_file()
                and candidate.stat().st_size == expected_bytes
                and _sha256(candidate) == expected_hash
            )
        except OSError:
            matches = False
        if not matches:
            failures.append(f"RESOURCE_INTEGRITY_FAILED:{relative_path}")
        else:
            verified += 1
    return verified, failures


def self_check(bundle_root: Path | None = None) -> dict[str, Any]:
    root = bundle_root or _bundle_root()
    verified, failures = verify_embedded_resources(root)
    frozen = bool(getattr(sys, "frozen", False))
    runtime_ok = sys.version_info[:3] == EXPECTED_PYTHON
    platform_ok = os.name == "nt" and platform.machine().upper() == EXPECTED_MACHINE
    passed = frozen and runtime_ok and platform_ok and not failures and verified > 0
    return {
        "product": "Sec_AI MVP",
        "component": "Windows One-shot Security Collector",
        "artifact_name": Path(sys.executable).name,
        "collector_version": __version__,
        "status": "PASS" if passed else "FAIL",
        "frozen_runtime": frozen,
        "python_runtime": platform.python_version(),
        "target": {
            "os": "Windows",
            "architecture": platform.machine(),
        },
        "collector_modules_exported": len(collector_exports),
        "embedded_resources_verified": verified,
        "resource_failures": failures,
        "automatic_elevation": False,
        "host_security_settings_read": False,
        "settings_modified": False,
        "actual_collection_started": False,
        "official_finding_created": False,
        "authenticode_expected_in": "IMP-035",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="SecAI-Collector-Windows-x64.exe",
        description=(
            "Sec_AI Windows One-shot Collector DEV build. "
            "Open the Launcher or select launch for a standard-user read-only scan."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Sec_AI Collector {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser(
        "self-check",
        help="Verify the frozen runtime and embedded resource hashes.",
    )
    subparsers.add_parser(
        "launch",
        help="Open the product page and connect its one-click scan button.",
    )
    administrator = subparsers.add_parser(
        "administrator-launch",
        help=argparse.SUPPRESS,
    )
    administrator.add_argument(
        "--consent-version",
        choices=(CONSENT_VERSION,),
        required=True,
    )
    administrator.add_argument(
        "--probe-id",
        action="append",
        choices=ADMINISTRATOR_PROBES,
        required=True,
    )
    administrator.add_argument(
        "--criteria-context",
        help=argparse.SUPPRESS,
    )
    administrator.add_argument(
        "--result-token",
        required=True,
        help=argparse.SUPPRESS,
    )
    return parser


def _launch() -> int:
    report = self_check()
    if report["status"] != "PASS":
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 1
    print(
        "Sec_AI Launcher가 실행 중입니다. "
        "열린 제품 화면에서 '내 PC 점검하기'를 누르세요."
    )
    try:
        run_launcher_bridge(
            _collection_root(),
            browser_opener=webbrowser.open,
        )
    except LauncherPortInUseError:
        print(
            "기존 Sec_AI Launcher를 안전하게 종료하지 못했습니다. "
            "잠시 후 다시 실행해 주세요."
        )
        return 2
    return 0


def _administrator_launch(
    probe_ids: Sequence[str],
    criteria_context_value: str | None,
    result_token: str,
) -> int:
    report = self_check()
    if report["status"] != "PASS":
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 1
    print(
        "동의한 관리자 추가 점검을 읽기 전용으로 실행합니다. "
        "PC 설정은 변경하지 않습니다."
    )
    try:
        criteria_context = (
            decode_criteria_execution_context(criteria_context_value)
            if criteria_context_value is not None
            else None
        )
    except CriteriaContractError:
        print("점검 기준 확인값이 올바르지 않아 관리자 점검을 시작하지 않았습니다.")
        return 2
    run_administrator_result_bridge(
        _collection_root(),
        selected_probe_ids=tuple(probe_ids),
        browser_opener=webbrowser.open,
        criteria_context=criteria_context,
        result_token=result_token,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "self-check":
        report = self_check()
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        return 0 if report["status"] == "PASS" else 1
    if arguments.command in {None, "launch"}:
        return _launch()
    if arguments.command == "administrator-launch":
        return _administrator_launch(
            arguments.probe_id,
            arguments.criteria_context,
            arguments.result_token,
        )
    parser.print_help()
    return 2
