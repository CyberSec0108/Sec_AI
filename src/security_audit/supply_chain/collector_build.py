"""Validate and finalize the unsigned IMP-034 Windows Collector build."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

ARTIFACT_NAME = "SecAI-Collector-Windows-x64.exe"
VERSION = "0.1.0"
SBOM_NAME = f"SecAI-Collector-Windows-x64-{VERSION}.cdx.json"
VULNERABILITY_NAME = f"SecAI-Collector-Windows-x64-{VERSION}.vulnerability.json"
CLAMAV_NAME = f"SecAI-Collector-Windows-x64-{VERSION}.clamav.json"
DEFENDER_NAME = f"SecAI-Collector-Windows-x64-{VERSION}.defender.json"
AUTHENTICODE_NAME = f"SecAI-Collector-Windows-x64-{VERSION}.authenticode.json"
MANIFEST_NAME = f"SecAI-Collector-Windows-x64-{VERSION}.manifest.json"
ACCEPTANCE_NAME = "imp034-acceptance.json"
LOCK_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\\s]+)")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object.")
    return cast(dict[str, Any], value)


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _locked_components(lock_path: Path) -> dict[str, str]:
    components: dict[str, str] = {}
    for line in lock_path.read_text(encoding="utf-8").splitlines():
        match = LOCK_PATTERN.match(line)
        if match:
            components[match.group(1).casefold().replace("_", "-")] = match.group(2)
    if not components:
        raise ValueError("Collector build lock has no exact package versions.")
    return components


def _audit_components(report: dict[str, Any]) -> tuple[dict[str, str], int]:
    raw_dependencies = report.get("dependencies")
    if not isinstance(raw_dependencies, list):
        raise ValueError("Vulnerability report dependencies are invalid.")
    components: dict[str, str] = {}
    vulnerabilities = 0
    for item in raw_dependencies:
        if not isinstance(item, dict):
            raise ValueError("Vulnerability report dependency is invalid.")
        name = item.get("name")
        version = item.get("version")
        vulns = item.get("vulns")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(vulns, list)
        ):
            raise ValueError("Vulnerability report dependency fields are invalid.")
        components[name.casefold().replace("_", "-")] = version
        vulnerabilities += len(vulns)
    return components, vulnerabilities


def finalize_imp034_build(project_root: Path, output_directory: Path) -> dict[str, Any]:
    project_root = project_root.resolve()
    output_directory = output_directory.resolve()
    expected_runtime = (project_root / "runtime" / "imp034-artifacts").resolve()
    if expected_runtime not in output_directory.parents:
        raise ValueError("IMP-034 output must remain under runtime/imp034-artifacts.")

    artifact = output_directory / ARTIFACT_NAME
    context_path = output_directory / "imp034-build-context.json"
    sbom_path = output_directory / SBOM_NAME
    vulnerability_path = output_directory / VULNERABILITY_NAME
    clamav_path = output_directory / CLAMAV_NAME
    defender_path = output_directory / DEFENDER_NAME
    authenticode_path = output_directory / AUTHENTICODE_NAME
    for path in (
        artifact,
        context_path,
        sbom_path,
        vulnerability_path,
        clamav_path,
        defender_path,
        authenticode_path,
    ):
        if not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(f"Required IMP-034 output is missing: {path.name}")

    context = _load_object(context_path)
    sbom = _load_object(sbom_path)
    vulnerability = _load_object(vulnerability_path)
    clamav = _load_object(clamav_path)
    defender = _load_object(defender_path)
    authenticode = _load_object(authenticode_path)
    artifact_hash = _sha256(artifact)
    context_artifact = context.get("artifact")
    if not isinstance(context_artifact, dict):
        raise ValueError("Build context artifact is invalid.")

    lock_path = project_root / "requirements" / "lock" / "collector-build.lock"
    locked = _locked_components(lock_path)
    audited, vulnerability_count = _audit_components(vulnerability)
    sbom_components = sbom.get("components")
    sbom_versions = (
        {
            str(component.get("name")).casefold().replace("_", "-"): str(
                component.get("version")
            )
            for component in sbom_components
            if isinstance(component, dict)
        }
        if isinstance(sbom_components, list)
        else {}
    )
    exact_audit = audited == locked
    exact_sbom = sbom_versions == locked
    scan_hashes_match = all(
        report.get("artifact_sha256") == artifact_hash
        for report in (clamav, defender, authenticode)
    )
    self_check = context.get("self_check")
    builder = context.get("builder")
    dependency_lock = context.get("dependency_lock")
    embedded = context.get("embedded_resources")
    checks = [
        {
            "id": "IMP034-C01",
            "title": "Windows 10/11 x64 native builder",
            "passed": (
                isinstance(builder, dict)
                and str(builder.get("os", "")).startswith("Windows-11-")
                and builder.get("architecture") == "AMD64"
            ),
        },
        {
            "id": "IMP034-C02",
            "title": "CPython 3.14.6·PyInstaller 6.21.0 exact build",
            "passed": (
                isinstance(builder, dict)
                and builder.get("python") == "3.14.6"
                and builder.get("pyinstaller") == "6.21.0"
            ),
        },
        {
            "id": "IMP034-C03",
            "title": "hash-locked dependency 설치·lock 결합",
            "passed": (
                isinstance(dependency_lock, dict)
                and dependency_lock.get("hash_install") == "PASS"
                and dependency_lock.get("sha256") == _sha256(lock_path)
            ),
        },
        {
            "id": "IMP034-C04",
            "title": "PE32+ AMD64 one-file artifact·100 MiB 상한",
            "passed": (
                context_artifact.get("format") == "PE32+"
                and context_artifact.get("machine") == "AMD64"
                and context_artifact.get("sha256") == artifact_hash
                and artifact.stat().st_size <= 100 * 1024 * 1024
            ),
        },
        {
            "id": "IMP034-C05",
            "title": "별도 Python 없는 frozen self-check·embedded resource hash",
            "passed": (
                isinstance(self_check, dict)
                and self_check.get("status") == "PASS"
                and self_check.get("frozen_runtime") is True
                and self_check.get("python_runtime") == "3.14.6"
                and self_check.get("resource_failures") == []
                and isinstance(embedded, dict)
                and embedded.get("file_count") == self_check.get(
                    "embedded_resources_verified"
                )
            ),
        },
        {
            "id": "IMP034-C06",
            "title": "CycloneDX SBOM과 exact lock component",
            "passed": (
                sbom.get("bomFormat") == "CycloneDX"
                and sbom.get("specVersion") == "1.4"
                and exact_sbom
            ),
        },
        {
            "id": "IMP034-C07",
            "title": "pip-audit 알려진 취약점 0건",
            "passed": exact_audit and vulnerability_count == 0,
        },
        {
            "id": "IMP034-C08",
            "title": "ClamAV·Microsoft Defender artifact CLEAN",
            "passed": (
                scan_hashes_match
                and clamav.get("status") == "CLEAN"
                and defender.get("status") == "CLEAN"
            ),
        },
        {
            "id": "IMP034-C09",
            "title": "IMP-034 unsigned 경계·IMP-035 Authenticode 보류",
            "passed": (
                authenticode.get("status") == "NOT_SIGNED"
                and context.get("authenticode")
                == "NOT_SIGNED_EXPECTED_UNTIL_IMP035"
            ),
        },
        {
            "id": "IMP034-C10",
            "title": "설정 변경·자동 상승·수집·Finding·이동 묶음 없음",
            "passed": (
                isinstance(self_check, dict)
                and self_check.get("settings_modified") is False
                and self_check.get("automatic_elevation") is False
                and self_check.get("actual_collection_started") is False
                and self_check.get("official_finding_created") is False
                and context.get("production_release") is False
            ),
        },
    ]
    passed = all(bool(check["passed"]) for check in checks)
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    file_records = [
        {
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
        for path in (
            artifact,
            context_path,
            output_directory
            / f"SecAI-Collector-Windows-x64-{VERSION}.embedded-resources.json",
            sbom_path,
            vulnerability_path,
            clamav_path,
            defender_path,
            authenticode_path,
        )
    ]
    manifest = {
        "schema_version": "1.0.0",
        "imp": "IMP-034",
        "product": "Sec_AI MVP",
        "component": "Windows One-shot Security Collector",
        "artifact_version": VERSION,
        "release_channel": "DEV-UNSIGNED",
        "status": "PASS" if passed else "FAIL",
        "generated_at": generated_at,
        "source_snapshot_sha256": context.get("source", {}).get(
            "snapshot_sha256"
        ),
        "dependency_lock_sha256": _sha256(lock_path),
        "files": file_records,
        "known_vulnerability_count": vulnerability_count,
        "malware_scan": {
            "clamav": clamav.get("status"),
            "microsoft_defender": defender.get("status"),
        },
        "authenticode": "NOT_SIGNED",
        "production_release": False,
        "next_imp": "IMP-035",
    }
    manifest_path = output_directory / MANIFEST_NAME
    _write_json(manifest_path, manifest)
    sums_paths = [Path(str(item["name"])) for item in file_records] + [
        Path(MANIFEST_NAME)
    ]
    sums = "\n".join(
        f"{_sha256(output_directory / path)}  {path.as_posix()}"
        for path in sorted(sums_paths, key=lambda item: item.as_posix().casefold())
    )
    (output_directory / "SHA256SUMS.txt").write_text(
        sums + "\n",
        encoding="utf-8",
        newline="\n",
    )
    acceptance = {
        "imp": "IMP-034",
        "acceptance_status": "PASS" if passed else "FAIL",
        "artifact": {
            "name": ARTIFACT_NAME,
            "bytes": artifact.stat().st_size,
            "sha256": artifact_hash,
            "release_channel": "DEV-UNSIGNED",
        },
        "dependency_components": len(locked),
        "known_vulnerabilities": vulnerability_count,
        "embedded_resources": (
            self_check.get("embedded_resources_verified")
            if isinstance(self_check, dict)
            else 0
        ),
        "checks": checks,
        "malware_scan": manifest["malware_scan"],
        "authenticode": "DEFERRED_TO_IMP035",
        "production_release": False,
        "portable_bundle_created": False,
        "official_finding_created": False,
        "next_imp": "IMP-035",
    }
    _write_json(output_directory / ACCEPTANCE_NAME, acceptance)
    if not passed:
        raise ValueError("IMP-034 final acceptance failed.")
    return acceptance
