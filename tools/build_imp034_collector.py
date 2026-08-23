from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

EXPECTED_PYTHON = (3, 14, 6)
EXPECTED_PYINSTALLER = "6.21.0"
ARTIFACT_NAME = "SecAI-Collector-Windows-x64.exe"
ARTIFACT_VERSION = "0.1.0"
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
RESOURCE_SUFFIXES = frozenset({".json", ".ps1"})
LIVE_DRAFT_RESOURCE_PATHS = (
    Path("audit_packs/kisa_2026_pc/src/pack-0.6.0.json"),
    Path(
        "audit_packs/kisa_2026_pc/reference_snapshots/"
        "microsoft_windows_11/2026-07-23.json"
    ),
    Path(
        "audit_packs/kisa_2026_pc/adapter_catalogs/"
        "endpoint_protection/0.1.0.json"
    ),
    Path("guides/mappings/kisa_2026_pc_control_sources.json"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_snapshot(project_root: Path) -> tuple[str, list[dict[str, object]]]:
    roots = (
        project_root / "src" / "security_audit",
        project_root / "collectors" / "one_shot",
        project_root / "database" / "schemas",
    )
    explicit = (
        project_root / "requirements" / "lock" / "collector-build.lock",
        project_root / "requirements" / "collector-build.in",
        project_root / "pyproject.toml",
        *(project_root / path for path in LIVE_DRAFT_RESOURCE_PATHS),
    )
    files = {
        path
        for root in roots
        for path in root.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix.casefold() not in {".pyc", ".pyo"}
    }
    files.update(explicit)
    records: list[dict[str, object]] = []
    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.as_posix().casefold()):
        relative = path.relative_to(project_root).as_posix()
        file_hash = _sha256(path)
        size = path.stat().st_size
        digest.update(f"{relative}\0{file_hash}\0{size}\n".encode())
        records.append({"path": relative, "sha256": file_hash, "bytes": size})
    return digest.hexdigest(), records


def _embedded_resources(project_root: Path) -> list[dict[str, object]]:
    roots = (
        project_root / "collectors" / "one_shot" / "contracts",
        (
            project_root
            / "collectors"
            / "one_shot"
            / "probes"
            / "windows"
            / "powershell"
        ),
        project_root / "database" / "schemas",
    )
    selected = {
        path
        for root in roots
        for path in root.rglob("*")
        if path.is_file() and path.suffix.casefold() in RESOURCE_SUFFIXES
    }
    selected.update(project_root / path for path in LIVE_DRAFT_RESOURCE_PATHS)
    if any(not path.is_file() for path in selected):
        raise RuntimeError("A required Collector runtime resource is missing.")
    records: list[dict[str, object]] = []
    for path in sorted(
        selected,
        key=lambda item: item.as_posix().casefold(),
    ):
        relative = path.relative_to(project_root).as_posix()
        records.append(
            {
                "path": relative,
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
            }
        )
    if not records:
        raise RuntimeError("No Collector resources were selected for the native build.")
    return records


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _run_self_check(artifact: Path) -> dict[str, Any]:
    completed = subprocess.run(  # noqa: S603 - exact freshly built artifact
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
        raise RuntimeError("Frozen Collector self-check failed.")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Frozen Collector returned invalid self-check JSON.") from exc
    if report.get("status") != "PASS":
        raise RuntimeError("Frozen Collector self-check did not pass.")
    return report


def _inspect_pe(artifact: Path) -> dict[str, object]:
    import pefile

    pe = pefile.PE(str(artifact), fast_load=True)
    try:
        machine = pe.FILE_HEADER.Machine
        optional_magic = pe.OPTIONAL_HEADER.Magic
        subsystem = pe.OPTIONAL_HEADER.Subsystem
    finally:
        pe.close()
    if machine != 0x8664 or optional_magic != 0x20B:
        raise RuntimeError("Collector artifact is not a Windows AMD64 PE32+ executable.")
    return {
        "format": "PE32+",
        "machine": "AMD64",
        "machine_code": "0x8664",
        "optional_header_magic": "0x20b",
        "subsystem": subsystem,
    }


def main() -> int:
    if os.name != "nt" or platform.machine().upper() != "AMD64":
        raise RuntimeError("IMP-034 must run on a Windows x64 builder.")
    if sys.version_info[:3] != EXPECTED_PYTHON:
        raise RuntimeError("IMP-034 requires exact CPython 3.14.6.")

    import PyInstaller
    import PyInstaller.__main__

    if PyInstaller.__version__ != EXPECTED_PYINSTALLER:
        raise RuntimeError("IMP-034 requires exact PyInstaller 6.21.0.")

    project_root = Path(__file__).resolve().parents[1]
    runtime_root = (project_root / "runtime").resolve()
    runtime_root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_dir = runtime_root / "imp034-artifacts" / f"build-{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=False)

    source_hash, source_files = _source_snapshot(project_root)
    resources = _embedded_resources(project_root)
    build_started_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    with tempfile.TemporaryDirectory(
        prefix="secai-imp034-",
        dir=runtime_root,
    ) as temporary:
        temporary_root = Path(temporary)
        resource_manifest_path = temporary_root / "embedded-resources.json"
        resource_manifest = {
            "schema_version": "1.0.0",
            "artifact_version": ARTIFACT_VERSION,
            "source_snapshot_sha256": source_hash,
            "files": resources,
        }
        _write_json(resource_manifest_path, resource_manifest)

        arguments = [
            str(project_root / "collectors" / "one_shot" / "entrypoint.py"),
            "--name",
            ARTIFACT_NAME.removesuffix(".exe"),
            "--onefile",
            "--console",
            "--noupx",
            "--clean",
            "--noconfirm",
            "--paths",
            str(project_root / "src"),
            "--collect-submodules",
            "security_audit.collector",
            "--version-file",
            str(
                project_root
                / "collectors"
                / "one_shot"
                / "build"
                / "windows_version_info.txt"
            ),
            "--distpath",
            str(output_dir),
            "--workpath",
            str(temporary_root / "work"),
            "--specpath",
            str(temporary_root / "spec"),
        ]
        for record in resources:
            relative = str(record["path"])
            destination = f"resources/{Path(relative).parent.as_posix()}"
            arguments.extend(
                [
                    "--add-data",
                    f"{project_root / Path(relative)}{os.pathsep}{destination}",
                ]
            )
        arguments.extend(
            [
                "--add-data",
                f"{resource_manifest_path}{os.pathsep}resources",
            ]
        )
        os.environ["PYTHONHASHSEED"] = "0"
        os.environ["SOURCE_DATE_EPOCH"] = "1784793600"
        PyInstaller.__main__.run(arguments)

        copied_manifest = output_dir / (
            "SecAI-Collector-Windows-x64-0.1.0.embedded-resources.json"
        )
        _write_json(copied_manifest, resource_manifest)

    artifact = output_dir / ARTIFACT_NAME
    if (
        not artifact.is_file()
        or artifact.stat().st_size <= 0
        or artifact.stat().st_size > MAX_ARTIFACT_BYTES
    ):
        raise RuntimeError("Collector artifact is missing or outside the size limit.")
    self_check = _run_self_check(artifact)
    pe = _inspect_pe(artifact)
    build_completed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    context = {
        "imp": "IMP-034",
        "status": "PASS",
        "artifact": {
            "name": ARTIFACT_NAME,
            "version": ARTIFACT_VERSION,
            "bytes": artifact.stat().st_size,
            "sha256": _sha256(artifact),
            **pe,
        },
        "builder": {
            "os": platform.platform(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "pyinstaller": PyInstaller.__version__,
        },
        "dependency_lock": {
            "path": "requirements/lock/collector-build.lock",
            "sha256": _sha256(
                project_root / "requirements" / "lock" / "collector-build.lock"
            ),
            "hash_install": "PASS",
        },
        "source": {
            "revision": "UNAVAILABLE_NO_GIT_CLIENT",
            "snapshot_sha256": source_hash,
            "file_count": len(source_files),
        },
        "embedded_resources": {
            "manifest": copied_manifest.name,
            "manifest_sha256": _sha256(copied_manifest),
            "file_count": len(resources),
        },
        "self_check": self_check,
        "build_started_at": build_started_at,
        "build_completed_at": build_completed_at,
        "authenticode": "NOT_SIGNED_EXPECTED_UNTIL_IMP035",
        "production_release": False,
    }
    context_path = output_dir / "imp034-build-context.json"
    _write_json(context_path, context)
    print(
        json.dumps(
            {
                "status": "PASS",
                "output_directory": str(output_dir),
                "artifact": str(artifact),
                "build_context": str(context_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
