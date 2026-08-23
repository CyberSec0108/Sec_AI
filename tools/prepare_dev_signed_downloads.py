from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from security_audit.supply_chain.dev_signed_download import (
    ACTIVE_POINTER_NAME,
    CATALOG_NAME,
    TRUST_NAME,
    TRUST_PROFILE,
    DevArtifactPlatform,
    build_dev_signed_catalog,
    sha256_file,
)


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object.")
    return cast(dict[str, Any], value)


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _private_key(
    path: Path,
    *,
    project_root: Path,
    generate_if_missing: bool,
) -> Ed25519PrivateKey:
    resolved = path.resolve()
    if resolved == project_root or project_root in resolved.parents:
        raise ValueError("Development signing private key must stay outside the project.")
    if not resolved.exists():
        if not generate_if_missing:
            raise ValueError("Development signing private key does not exist.")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        encoded = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        descriptor = os.open(resolved, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
        return key
    value = load_pem_private_key(resolved.read_bytes(), password=None)
    if not isinstance(value, Ed25519PrivateKey):
        raise ValueError("Development signing key must be Ed25519 PKCS8 PEM.")
    return value


def _windows_source(root: Path) -> tuple[Path, dict[str, object]]:
    acceptance_path = root / "imp035-acceptance.json"
    acceptance = _load_object(acceptance_path)
    artifact = root / "SecAI-Collector-Windows-x64.exe"
    artifact_record = acceptance.get("artifact")
    malware = acceptance.get("malware_scan")
    if (
        acceptance.get("acceptance_status")
        != "PASS_WITH_DEFERRED_EXTERNAL_GATES"
        or acceptance.get("implementation_complete") is not True
        or acceptance.get("production_release_ready") is not False
        or acceptance.get("profile") != "DEV-EPHEMERAL-AUTHENTICODE"
        or not isinstance(artifact_record, dict)
        or not isinstance(malware, dict)
        or acceptance.get("known_vulnerabilities") != 0
        or malware.get("clamav") != "CLEAN"
        or malware.get("microsoft_defender") != "CLEAN"
        or not artifact.is_file()
        or artifact_record.get("post_sign_sha256") != sha256_file(artifact)
    ):
        raise ValueError("Windows development Authenticode release did not pass.")
    return artifact, {
        "source_profile": "DEV-EPHEMERAL-AUTHENTICODE",
        "security_gates": "PASS",
        "source_acceptance_sha256": sha256_file(acceptance_path),
        "native_signature": "AUTHENTICODE-SELF-SIGNED-UNTRUSTED-ROOT",
        "known_vulnerabilities": 0,
        "malware_scan": "CLAMAV-AND-DEFENDER-CLEAN",
    }


def _linux_sources(
    root: Path,
) -> tuple[dict[DevArtifactPlatform, Path], dict[DevArtifactPlatform, dict[str, object]]]:
    manifest_path = root / "linux-collector-release-manifest.json"
    manifest = _load_object(manifest_path)
    gates = manifest.get("security_gates")
    items = manifest.get("artifacts")
    if (
        manifest.get("schema_version") != "1.0.0"
        or manifest.get("profile") != "SECAI-LINUX-COLLECTOR-RELEASE-V1"
        or not isinstance(gates, dict)
        or gates.get("dependency_scan") != "PASS"
        or gates.get("os_package_scan") != "PASS"
        or gates.get("malware_scan") != "CLEAN"
        or not isinstance(items, list)
    ):
        raise ValueError("Linux development release security gates did not pass.")
    source_manifest_hash = sha256_file(manifest_path)
    by_distribution = {
        "AUTO_X86_64": DevArtifactPlatform.LINUX_AUTO_X64,
        "UBUNTU_24_04": DevArtifactPlatform.UBUNTU_24_04_X64,
        "ROCKY_9": DevArtifactPlatform.ROCKY_9_X64,
    }
    artifacts: dict[DevArtifactPlatform, Path] = {}
    provenance: dict[DevArtifactPlatform, dict[str, object]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        distribution = item.get("distribution")
        if distribution not in by_distribution:
            continue
        platform = by_distribution[cast(str, distribution)]
        filename = item.get("filename")
        if not isinstance(filename, str):
            raise ValueError("Linux artifact filename is invalid.")
        artifact = root / filename
        if (
            not artifact.is_file()
            or artifact.resolve().parent != root.resolve()
            or item.get("sha256") != sha256_file(artifact)
        ):
            raise ValueError("Linux artifact hash does not match its source manifest.")
        artifacts[platform] = artifact
        provenance[platform] = {
            "source_profile": str(manifest.get("release_channel", "")),
            "security_gates": "PASS",
            "source_manifest_sha256": source_manifest_hash,
            "native_signature": "DETACHED-ED25519-ADDED-BY-DEV-CATALOG",
            "builder_image_digest": str(manifest.get("build_image_digest", "")),
            "malware_scan": "CLAMAV-CLEAN",
        }
    if set(artifacts) != {
        DevArtifactPlatform.LINUX_AUTO_X64,
        DevArtifactPlatform.UBUNTU_24_04_X64,
        DevArtifactPlatform.ROCKY_9_X64,
    }:
        raise ValueError("All automatic, Ubuntu and Rocky artifacts are required.")
    return artifacts, provenance


def _safe_output_root(project_root: Path, requested: Path) -> Path:
    expected = (project_root / "runtime" / "dev-signed-downloads").resolve()
    resolved = requested.resolve()
    if resolved != expected:
        raise ValueError("Development download output must use runtime/dev-signed-downloads.")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--generate-key-if-missing", action="store_true")
    parser.add_argument("--windows-release", type=Path, required=True)
    parser.add_argument("--linux-release", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--valid-days", type=int, default=7)
    arguments = parser.parse_args()

    project_root = Path(__file__).resolve().parents[1]
    output_root = _safe_output_root(project_root, arguments.output_root)
    if arguments.valid_days < 1 or arguments.valid_days > 100:
        raise ValueError("Development release validity must be between 1 and 100 days.")
    key = _private_key(
        arguments.signing_key,
        project_root=project_root,
        generate_if_missing=arguments.generate_key_if_missing,
    )
    public_raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_hash = hashlib.sha256(public_raw).hexdigest()
    key_id = "secai-dev-download-" + public_hash[:16]

    windows, windows_provenance = _windows_source(arguments.windows_release.resolve())
    linux, linux_provenance = _linux_sources(arguments.linux_release.resolve())
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    release_directory = output_root / f"release-{timestamp}"
    release_directory.mkdir(parents=False, exist_ok=False)
    sources = {DevArtifactPlatform.WINDOWS_X64: windows, **linux}
    copied: dict[DevArtifactPlatform, Path] = {}
    for platform, source in sources.items():
        destination = release_directory / source.name
        shutil.copy2(source, destination)
        copied[platform] = destination

    created_at = datetime.now(UTC)
    catalog = build_dev_signed_catalog(
        artifacts=copied,
        created_at=created_at,
        expires_at=created_at + timedelta(days=arguments.valid_days),
        sign=lambda payload: (key_id, key.sign(payload)),
        provenance={
            DevArtifactPlatform.WINDOWS_X64: windows_provenance,
            **linux_provenance,
        },
    )
    _write_json(release_directory / CATALOG_NAME, catalog)
    (release_directory / "DEV-SIGNED-TEST.txt").write_text(
        "개발시험 전용 임시 서명 파일입니다. 조직 서명 또는 운영 배포본이 아닙니다.\n",
        encoding="utf-8",
        newline="\n",
    )

    trust = {
        "schema_version": "1.0.0",
        "profile": TRUST_PROFILE,
        "algorithm": "Ed25519",
        "key_id": key_id,
        "public_key_base64": base64.urlsafe_b64encode(public_raw)
        .decode("ascii")
        .rstrip("="),
        "public_key_sha256": public_hash,
        "production_trust": False,
    }
    existing_trust_path = output_root / TRUST_NAME
    if existing_trust_path.exists():
        existing = _load_object(existing_trust_path)
        if existing.get("public_key_sha256") != public_hash:
            raise ValueError("Development trust key rotation requires explicit cleanup.")
    _write_json(existing_trust_path, trust)
    _write_json(
        output_root / ACTIVE_POINTER_NAME,
        {
            "schema_version": "1.0.0",
            "release_directory": release_directory.name,
            "catalog_sha256": sha256_file(release_directory / CATALOG_NAME),
            "activated_at": created_at.isoformat().replace("+00:00", "Z"),
        },
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "release_directory": str(release_directory),
                "key_id": key_id,
                "platforms": [item.value for item in DevArtifactPlatform],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
