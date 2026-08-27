from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_audit.collector.scan_sidecar_keys import trusted_keys_document
from security_audit.supply_chain.linux_collector_release import (
    ReleaseSigner,
    build_linux_release_manifest,
)

EXPECTED_PYTHON = (3, 14, 6)
EXPECTED_PYINSTALLER = "6.21.0"
VERSION = "0.1.0"
ARTIFACTS = {
    "AUTO_X86_64": (
        "collectors/one_shot/linux_entrypoint.py",
        "secai-linux-check-x86_64",
    ),
    "UBUNTU_24_04": (
        "collectors/one_shot/linux_ubuntu24_entrypoint.py",
        "secai-linux-check-ubuntu24-x86_64",
    ),
    "ROCKY_9": (
        "collectors/one_shot/linux_rocky9_entrypoint.py",
        "secai-linux-check-rocky9-x86_64",
    ),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _installed_packages() -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata.get("Name")
        if not name:
            continue
        license_name = (
            distribution.metadata.get("License-Expression")
            or distribution.metadata.get("License")
            or "NOASSERTION"
        )
        packages.append(
            {
                "name": name,
                "version": distribution.version,
                "license": " ".join(license_name.split()) or "NOASSERTION",
            }
        )
    return sorted(packages, key=lambda item: item["name"].casefold())


def _write_supply_chain_documents(
    output: Path,
    *,
    project_root: Path,
) -> tuple[Path, Path, Path]:
    packages = _installed_packages()
    sbom = output / f"secai-linux-check-{VERSION}.spdx.json"
    _write_json(
        sbom,
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "name": f"Sec_AI Linux Collector {VERSION}",
            "documentNamespace": (
                "https://sec-ai.invalid/spdx/linux-collector/"
                f"{VERSION}/{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
            ),
            "creationInfo": {
                "created": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "creators": ["Tool: Sec_AI locked Linux Collector builder"],
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-Package-{index}",
                    "name": item["name"],
                    "versionInfo": item["version"],
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": item["license"],
                }
                for index, item in enumerate(packages, start=1)
            ],
        },
    )
    notice = output / f"secai-linux-check-{VERSION}-THIRD-PARTY-NOTICES.txt"
    lines = [
        "Sec_AI Linux Collector third-party package notice",
        "Exact license texts must be reviewed from the corresponding package distribution.",
        "",
        *(f"{item['name']} {item['version']} | {item['license']}" for item in packages),
        "",
    ]
    notice.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    vex = output / f"secai-linux-check-{VERSION}.openvex.json"
    shutil.copyfile(
        project_root / "deploy" / "security" / "linux-collector-builder.openvex.json",
        vex,
    )
    return sbom, notice, vex


def _load_signer(
    *,
    signing_key_file: Path | None,
    signing_key_id: str | None,
    project_root: Path,
    output: Path,
) -> tuple[ReleaseSigner | None, dict[str, str] | None]:
    if signing_key_file is None:
        return None, None
    if not signing_key_id:
        raise RuntimeError("A signing key id is required with the external key file.")
    resolved = signing_key_file.resolve(strict=True)
    if resolved.is_relative_to(project_root) or resolved.is_relative_to(output):
        raise RuntimeError("The release private key must stay outside source and output paths.")
    private_key = serialization.load_pem_private_key(resolved.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError("The Linux release key must be an Ed25519 private key.")

    def sign(payload: bytes) -> tuple[str, bytes]:
        return signing_key_id, private_key.sign(payload)

    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_record = {
        "algorithm": "Ed25519",
        "key_id": signing_key_id,
        "public_key": base64.urlsafe_b64encode(raw_public).decode("ascii").rstrip("="),
    }
    return sign, public_record


def _build_artifact(
    *,
    project_root: Path,
    output: Path,
    work: Path,
    entrypoint: str,
    name: str,
    trusted_keys: Path,
) -> Path:
    spec_path = work / f"{name}.spec"
    spec_path.write_text(
        "\n".join(
            [
                "# -*- mode: python ; coding: utf-8 -*-",
                "",
                "a = Analysis(",
                f"    [{str(project_root / entrypoint)!r}],",
                f"    pathex=[{str(project_root / 'src')!r}],",
                "    binaries=[],",
                "    datas=[",
                "        (",
                f"            {str(project_root / 'database' / 'schemas')!r},",
                "            'database/schemas',",
                "        ),",
                "        (",
                f"            {str(trusted_keys)!r},",
                "            'collectors/one_shot/contracts',",
                "        ),",
                "    ],",
                "    hiddenimports=[],",
                "    hookspath=[],",
                "    hooksconfig={},",
                "    runtime_hooks=[],",
                "    excludes=[],",
                "    noarchive=False,",
                "    optimize=0,",
                ")",
                "# 대상 OS가 제공하는 하위 호환 GCC runtime을 사용합니다.",
                "a.binaries = [",
                "    item for item in a.binaries",
                "    if str(item[0]).rsplit('/', 1)[-1]",
                "    not in {'libgcc_s.so.1', 'libstdc++.so.6'}",
                "]",
                "pyz = PYZ(a.pure)",
                "exe = EXE(",
                "    pyz,",
                "    a.scripts,",
                "    a.binaries,",
                "    a.datas,",
                "    [],",
                f"    name={name!r},",
                "    debug=False,",
                "    bootloader_ignore_signals=False,",
                "    strip=False,",
                "    upx=False,",
                "    runtime_tmpdir=None,",
                "    console=True,",
                "    disable_windowed_traceback=False,",
                "    argv_emulation=False,",
                "    target_arch=None,",
                "    codesign_identity=None,",
                "    entitlements_file=None,",
                ")",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(spec_path),
        "--clean",
        "--noconfirm",
        "--distpath",
        str(output),
        "--workpath",
        str(work / f"work-{name}"),
    ]
    completed = subprocess.run(command, check=False, shell=False)  # noqa: S603
    if completed.returncode != 0:
        raise RuntimeError(f"PyInstaller failed for {name}.")
    artifact = output / name
    if not artifact.is_file():
        raise RuntimeError(f"PyInstaller did not create {name}.")
    artifact.chmod(0o755)
    return artifact


def _write_trusted_sidecar_keys(seed_path: Path, work: Path) -> Path:
    """서명 seed에서 공개 키만 뽑아 빌드 작업 폴더에 둡니다.

    빌드 컨테이너는 읽기 전용이라 원본 트리에 쓰지 않습니다.
    """

    try:
        seed = seed_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(
            "사이드카 서명 seed를 찾을 수 없습니다. "
            "tools/init-dev-secrets.ps1을 먼저 실행하세요."
        ) from exc
    target = work / "scan_sidecar_trusted_keys.json"
    target.write_text(trusted_keys_document(seed), encoding="utf-8", newline="\n")
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--build-image-digest", required=True)
    parser.add_argument(
        "--release-channel",
        choices=["DEV-UNSIGNED", "SIGNED-PILOT", "SIGNED-PRODUCTION"],
        default="DEV-UNSIGNED",
    )
    parser.add_argument("--signing-key-file", type=Path)
    parser.add_argument("--sidecar-signing-key-file", type=Path, required=True)
    parser.add_argument("--signing-key-id")
    parser.add_argument("--dependency-scan", choices=["PASS", "FAIL", "PENDING"], default="PENDING")
    parser.add_argument("--os-package-scan", choices=["PASS", "FAIL", "PENDING"], default="PENDING")
    parser.add_argument(
        "--malware-scan",
        choices=["CLEAN", "INFECTED", "PENDING"],
        default="PENDING",
    )
    arguments = parser.parse_args()

    if sys.version_info[:3] != EXPECTED_PYTHON:
        raise RuntimeError("Linux Collector requires exact CPython 3.14.6.")
    if importlib.metadata.version("pyinstaller") != EXPECTED_PYINSTALLER:
        raise RuntimeError("Linux Collector requires exact PyInstaller 6.21.0.")
    if arguments.release_channel != "DEV-UNSIGNED" and arguments.signing_key_file is None:
        raise RuntimeError("Signed channels require an externally mounted private key.")

    project_root = Path(__file__).resolve().parents[1]
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    signer, public_record = _load_signer(
        signing_key_file=arguments.signing_key_file,
        signing_key_id=arguments.signing_key_id,
        project_root=project_root,
        output=output,
    )
    with tempfile.TemporaryDirectory(prefix="secai-linux-build-") as temporary:
        work = Path(temporary)
        trusted_keys = _write_trusted_sidecar_keys(
            arguments.sidecar_signing_key_file,
            work,
        )
        artifacts = {
            distribution: _build_artifact(
                project_root=project_root,
                output=output,
                work=work,
                entrypoint=entrypoint,
                name=name,
                trusted_keys=trusted_keys,
            )
            for distribution, (entrypoint, name) in ARTIFACTS.items()
        }

    sbom, notice, vex = _write_supply_chain_documents(output, project_root=project_root)
    lock = project_root / "requirements" / "lock" / "linux-collector-build.lock"
    manifest = build_linux_release_manifest(
        artifacts=artifacts,
        sbom_path=sbom,
        third_party_notice_path=notice,
        vex_path=vex,
        version=VERSION,
        release_channel=arguments.release_channel,
        source_revision=arguments.source_revision,
        lock_sha256=_sha256(lock),
        lock_path="requirements/lock/linux-collector-build.lock",
        build_image_digest=arguments.build_image_digest,
        created_at=datetime.now(UTC),
        sign=signer,
        dependency_scan=arguments.dependency_scan,
        os_package_scan=arguments.os_package_scan,
        malware_scan=arguments.malware_scan,
    )
    _write_json(output / "linux-collector-release-manifest.json", manifest)
    if public_record is not None:
        _write_json(output / "linux-collector-release-public-key.json", public_record)
    else:
        (output / "DEV-UNSIGNED.txt").write_text(
            "개발용 미서명 artifact입니다. 운영 다운로드로 제공할 수 없습니다.\n",
            encoding="utf-8",
            newline="\n",
        )
    shutil.rmtree(output / "__pycache__", ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
