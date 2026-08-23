"""Fail-closed ZIP preflight and descriptor comparison for Sec_AI packages."""

from __future__ import annotations

import re
import stat
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import Never, cast
from zipfile import (
    ZIP_DEFLATED,
    ZIP_STORED,
    BadZipFile,
    LargeZipFile,
    ZipFile,
    ZipInfo,
)

from security_audit.common.canonical_json import JsonValue, canonical_sha256

from .contracts import (
    PackageFileRecord,
    PackageInspection,
    PackageLimits,
    PackageValidationCode,
    PackageValidationError,
)
from .strict_json import load_strict_json

_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SAFE_MEMBER_PATTERN = re.compile(
    r"^(?:collector_manifest\.json|(?:evidence|errors)/[0-9a-fA-F-]{36}\.json)$"
)
_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:")
_NESTED_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz")
_ALLOWED_COMPRESSION = frozenset({ZIP_STORED, ZIP_DEFLATED})
_CHUNK_SIZE = 64 * 1024


def _reject(
    code: PackageValidationCode,
    message: str,
    *,
    member_path: str | None = None,
) -> Never:
    raise PackageValidationError(code, message, member_path=member_path)


def _validate_member_path(path: str, limits: PackageLimits) -> None:
    if len(path) > limits.max_path_length or "\x00" in path:
        _reject(PackageValidationCode.PATH_INVALID, "Archive member path is invalid.")
    if path.startswith(("/", "\\")) or _DRIVE_PATTERN.match(path):
        _reject(PackageValidationCode.PATH_TRAVERSAL, "Absolute archive paths are forbidden.")
    if "\\" in path:
        _reject(PackageValidationCode.PATH_INVALID, "Backslashes are forbidden in archive paths.")
    segments = path.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        _reject(PackageValidationCode.PATH_TRAVERSAL, "Archive path traversal is forbidden.")
    if path.casefold().endswith(_NESTED_ARCHIVE_SUFFIXES):
        _reject(
            PackageValidationCode.NESTED_ARCHIVE,
            "Nested archives are forbidden.",
            member_path=path,
        )
    if _SAFE_MEMBER_PATTERN.fullmatch(path) is None:
        _reject(
            PackageValidationCode.PATH_INVALID,
            "Archive member is outside the approved package layout.",
            member_path=path,
        )


def _validate_member_type(info: ZipInfo) -> None:
    if info.is_dir():
        _reject(
            PackageValidationCode.DIRECTORY_ENTRY,
            "Explicit directory entries are forbidden.",
            member_path=info.filename,
        )
    unix_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    if file_type == stat.S_IFLNK:
        _reject(
            PackageValidationCode.SYMLINK_ENTRY,
            "Symbolic links are forbidden.",
            member_path=info.filename,
        )
    dos_attributes = info.external_attr & 0xFFFF
    if dos_attributes & 0x400:
        _reject(
            PackageValidationCode.REPARSE_POINT,
            "Windows reparse-point entries are forbidden.",
            member_path=info.filename,
        )
    if file_type not in {0, stat.S_IFREG}:
        _reject(
            PackageValidationCode.SPECIAL_FILE_ENTRY,
            "Special files are forbidden.",
            member_path=info.filename,
        )


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _read_member(
    archive: ZipFile,
    info: ZipInfo,
    limits: PackageLimits,
    total_before: int,
) -> tuple[bytes, int]:
    content = bytearray()
    measured = 0
    try:
        with archive.open(info, "r") as stream:
            while chunk := stream.read(_CHUNK_SIZE):
                measured += len(chunk)
                if measured > limits.max_member_bytes:
                    _reject(
                        PackageValidationCode.FILE_TOO_LARGE,
                        "Archive member exceeded its extraction limit.",
                        member_path=info.filename,
                    )
                if total_before + measured > limits.max_uncompressed_bytes:
                    _reject(
                        PackageValidationCode.TOTAL_SIZE_EXCEEDED,
                        "Archive exceeded its total extraction limit.",
                        member_path=info.filename,
                    )
                content.extend(chunk)
    except PackageValidationError:
        raise
    except (BadZipFile, EOFError, OSError, RuntimeError) as exc:
        raise PackageValidationError(
            PackageValidationCode.MEMBER_READ_ERROR,
            "Archive member could not be read safely.",
            member_path=info.filename,
        ) from exc
    if measured != info.file_size:
        _reject(
            PackageValidationCode.MEMBER_SIZE_MISMATCH,
            "Archive member size metadata does not match extracted bytes.",
            member_path=info.filename,
        )
    return bytes(content), measured


def inspect_package_archive(
    archive_path: Path,
    *,
    limits: PackageLimits | None = None,
) -> PackageInspection:
    """Inspect a ZIP without writing any member to the filesystem."""

    active_limits = limits or PackageLimits()
    if not archive_path.is_file():
        _reject(PackageValidationCode.ARCHIVE_NOT_FILE, "Package archive is not a regular file.")
    archive_size = archive_path.stat().st_size
    if archive_size == 0:
        _reject(PackageValidationCode.ARCHIVE_EMPTY, "Package archive is empty.")
    if archive_size > active_limits.max_archive_bytes:
        _reject(PackageValidationCode.ARCHIVE_TOO_LARGE, "Package archive is too large.")

    try:
        with ZipFile(archive_path, "r", allowZip64=False) as archive:
            infos = archive.infolist()
            if not active_limits.min_files <= len(infos) <= active_limits.max_files:
                _reject(
                    PackageValidationCode.FILE_COUNT_OUT_OF_RANGE,
                    "Package file count is outside the approved range.",
                )

            seen: set[str] = set()
            seen_folded: set[str] = set()
            seen_offsets: set[int] = set()
            metadata_total = 0
            compressed_total = 0
            for info in infos:
                _validate_member_type(info)
                _validate_member_path(info.filename, active_limits)
                if info.header_offset in seen_offsets:
                    _reject(
                        PackageValidationCode.OVERLAPPING_ENTRY,
                        "Multiple members may not reference the same local ZIP header.",
                        member_path=info.filename,
                    )
                seen_offsets.add(info.header_offset)
                if info.filename in seen:
                    _reject(
                        PackageValidationCode.DUPLICATE_PATH,
                        "Duplicate archive member path is forbidden.",
                        member_path=info.filename,
                    )
                folded = info.filename.casefold()
                if folded in seen_folded:
                    _reject(
                        PackageValidationCode.CASE_COLLISION,
                        "Case-colliding archive member paths are forbidden.",
                        member_path=info.filename,
                    )
                seen.add(info.filename)
                seen_folded.add(folded)
                if info.flag_bits & 0x1:
                    _reject(
                        PackageValidationCode.ENCRYPTED_ENTRY,
                        "Encrypted ZIP members are forbidden.",
                        member_path=info.filename,
                    )
                if info.compress_type not in _ALLOWED_COMPRESSION:
                    _reject(
                        PackageValidationCode.UNSUPPORTED_COMPRESSION,
                        "Only ZIP stored and deflate methods are allowed.",
                        member_path=info.filename,
                    )
                if info.file_size < 2:
                    _reject(
                        PackageValidationCode.FILE_TOO_SMALL,
                        "Package JSON member is too small.",
                        member_path=info.filename,
                    )
                if info.file_size > active_limits.max_member_bytes:
                    _reject(
                        PackageValidationCode.FILE_TOO_LARGE,
                        "Package member is too large.",
                        member_path=info.filename,
                    )
                metadata_total += info.file_size
                compressed_total += info.compress_size
                if metadata_total > active_limits.max_uncompressed_bytes:
                    _reject(
                        PackageValidationCode.TOTAL_SIZE_EXCEEDED,
                        "Package metadata exceeds the total extraction limit.",
                    )
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > active_limits.max_compression_ratio:
                    _reject(
                        PackageValidationCode.COMPRESSION_RATIO_EXCEEDED,
                        "Archive member compression ratio exceeds the approved limit.",
                        member_path=info.filename,
                    )

            if "collector_manifest.json" not in seen:
                _reject(
                    PackageValidationCode.REQUIRED_MANIFEST_MISSING,
                    "collector_manifest.json is required.",
                )
            aggregate_ratio = metadata_total / max(compressed_total, 1)
            if aggregate_ratio > active_limits.max_compression_ratio:
                _reject(
                    PackageValidationCode.COMPRESSION_RATIO_EXCEEDED,
                    "Aggregate compression ratio exceeds the approved limit.",
                )

            records: list[PackageFileRecord] = []
            measured_total = 0
            for info in infos:
                member_bytes, measured = _read_member(
                    archive,
                    info,
                    active_limits,
                    measured_total,
                )
                measured_total += measured
                try:
                    load_strict_json(member_bytes)
                except PackageValidationError as exc:
                    if exc.member_path is None:
                        exc.member_path = info.filename
                    raise
                records.append(
                    PackageFileRecord(
                        path=info.filename,
                        size_bytes=measured,
                        sha256=sha256(member_bytes).hexdigest(),
                    )
                )
    except PackageValidationError:
        raise
    except (BadZipFile, LargeZipFile, OSError, ValueError) as exc:
        raise PackageValidationError(
            PackageValidationCode.ARCHIVE_INVALID,
            "Input is not an approved ZIP archive.",
        ) from exc

    sorted_records = tuple(sorted(records, key=lambda record: record.path))
    evidence_records = tuple(
        record for record in sorted_records if record.path != "collector_manifest.json"
    )
    content_vector: list[JsonValue] = [
        {
            "evidence_id": record.path.rsplit("/", 1)[-1].removesuffix(".json"),
            "evidence_sha256": record.sha256,
        }
        for record in sorted(
            evidence_records,
            key=lambda record: record.path.rsplit("/", 1)[-1],
        )
    ]
    return PackageInspection(
        archive_sha256=_sha256_file(archive_path),
        content_set_sha256=canonical_sha256(content_vector),
        compressed_bytes=archive_size,
        uncompressed_bytes=sum(record.size_bytes for record in sorted_records),
        file_count=len(sorted_records),
        files=sorted_records,
    )


def _required_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(PackageValidationCode.INVENTORY_INVALID, "Descriptor object is missing or invalid.")
    return cast(Mapping[str, object], value)


def _required_sequence(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        _reject(PackageValidationCode.INVENTORY_INVALID, "Descriptor inventory is invalid.")
    return cast(Sequence[object], value)


def _required_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        _reject(PackageValidationCode.INVENTORY_INVALID, f"Descriptor field {key} is invalid.")
    return value


def _required_hash(mapping: Mapping[str, object], key: str) -> str:
    value = _required_string(mapping, key)
    if _HASH_PATTERN.fullmatch(value) is None:
        _reject(PackageValidationCode.INVENTORY_INVALID, f"Descriptor hash {key} is invalid.")
    return value


def _required_integer(mapping: Mapping[str, object], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _reject(PackageValidationCode.INVENTORY_INVALID, f"Descriptor field {key} is invalid.")
    return value


def validate_package_contract(
    archive_path: Path,
    descriptor: Mapping[str, object],
    *,
    limits: PackageLimits | None = None,
) -> PackageInspection:
    """Inspect an archive and compare every measured fact to its descriptor."""

    active_limits = limits or PackageLimits()
    inspection = inspect_package_archive(archive_path, limits=active_limits)
    archive_fields = _required_mapping(descriptor.get("archive"))
    inventory = _required_sequence(descriptor.get("file_inventory"))

    expected_records: dict[str, tuple[int, str]] = {}
    folded_paths: set[str] = set()
    for raw_entry in inventory:
        entry = _required_mapping(raw_entry)
        path = _required_string(entry, "path")
        _validate_member_path(path, active_limits)
        if path in expected_records:
            _reject(PackageValidationCode.DUPLICATE_PATH, "Inventory path is duplicated.")
        if path.casefold() in folded_paths:
            _reject(PackageValidationCode.CASE_COLLISION, "Inventory paths collide by case.")
        folded_paths.add(path.casefold())
        expected_records[path] = (
            _required_integer(entry, "size_bytes"),
            _required_hash(entry, "sha256"),
        )

    actual_records = {record.path: record for record in inspection.files}
    missing = sorted(set(expected_records) - set(actual_records))
    if missing:
        _reject(
            PackageValidationCode.FILE_MISSING,
            "A descriptor-declared file is missing from the archive.",
            member_path=missing[0],
        )
    undeclared = sorted(set(actual_records) - set(expected_records))
    if undeclared:
        _reject(
            PackageValidationCode.UNDECLARED_FILE,
            "The archive contains a file not declared by the descriptor.",
            member_path=undeclared[0],
        )
    for path, (expected_size, expected_hash) in expected_records.items():
        actual = actual_records[path]
        if actual.size_bytes != expected_size:
            _reject(
                PackageValidationCode.SIZE_MISMATCH,
                "Archive member size differs from the descriptor.",
                member_path=path,
            )
        if actual.sha256 != expected_hash:
            _reject(
                PackageValidationCode.HASH_MISMATCH,
                "Archive member hash differs from the descriptor.",
                member_path=path,
            )

    comparisons = (
        (
            inspection.archive_sha256,
            _required_hash(archive_fields, "archive_sha256"),
            PackageValidationCode.ARCHIVE_HASH_MISMATCH,
        ),
        (
            inspection.content_set_sha256,
            _required_hash(archive_fields, "content_set_sha256"),
            PackageValidationCode.CONTENT_SET_HASH_MISMATCH,
        ),
        (
            inspection.compressed_bytes,
            _required_integer(archive_fields, "compressed_bytes"),
            PackageValidationCode.ARCHIVE_SIZE_MISMATCH,
        ),
        (
            inspection.uncompressed_bytes,
            _required_integer(archive_fields, "uncompressed_bytes"),
            PackageValidationCode.UNCOMPRESSED_SIZE_MISMATCH,
        ),
        (
            inspection.file_count,
            _required_integer(archive_fields, "file_count"),
            PackageValidationCode.FILE_COUNT_MISMATCH,
        ),
    )
    for actual_value, expected_value, error_code in comparisons:
        if actual_value != expected_value:
            _reject(error_code, "Measured archive metadata differs from the descriptor.")
    return inspection
