from __future__ import annotations

import json
import stat
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from zipfile import ZIP_BZIP2, ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

import pytest

from security_audit.analysis.package_validation import (
    PackageInspection,
    PackageLimits,
    PackageValidationCode,
    PackageValidationError,
    inspect_package_archive,
    load_strict_json,
    validate_package_contract,
)

MANIFEST_PATH = "collector_manifest.json"
EVIDENCE_PATH = "evidence/aaaaaaaa-0000-4000-8000-000000000001.json"
SECOND_EVIDENCE_PATH = "evidence/bbbbbbbb-0000-4000-8000-000000000002.json"
MANIFEST_BYTES = b'{"kind":"manifest","schema_version":"1.0.0"}'
EVIDENCE_BYTES = b'{"control_id":"PC-07","filesystem":"NTFS"}'


def _write_archive(
    path: Path,
    members: Iterable[tuple[str | ZipInfo, bytes]],
    *,
    compression: int = ZIP_DEFLATED,
) -> Path:
    with ZipFile(path, "w", compression=compression) as archive:
        for name, content in members:
            archive.writestr(name, content)
    return path


def _normal_archive(tmp_path: Path) -> Path:
    return _write_archive(
        tmp_path / "normal.zip",
        [(MANIFEST_PATH, MANIFEST_BYTES), (EVIDENCE_PATH, EVIDENCE_BYTES)],
    )


def _descriptor(inspection: PackageInspection) -> dict[str, object]:
    return {
        "archive": {
            "format": "ZIP-STORED-OR-DEFLATE",
            "archive_sha256": inspection.archive_sha256,
            "content_set_sha256": inspection.content_set_sha256,
            "compressed_bytes": inspection.compressed_bytes,
            "uncompressed_bytes": inspection.uncompressed_bytes,
            "file_count": inspection.file_count,
        },
        "file_inventory": [
            {
                "path": record.path,
                "media_type": "application/json",
                "size_bytes": record.size_bytes,
                "sha256": record.sha256,
            }
            for record in inspection.files
        ],
    }


def _expect_code(
    expected: PackageValidationCode,
    callable_: Any,
    *args: object,
    **kwargs: object,
) -> PackageValidationError:
    with pytest.raises(PackageValidationError) as captured:
        callable_(*args, **kwargs)
    assert captured.value.code is expected
    return captured.value


def test_strict_json_rejects_duplicate_property() -> None:
    _expect_code(
        PackageValidationCode.DUPLICATE_JSON_KEY,
        load_strict_json,
        b'{"status":"PASS","status":"FAIL"}',
    )


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"\xef\xbb\xbf{}", PackageValidationCode.JSON_BOM_NOT_ALLOWED),
        (b'{"value":"\xff"}', PackageValidationCode.JSON_ENCODING_INVALID),
        (b'{"value":NaN}', PackageValidationCode.JSON_NUMBER_INVALID),
        (b'{"value":1e999}', PackageValidationCode.JSON_NUMBER_INVALID),
        (b'{"value":9007199254740992}', PackageValidationCode.JSON_NUMBER_INVALID),
        (b"[]", PackageValidationCode.JSON_TOP_LEVEL_INVALID),
    ],
)
def test_strict_json_rejects_ambiguous_documents(
    payload: bytes,
    expected: PackageValidationCode,
) -> None:
    _expect_code(expected, load_strict_json, payload)


def test_valid_package_matches_every_descriptor_fact(tmp_path: Path) -> None:
    archive_path = _normal_archive(tmp_path)
    inspection = inspect_package_archive(archive_path)

    validated = validate_package_contract(archive_path, _descriptor(inspection))

    assert validated == inspection
    assert validated.file_count == 2
    assert [record.path for record in validated.files] == [MANIFEST_PATH, EVIDENCE_PATH]


def test_content_set_hash_uses_evidence_id_and_hash_but_not_manifest_hash(
    tmp_path: Path,
) -> None:
    first_path = _normal_archive(tmp_path)
    first = inspect_package_archive(first_path)
    second_path = _write_archive(
        tmp_path / "changed-manifest.zip",
        [(MANIFEST_PATH, b'{"kind":"changed"}'), (EVIDENCE_PATH, EVIDENCE_BYTES)],
    )
    second = inspect_package_archive(second_path)

    assert first.archive_sha256 != second.archive_sha256
    assert first.content_set_sha256 == second.content_set_sha256


def test_invalid_zip_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "invalid.zip"
    archive_path.write_bytes(b"not-a-zip")

    _expect_code(PackageValidationCode.ARCHIVE_INVALID, inspect_package_archive, archive_path)


def test_archive_byte_limit_is_enforced_before_zip_parsing(tmp_path: Path) -> None:
    archive_path = _normal_archive(tmp_path)
    limits = PackageLimits(max_archive_bytes=archive_path.stat().st_size - 1)

    _expect_code(
        PackageValidationCode.ARCHIVE_TOO_LARGE,
        inspect_package_archive,
        archive_path,
        limits=limits,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_archive_bytes": (100 * 1024 * 1024) + 1},
        {"max_uncompressed_bytes": (500 * 1024 * 1024) + 1},
        {"max_files": 1025},
        {"max_member_bytes": (1024 * 1024) + 1},
        {"max_path_length": 241},
        {"max_compression_ratio": 100.1},
        {"min_files": 1},
    ],
)
def test_caller_cannot_expand_or_weaken_absolute_server_limits(
    overrides: Mapping[str, int | float],
) -> None:
    with pytest.raises(ValueError):
        PackageLimits(**overrides)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../evidence/aaaaaaaa-0000-4000-8000-000000000001.json",
        "/evidence/aaaaaaaa-0000-4000-8000-000000000001.json",
        "C:/evidence/aaaaaaaa-0000-4000-8000-000000000001.json",
    ],
)
def test_path_traversal_and_absolute_paths_are_rejected(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    archive_path = _write_archive(
        tmp_path / "traversal.zip",
        [(MANIFEST_PATH, MANIFEST_BYTES), (unsafe_path, EVIDENCE_BYTES)],
    )

    _expect_code(PackageValidationCode.PATH_TRAVERSAL, inspect_package_archive, archive_path)


def test_backslash_path_is_rejected(tmp_path: Path) -> None:
    archive_path = _write_archive(
        tmp_path / "backslash.zip",
        [
            (MANIFEST_PATH, MANIFEST_BYTES),
            (r"evidence\aaaaaaaa-0000-4000-8000-000000000001.json", EVIDENCE_BYTES),
        ],
    )

    _expect_code(PackageValidationCode.PATH_INVALID, inspect_package_archive, archive_path)


def test_nested_archive_is_rejected(tmp_path: Path) -> None:
    archive_path = _write_archive(
        tmp_path / "nested.zip",
        [(MANIFEST_PATH, MANIFEST_BYTES), ("evidence/nested.zip", b"PK\x03\x04")],
    )

    _expect_code(PackageValidationCode.NESTED_ARCHIVE, inspect_package_archive, archive_path)


def test_duplicate_member_path_is_rejected(tmp_path: Path) -> None:
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive_path = _write_archive(
            tmp_path / "duplicate.zip",
            [
                (MANIFEST_PATH, MANIFEST_BYTES),
                (EVIDENCE_PATH, EVIDENCE_BYTES),
                (EVIDENCE_PATH, EVIDENCE_BYTES),
            ],
        )

    _expect_code(PackageValidationCode.DUPLICATE_PATH, inspect_package_archive, archive_path)


def test_case_colliding_member_path_is_rejected(tmp_path: Path) -> None:
    archive_path = _write_archive(
        tmp_path / "case-collision.zip",
        [
            (MANIFEST_PATH, MANIFEST_BYTES),
            (EVIDENCE_PATH, EVIDENCE_BYTES),
            (EVIDENCE_PATH.replace("aaaaaaaa", "AAAAAAAA"), EVIDENCE_BYTES),
        ],
    )

    _expect_code(PackageValidationCode.CASE_COLLISION, inspect_package_archive, archive_path)


def test_explicit_directory_entry_is_rejected(tmp_path: Path) -> None:
    directory = ZipInfo("evidence/")
    directory.external_attr = (stat.S_IFDIR | 0o755) << 16
    archive_path = _write_archive(
        tmp_path / "directory.zip",
        [(directory, b""), (MANIFEST_PATH, MANIFEST_BYTES)],
        compression=ZIP_STORED,
    )

    _expect_code(PackageValidationCode.DIRECTORY_ENTRY, inspect_package_archive, archive_path)


def test_symbolic_link_entry_is_rejected(tmp_path: Path) -> None:
    symlink = ZipInfo(EVIDENCE_PATH)
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    archive_path = _write_archive(
        tmp_path / "symlink.zip",
        [(MANIFEST_PATH, MANIFEST_BYTES), (symlink, b"target")],
        compression=ZIP_STORED,
    )

    _expect_code(PackageValidationCode.SYMLINK_ENTRY, inspect_package_archive, archive_path)


def test_windows_reparse_point_entry_is_rejected(tmp_path: Path) -> None:
    reparse_point = ZipInfo(EVIDENCE_PATH)
    reparse_point.create_system = 0
    reparse_point.external_attr = 0x400
    archive_path = _write_archive(
        tmp_path / "reparse-point.zip",
        [(MANIFEST_PATH, MANIFEST_BYTES), (reparse_point, EVIDENCE_BYTES)],
        compression=ZIP_STORED,
    )

    _expect_code(PackageValidationCode.REPARSE_POINT, inspect_package_archive, archive_path)


def test_unsupported_zip_compression_is_rejected(tmp_path: Path) -> None:
    archive_path = _write_archive(
        tmp_path / "bzip2.zip",
        [(MANIFEST_PATH, MANIFEST_BYTES), (EVIDENCE_PATH, EVIDENCE_BYTES)],
        compression=ZIP_BZIP2,
    )

    _expect_code(
        PackageValidationCode.UNSUPPORTED_COMPRESSION,
        inspect_package_archive,
        archive_path,
    )


def test_encrypted_zip_flag_is_rejected_before_member_read(tmp_path: Path) -> None:
    archive_path = _normal_archive(tmp_path)
    raw = bytearray(archive_path.read_bytes())
    central_header = raw.find(b"PK\x01\x02")
    assert central_header >= 0
    flag_offset = central_header + 8
    flag = int.from_bytes(raw[flag_offset : flag_offset + 2], "little") | 0x1
    raw[flag_offset : flag_offset + 2] = flag.to_bytes(2, "little")
    archive_path.write_bytes(raw)

    _expect_code(PackageValidationCode.ENCRYPTED_ENTRY, inspect_package_archive, archive_path)


def test_high_compression_ratio_is_rejected_before_member_read(tmp_path: Path) -> None:
    compressed_json = b'{"value":"' + (b"A" * 200_000) + b'"}'
    archive_path = _write_archive(
        tmp_path / "compression-bomb.zip",
        [(MANIFEST_PATH, MANIFEST_BYTES), (EVIDENCE_PATH, compressed_json)],
    )

    _expect_code(
        PackageValidationCode.COMPRESSION_RATIO_EXCEEDED,
        inspect_package_archive,
        archive_path,
    )


def test_file_count_limit_is_enforced(tmp_path: Path) -> None:
    archive_path = _write_archive(
        tmp_path / "too-many.zip",
        [
            (MANIFEST_PATH, MANIFEST_BYTES),
            (EVIDENCE_PATH, EVIDENCE_BYTES),
            (SECOND_EVIDENCE_PATH, EVIDENCE_BYTES),
        ],
    )

    _expect_code(
        PackageValidationCode.FILE_COUNT_OUT_OF_RANGE,
        inspect_package_archive,
        archive_path,
        limits=PackageLimits(max_files=2),
    )


def test_required_manifest_is_enforced(tmp_path: Path) -> None:
    archive_path = _write_archive(
        tmp_path / "no-manifest.zip",
        [(EVIDENCE_PATH, EVIDENCE_BYTES), (SECOND_EVIDENCE_PATH, EVIDENCE_BYTES)],
    )

    _expect_code(
        PackageValidationCode.REQUIRED_MANIFEST_MISSING,
        inspect_package_archive,
        archive_path,
    )


def test_duplicate_json_property_inside_member_is_rejected(tmp_path: Path) -> None:
    archive_path = _write_archive(
        tmp_path / "duplicate-json-key.zip",
        [(MANIFEST_PATH, MANIFEST_BYTES), (EVIDENCE_PATH, b'{"value":1,"value":2}')],
    )

    error = _expect_code(
        PackageValidationCode.DUPLICATE_JSON_KEY,
        inspect_package_archive,
        archive_path,
    )
    assert error.member_path == EVIDENCE_PATH


def test_declared_member_hash_mismatch_is_rejected(tmp_path: Path) -> None:
    archive_path = _normal_archive(tmp_path)
    descriptor = _descriptor(inspect_package_archive(archive_path))
    inventory = descriptor["file_inventory"]
    assert isinstance(inventory, list)
    evidence = next(item for item in inventory if item["path"] == EVIDENCE_PATH)
    evidence["sha256"] = "0" * 64

    _expect_code(
        PackageValidationCode.HASH_MISMATCH,
        validate_package_contract,
        archive_path,
        descriptor,
    )


def test_undeclared_archive_member_is_rejected(tmp_path: Path) -> None:
    archive_path = _normal_archive(tmp_path)
    descriptor = _descriptor(inspect_package_archive(archive_path))
    inventory = descriptor["file_inventory"]
    assert isinstance(inventory, list)
    descriptor["file_inventory"] = [
        entry
        for entry in inventory
        if entry["path"] == MANIFEST_PATH
    ]

    _expect_code(
        PackageValidationCode.UNDECLARED_FILE,
        validate_package_contract,
        archive_path,
        descriptor,
    )


def test_descriptor_declared_missing_member_is_rejected(tmp_path: Path) -> None:
    archive_path = _normal_archive(tmp_path)
    descriptor = _descriptor(inspect_package_archive(archive_path))
    inventory = descriptor["file_inventory"]
    assert isinstance(inventory, list)
    inventory.append(
        {
            "path": SECOND_EVIDENCE_PATH,
            "media_type": "application/json",
            "size_bytes": 2,
            "sha256": "0" * 64,
        }
    )

    _expect_code(
        PackageValidationCode.FILE_MISSING,
        validate_package_contract,
        archive_path,
        descriptor,
    )


@pytest.mark.parametrize(
    ("field", "replacement", "expected"),
    [
        ("archive_sha256", "0" * 64, PackageValidationCode.ARCHIVE_HASH_MISMATCH),
        ("content_set_sha256", "0" * 64, PackageValidationCode.CONTENT_SET_HASH_MISMATCH),
        ("compressed_bytes", 1, PackageValidationCode.ARCHIVE_SIZE_MISMATCH),
        ("uncompressed_bytes", 1, PackageValidationCode.UNCOMPRESSED_SIZE_MISMATCH),
        ("file_count", 999, PackageValidationCode.FILE_COUNT_MISMATCH),
    ],
)
def test_descriptor_archive_fact_mismatch_is_rejected(
    tmp_path: Path,
    field: str,
    replacement: object,
    expected: PackageValidationCode,
) -> None:
    archive_path = _normal_archive(tmp_path)
    descriptor = _descriptor(inspect_package_archive(archive_path))
    archive_fields = descriptor["archive"]
    assert isinstance(archive_fields, dict)
    archive_fields[field] = replacement

    _expect_code(expected, validate_package_contract, archive_path, descriptor)


def test_fixture_catalog_uses_unique_stable_error_codes() -> None:
    project_root = Path(__file__).resolve().parents[2]
    fixture_path = project_root / "tests" / "fixtures" / "packages" / "imp009_cases.json"
    catalog = json.loads(fixture_path.read_text(encoding="utf-8"))
    cases: list[Mapping[str, str]] = catalog["rejection_cases"]
    codes = [case["expected_code"] for case in cases]

    assert len(codes) == len(set(codes))
    assert all(code in PackageValidationCode for code in codes)
