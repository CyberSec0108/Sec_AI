from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent


def no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicate_object)


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def semantic_errors(schema_file: str, instance: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if schema_file in {
        "collector_manifest.schema.json",
        "linux_collector_manifest.schema.json",
    }:
        if parse_utc(instance["expires_at"]) <= parse_utc(instance["issued_at"]):
            errors.append("expires_at must be later than issued_at")
        probe_ids = [item["probe_id"] for item in instance["probes"]]
        if len(probe_ids) != len(set(probe_ids)):
            errors.append("probe_id must be unique")
    elif schema_file in {
        "audit_package.schema.json",
        "linux_audit_package.schema.json",
    }:
        if parse_utc(instance["expires_at"]) <= parse_utc(instance["issued_at"]):
            errors.append("expires_at must be later than issued_at")
        paths = [item["path"] for item in instance["file_inventory"]]
        if len(paths) != len(set(paths)):
            errors.append("file_inventory path must be unique")
        evidence_ids = [item["evidence_id"] for item in instance["evidence_records"]]
        if len(evidence_ids) != len(set(evidence_ids)):
            errors.append("evidence_id must be unique")
        if instance["archive"]["file_count"] != len(instance["file_inventory"]):
            errors.append("archive.file_count must match file_inventory length")
        inventoried_bytes = sum(
            item["size_bytes"] for item in instance["file_inventory"]
        )
        if instance["archive"]["uncompressed_bytes"] < inventoried_bytes:
            errors.append("archive.uncompressed_bytes cannot be smaller than inventoried files")
        evidence_paths = (
            {item["member_path"] for item in instance["evidence_records"]}
            if schema_file == "linux_audit_package.schema.json"
            else {f"evidence/{evidence_id}.json" for evidence_id in evidence_ids}
        )
        inventory_paths = set(paths)
        if not evidence_paths.issubset(inventory_paths):
            errors.append(
                "every evidence record must have a matching "
                "evidence/<UUID>.json inventory entry"
            )
    elif schema_file == "audit_pack.schema.json":
        control_ids = [item["control_id"] for item in instance["controls"]]
        if len(control_ids) != len(set(control_ids)):
            errors.append("control_id must be unique")
        for control in instance["controls"]:
            requirement_ids = [item["requirement_id"] for item in control["evidence_requirements"]]
            if len(requirement_ids) != len(set(requirement_ids)):
                errors.append(f"{control['control_id']}: requirement_id must be unique")
            for citation in control["citations"]:
                if citation["page_end"] < citation["page_start"]:
                    errors.append(f"{control['control_id']}: citation page range is reversed")
        if instance["approval"]["status"] == "APPROVED":
            expected = {f"PC-{number:02d}" for number in range(1, 19)}
            if set(control_ids) != expected:
                errors.append(
                    "approved MVP Audit Pack must contain PC-01 through PC-18 exactly once"
                )
    elif schema_file == "guide_catalog.schema.json":
        guide_keys = [
            (guide["guide_id"], guide["version"]) for guide in instance["guides"]
        ]
        if len(guide_keys) != len(set(guide_keys)):
            errors.append("guide_id and version must be unique")
        for guide in instance["guides"]:
            for scope in guide["query_scopes"]:
                if scope["pdf_page_end"] < scope["pdf_page_start"]:
                    errors.append(f"{scope['scope_id']}: page range is reversed")
                if scope["pdf_page_end"] > guide["source"]["page_count"]:
                    errors.append(f"{scope['scope_id']}: page range exceeds source")
            license_approved = (
                guide["license_policy"]["status"] == "APPROVED"
                and guide["gates"]["license_review_approved"]
            )
            all_gates = all(guide["gates"].values())
            if guide["status"] == "APPROVED" and not (license_approved and all_gates):
                errors.append(
                    f"{guide['guide_id']}: APPROVED requires all source, "
                    "license and retrieval gates"
                )
            if guide["status"] != "APPROVED" and any(
                scope["default_enabled"] for scope in guide["query_scopes"]
            ):
                errors.append(
                    f"{guide['guide_id']}: non-approved guide cannot be default enabled"
                )
            if guide["audit_pack_activation_allowed"]:
                errors.append(
                    f"{guide['guide_id']}: Guide Catalog cannot activate an Audit Pack"
                )
    elif schema_file == "guide_page_map.schema.json":
        pages = instance["pages"]
        numbers = [page["pdf_page_number"] for page in pages]
        expected = list(
            range(instance["pdf_page_start"], instance["pdf_page_end"] + 1)
        )
        if numbers != expected:
            errors.append("page map must be ordered, unique and contiguous")
        if any(page["pdf_page_index"] != page["pdf_page_number"] - 1 for page in pages):
            errors.append("pdf_page_index must be zero-based pdf_page_number")
        if any(
            page["printed_page_number"] != page["pdf_page_number"] for page in pages
        ):
            errors.append("this page map profile requires printed and PDF pages to match")
        if instance["pdf_page_end"] > instance["source_page_count"]:
            errors.append("page map exceeds source_page_count")
    elif schema_file == "control_source_mapping.schema.json":
        control_ids = [item["control_id"] for item in instance["mappings"]]
        if len(control_ids) != len(set(control_ids)):
            errors.append("control_id must be unique")
        if any(
            item["page_end"] < item["page_start"] for item in instance["mappings"]
        ):
            errors.append("mapping page range is reversed")
        if instance["runtime_activation_allowed"]:
            errors.append("Control Source Mapping cannot directly activate runtime rules")
    elif schema_file == "guide_ingest_manifest.schema.json":
        gates = instance["gates"]
        required_gates = (
            "source_hash_verified",
            "page_map_verified",
            "license_approved",
            "derivative_text_storage_allowed",
            "malware_scan_passed",
            "extraction_quality_approved",
            "query_scope_enabled",
        )
        if instance["status"] == "READY" and not all(
            gates[name] for name in required_gates
        ):
            errors.append("READY guide ingest requires every approval gate")
        if gates["synthetic_test_only"] != (
            instance["classification"] == "SYNTHETIC_DEV_ONLY"
        ):
            errors.append("synthetic gate and classification must match")
    elif schema_file == "guide_search_result.schema.json":
        hits = instance["hits"]
        chunk_ids = [hit["chunk_id"] for hit in hits]
        if len(chunk_ids) != len(set(chunk_ids)):
            errors.append("guide search chunk_id must be unique")
        if instance["status"] == "FOUND" and not hits:
            errors.append("FOUND guide search requires at least one hit")
        if instance["status"] != "FOUND" and hits:
            errors.append("non-FOUND guide search cannot contain hits")
        if any(
            hit["guide_id"] != instance["guide"]["guide_id"]
            or hit["guide_version"] != instance["guide"]["version"]
            or hit["scope_id"] != instance["scope_id"]
            for hit in hits
        ):
            errors.append("guide search hits must match the authorized scope")
    elif schema_file == "guide_question_evaluation.schema.json":
        cases = instance["cases"]
        case_ids = [case["case_id"] for case in cases]
        if len(case_ids) != len(set(case_ids)):
            errors.append("guide evaluation case_id must be unique")
        supported = [
            case for case in cases if case["expected_status"] == "FOUND"
        ]
        controls = {case["expected_control_id"] for case in supported}
        expected_controls = {f"PC-{number:02d}" for number in range(1, 19)}
        if controls != expected_controls:
            errors.append("guide evaluation must cover PC-01 through PC-18")
        for case in supported:
            if case["expected_page_end"] < case["expected_page_start"]:
                errors.append(f"{case['case_id']}: page range is reversed")
        negative_count = sum(
            case["expected_status"] == "NO_EVIDENCE" for case in cases
        )
        if negative_count < 4:
            errors.append("guide evaluation requires at least four no-evidence cases")
    return errors


def main() -> int:
    catalog = load_json(ROOT / "schema-catalog.json")
    schemas: dict[str, dict[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    failures: list[str] = []

    for entry in catalog["schemas"]:
        schema = load_json(ROOT / entry["file"])
        Draft202012Validator.check_schema(schema)
        if schema["$id"] != entry["id"]:
            failures.append(f"{entry['file']}: catalog id mismatch")
        schemas[entry["file"]] = schema
        resources.append((schema["$id"], Resource.from_contents(schema)))

    registry = Registry().with_resources(resources)
    examples = load_json(ROOT / "examples" / "index.json")

    for entry in examples["examples"]:
        instance = load_json(ROOT / "examples" / entry["file"])
        validator = Draft202012Validator(
            schemas[entry["schema"]],
            registry=registry,
            format_checker=FormatChecker(),
        )
        validation_errors = sorted(
            validator.iter_errors(instance),
            key=lambda error: list(error.path),
        )
        semantic = [] if validation_errors else semantic_errors(entry["schema"], instance)
        accepted = not validation_errors and not semantic
        if accepted != entry["valid"]:
            details = [error.message for error in validation_errors[:3]] + semantic[:3]
            failures.append(f"{entry['file']}: expected valid={entry['valid']}, details={details}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(f"PASS: {len(schemas)} schemas and {len(examples['examples'])} examples validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
