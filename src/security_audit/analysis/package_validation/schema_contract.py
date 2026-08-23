"""Offline-only JSON Schema validation for untrusted package documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable

from security_audit.common.canonical_json import JsonValue

from .contracts import PackageValidationCode, PackageValidationError


class PackageSchemaCatalog:
    """A closed local registry that never retrieves a remote ``$ref``."""

    def __init__(self, schema_root: Path) -> None:
        self._validators: dict[str, Draft202012Validator] = {}
        try:
            catalog = json.loads((schema_root / "schema-catalog.json").read_text(encoding="utf-8"))
            schemas: dict[str, dict[str, Any]] = {}
            resources: list[tuple[str, Resource[Any]]] = []
            for entry in catalog["schemas"]:
                filename = cast(str, entry["file"])
                schema = cast(
                    dict[str, Any],
                    json.loads((schema_root / filename).read_text(encoding="utf-8")),
                )
                Draft202012Validator.check_schema(schema)
                if schema.get("$id") != entry.get("id"):
                    raise ValueError("Schema catalog ID mismatch.")
                schemas[filename] = schema
                resources.append((cast(str, schema["$id"]), Resource.from_contents(schema)))
            registry = Registry().with_resources(resources)
            self._validators = {
                filename: Draft202012Validator(
                    schema,
                    registry=registry,
                    format_checker=FormatChecker(),
                )
                for filename, schema in schemas.items()
            }
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError, SchemaError) as exc:
            raise PackageValidationError(
                PackageValidationCode.SCHEMA_CATALOG_INVALID,
                "The local Schema catalog is unavailable or invalid.",
            ) from exc

    def validate(
        self,
        instance: JsonValue,
        schema_filename: str,
        error_code: PackageValidationCode,
    ) -> None:
        validator = self._validators.get(schema_filename)
        if validator is None:
            raise PackageValidationError(
                PackageValidationCode.SCHEMA_CATALOG_INVALID,
                "The required local Schema is not registered.",
            )
        try:
            first_error = next(iter(validator.iter_errors(instance)), None)
        except Unresolvable as exc:
            raise PackageValidationError(
                PackageValidationCode.SCHEMA_CATALOG_INVALID,
                "A Schema reference is not present in the local catalog.",
            ) from exc
        if first_error is not None:
            raise PackageValidationError(error_code, "Package document failed its JSON Schema.")
