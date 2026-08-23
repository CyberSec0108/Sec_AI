from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_catalog_registers_thirty_local_schemas() -> None:
    catalog = _load_json(SCHEMA_ROOT / "schema-catalog.json")
    schemas = catalog["schemas"]

    assert len(schemas) == 30
    assert len({entry["id"] for entry in schemas}) == len(schemas)
    assert all((SCHEMA_ROOT / entry["file"]).is_file() for entry in schemas)


def test_catalog_ids_match_schema_ids() -> None:
    catalog = _load_json(SCHEMA_ROOT / "schema-catalog.json")

    for entry in catalog["schemas"]:
        schema = _load_json(SCHEMA_ROOT / entry["file"])
        assert schema["$id"] == entry["id"]
