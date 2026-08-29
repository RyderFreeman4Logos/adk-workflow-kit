#!/usr/bin/env python3
"""Validate the ADK-Rust pattern catalog without third-party tooling."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "docs/architecture/adk-rust-pattern-catalog.json"
SCHEMA_PATH = ROOT / "docs/architecture/adk-rust-pattern-catalog.schema.json"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
LINK_RE = re.compile(
    r"^https://github\.com/([^/]+/[^/]+)/(?:blob|raw)/([0-9a-f]{40})/(.+)$"
)
CLASSES = {"adopt", "wrap", "adapt", "research", "reject"}


class CatalogError(ValueError):
    """A catalog or schema contract is invalid."""


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def _schema_error(path: str, message: str) -> CatalogError:
    return CatalogError(f"{path}: {message}")


def validate_schema(value: Any, schema: dict[str, Any], path: str = "$", root: dict[str, Any] | None = None) -> None:
    """Validate the JSON Schema subset used by this repository's catalog."""
    root = root or schema
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise _schema_error(path, f"unsupported reference {ref!r}")
        validate_schema(value, root["$defs"][ref.removeprefix("#/$defs/")], path, root)
        return
    if "type" in schema and not _type_matches(value, schema["type"]):
        raise _schema_error(path, f"expected {schema['type']}")
    if "const" in schema and value != schema["const"]:
        raise _schema_error(path, f"expected {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise _schema_error(path, f"expected one of {schema['enum']!r}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise _schema_error(path, "is too short")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise _schema_error(path, f"does not match {schema['pattern']!r}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise _schema_error(path, "has too few items")
        if "items" in schema:
            for index, item in enumerate(value):
                validate_schema(item, schema["items"], f"{path}[{index}]", root)
    if isinstance(value, dict):
        required = set(schema.get("required", []))
        missing = required - value.keys()
        if missing:
            raise _schema_error(path, f"missing {sorted(missing)!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unknown = set(value) - properties.keys()
            if unknown:
                raise _schema_error(path, f"unknown properties {sorted(unknown)!r}")
        for key, subschema in properties.items():
            if key in value:
                validate_schema(value[key], subschema, f"{path}.{key}", root)


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"{path}: {exc}") from exc


def _validate_record(record: dict[str, Any], official: bool, expected_commit: str) -> None:
    if not COMMIT_RE.fullmatch(record["commit"]):
        raise CatalogError(f"{record['id']}: commit is not a full lowercase SHA")
    if record["class"] not in CLASSES:
        raise CatalogError(f"{record['id']}: unknown class")
    if not record["source_paths"] or len(record["source_paths"]) != len(record["source_links"]):
        raise CatalogError(f"{record['id']}: source paths and links must be paired")
    for path, link in zip(record["source_paths"], record["source_links"]):
        if path.startswith("/") or ".." in Path(path).parts:
            raise CatalogError(f"{record['id']}: unsafe source path {path!r}")
        match = LINK_RE.fullmatch(link)
        if not match or match.group(2) != record["commit"] or match.group(3) != path:
            raise CatalogError(f"{record['id']}: source link is not an immutable path link: {link}")
        if official and match.group(1) != "zavora-ai/adk-rust":
            raise CatalogError(f"{record['id']}: official source is not ADK-Rust")
    if record["tests"]["in_repo"] != ["just pattern-catalog-test"]:
        raise CatalogError(f"{record['id']}: unexpected in-repo test command")
    if official:
        if record["version"] != "2.1.0" or record["commit"] != expected_commit:
            raise CatalogError(f"{record['id']}: official record is not pinned to v2.1.0")
        if record["compatibility"] != "adk-rust-2.x":
            raise CatalogError(f"{record['id']}: official compatibility must be adk-rust-2.x")
    elif record["compatibility"] != "version-independent":
        raise CatalogError(f"{record['id']}: third-party evidence must be version-independent")


def _validate_local_dependency_evidence(metadata: dict[str, Any]) -> None:
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    expected_requirement = 'adk-rust = { version = "=2.1.0"'
    if expected_requirement not in manifest:
        raise CatalogError("Cargo.toml does not retain the exact adk-rust = =2.1.0 pin")
    lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
    match = re.search(
        r'(?ms)^\[\[package\]\]\nname = "adk-rust"\n(.*?)(?=^\[\[package\]\]|\Z)',
        lock,
    )
    if not match:
        raise CatalogError("Cargo.lock has no adk-rust package record")
    lock_record = match.group(0)
    evidence = metadata["adk_rust"]["cargo_lock"]
    for field, expected in (
        ("version", f'version = "{evidence["version"]}"'),
        ("source", f'source = "{evidence["source"]}"'),
        ("checksum", f'checksum = "{evidence["checksum"]}"'),
    ):
        if expected not in lock_record:
            raise CatalogError(f"Cargo.lock {field} differs from catalog evidence")


def validate_catalog(catalog: Any, schema: Any) -> None:
    validate_schema(catalog, schema)
    metadata = catalog["catalog"]
    _validate_local_dependency_evidence(metadata)
    expected_commit = metadata["adk_rust"]["commit"]
    records = catalog["official"] + catalog["third_party"]
    ids = [record["id"] for record in records]
    if len(ids) != len(set(ids)):
        raise CatalogError("record IDs must be unique")
    for record in catalog["official"]:
        _validate_record(record, True, expected_commit)
    for record in catalog["third_party"]:
        _validate_record(record, False, expected_commit)
    high_value = [record for record in records if record["value"] == "high" and record["class"] != "reject"]
    rejected = [record for record in records if record["class"] == "reject"]
    if len(high_value) < 3:
        raise CatalogError("catalog needs at least three high-value non-rejected patterns")
    if len(rejected) < 3:
        raise CatalogError("catalog needs at least three rejected patterns")
    constraints = metadata["policy"]["constraints"]
    required_constraints = {
        "no GitHub Actions or hosted CI",
        "no M1 expansion",
        "no new focused issues without demonstrated in-repo need",
    }
    if not required_constraints.issubset(constraints):
        raise CatalogError("scope constraints are incomplete")


def main() -> int:
    try:
        validate_catalog(_load(CATALOG_PATH), _load(SCHEMA_PATH))
    except CatalogError as exc:
        print(f"pattern-catalog: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"pattern-catalog: PASS ({CATALOG_PATH.relative_to(ROOT)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
