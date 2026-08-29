#!/usr/bin/env python3
"""Contract tests for the checked-in ADK-Rust pattern catalog."""

from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs/architecture/adk-rust-pattern-catalog.json"
SCHEMA = ROOT / "docs/architecture/adk-rust-pattern-catalog.schema.json"
VALIDATOR = ROOT / "scripts/validate_pattern_catalog.py"


class PatternCatalogContractTests(unittest.TestCase):
    def test_catalog_and_schema_are_published(self) -> None:
        self.assertTrue(CATALOG.is_file(), f"missing catalog: {CATALOG}")
        self.assertTrue(SCHEMA.is_file(), f"missing schema: {SCHEMA}")

    def test_catalog_passes_schema_and_policy_validation(self) -> None:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
