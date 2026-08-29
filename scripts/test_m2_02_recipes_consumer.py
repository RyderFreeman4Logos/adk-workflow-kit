#!/usr/bin/env python3
"""Executable evidence for the #187 recipes-consumer decision."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADR = ROOT / "docs/architecture/adrs/ADR-0024.md"
WORKSPACE = ROOT / "Cargo.toml"
CONSUMER_MANIFESTS = (
    ROOT / "crates/workflowctl/Cargo.toml",
    ROOT / "crates/workflow-testkit/Cargo.toml",
)


class M202RecipesConsumerTests(unittest.TestCase):
    def test_decision_adr_is_explicit(self) -> None:
        self.assertTrue(ADR.is_file(), f"missing decision ADR: {ADR}")
        text = ADR.read_text(encoding="utf-8")
        for marker in (
            "# ADR-0024:",
            "- Status: Accepted",
            "- Source: Issue #187",
            "no-create",
            "published crate",
            "exact git revision pin",
            "No companion repository is created",
        ):
            self.assertIn(marker, text, f"ADR missing marker: {marker}")

    def test_workspace_is_not_a_path_independent_consumer_package(self) -> None:
        workspace = WORKSPACE.read_text(encoding="utf-8")
        self.assertIn("[workspace]", workspace)
        self.assertNotIn("\n[package]", workspace)
        for manifest_path in CONSUMER_MANIFESTS:
            manifest = manifest_path.read_text(encoding="utf-8")
            self.assertRegex(manifest, r"(?m)^\w[\w-]*\s*=\s*\{\s*path\s*=")
            self.assertNotRegex(manifest, r"(?m)^\s*git\s*=")

    def test_future_creation_gate_is_recorded(self) -> None:
        self.assertTrue(ADR.is_file(), f"missing decision ADR: {ADR}")
        text = ADR.read_text(encoding="utf-8")
        for marker in (
            "published crate or an exact git revision pin",
            "run/resume/inspect/replay",
            "local-only gates",
            "adk-rust = \"=2.1.0\"",
            "ADK implementation types",
        ):
            self.assertIn(marker, text, f"ADR missing future gate: {marker}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
