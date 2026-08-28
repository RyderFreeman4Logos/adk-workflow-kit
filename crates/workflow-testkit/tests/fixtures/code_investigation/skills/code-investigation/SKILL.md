---
name: code-investigation
description: Read-only, evidence-grounded investigation of a checked-out Rust repository.
license: Apache-2.0
compatibility: workflow-testkit
allowed-tools: search_code, read_source_range, list_directory, inspect_symbol, read_artifact, finish_investigation, finish_review
---

# Code investigation

Produce only claims supported by selected source ranges. Keep repository access read-only.
The deterministic grounding validator owns snapshot, digest, range, and snippet facts.
Review is isolated from producer history and may pass, request revision, or abstain.
