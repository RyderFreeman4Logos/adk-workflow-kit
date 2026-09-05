#!/usr/bin/env python3
"""Verify the external exact-Git downstream consumer for issue #269."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
DOWNSTREAM = Path(
    os.environ.get("ISSUE_269_DOWNSTREAM", "/home/obj/project/downstream/adk-workflow-kit-269")
)
PINNED_REVISION = "026b883a58bab6cc2d0c8610b44e3983e6017cb8"
EXPECTED_TARGET = f"/ssd/mirror-rootfs{DOWNSTREAM}/target"
DIRECT_DEPENDENCIES = ("workflow-compiler", "workflow-adk", "workflow-testkit")


def fail(message: str) -> NoReturn:
    raise SystemExit(f"issue-269 acceptance: FAIL: {message}")


def main() -> int:
    if not DOWNSTREAM.is_dir():
        fail(f"missing external consumer: {DOWNSTREAM}")
    manifest = (DOWNSTREAM / "Cargo.toml").read_text(encoding="utf-8")
    if "[workspace]" in manifest or "path =" in manifest or "../" in manifest or "workflowctl" in manifest:
        fail("consumer manifest uses a workspace, path dependency, traversal, or workflowctl")
    revisions = []
    for package in DIRECT_DEPENDENCIES:
        match = re.search(
            rf"(?m)^\s*{re.escape(package)}\s*=\s*\{{[^\n]*git\s*=\s*\"[^\"]+\"[^\n]*rev\s*=\s*\"([0-9a-f]{{40}})\"",
            manifest,
        )
        if match is None:
            fail(f"{package} is not pinned to an exact Git revision")
        revisions.append(match.group(1))
    if revisions != [PINNED_REVISION] * len(DIRECT_DEPENDENCIES):
        fail(f"direct Git revisions are not the supported pin: {revisions}")
    lock_text = (DOWNSTREAM / "Cargo.lock").read_text(encoding="utf-8")
    for package in DIRECT_DEPENDENCIES:
        block = next((block for block in lock_text.split("[[package]]") if f'name = "{package}"' in block), "")
        if f"#{PINNED_REVISION}" not in block:
            fail(f"Cargo.lock does not pin {package} to {PINNED_REVISION}")
    target = DOWNSTREAM / "target"
    if not target.is_symlink() or os.readlink(target) != EXPECTED_TARGET:
        fail(f"target symlink is not lexical {EXPECTED_TARGET}")
    required = (
        "justfile",
        "src/main.rs",
        "fixtures/workflow.toml",
        "fixtures/profile.json",
        "fixtures/replay.json",
        "assets/prompt.txt",
        "assets/skills/demo/SKILL.md",
        "assets/skills/demo/skill.runtime.toml",
        "assets/connectors/echo.json",
        "assets/data/input.json",
    )
    for relative in required:
        path = DOWNSTREAM / relative
        if not path.is_file() or path.is_symlink():
            fail(f"missing or linked downstream-owned asset: {relative}")
        if "../" in path.read_text(encoding="utf-8"):
            fail(f"asset contains checkout traversal: {relative}")
    tracked_replay = ROOT / "examples/02-downstream-consumer-269/fixtures/replay.json"
    consumer_replay = DOWNSTREAM / "fixtures/replay.json"
    if tracked_replay.read_bytes() != consumer_replay.read_bytes():
        fail("consumer replay.json diverged from the tracked fixture source")
    replay = json.loads(tracked_replay.read_text(encoding="utf-8"))
    lock_toml = replay["workflow_lock"]["toml"].encode("utf-8")
    lock_digest = "sha256:" + hashlib.sha256(lock_toml).hexdigest()
    if replay["workflow_lock"]["sha256"] != lock_digest:
        fail("replay workflow-lock digest does not match canonical toml bytes")
    if replay["workflow_lock"]["sha256"] == "sha256:" + ("1" * 64):
        fail("replay workflow-lock digest is still the placeholder")
    for fixture in replay["fixtures"]:
        actual = "sha256:" + hashlib.sha256(bytes(fixture["bytes"])).hexdigest()
        if fixture["sha256"] != actual:
            fail("replay fixture digest does not match inline bytes")
    result = subprocess.run(
        ["just", "acceptance"],
        cwd=DOWNSTREAM,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        print(result.stdout, end="")
        print(result.stderr, end="")
        fail(f"external acceptance exited {result.returncode}")
    receipts = [
        line.removeprefix("ISSUE_269_RECEIPT=")
        for line in result.stdout.splitlines()
        if line.startswith("ISSUE_269_RECEIPT=")
    ]
    if len(receipts) != 1:
        fail("external acceptance did not emit one receipt")
    receipt = json.loads(receipts[0])
    if receipt.get("revision") != PINNED_REVISION:
        fail("receipt revision does not match the exact dependency pin")
    if receipt.get("operations") != ["validate", "lock", "run", "inspect", "resume", "replay"]:
        fail("receipt does not prove exactly the six required operations")
    if receipt.get("checks_passed") != 12:
        fail(f"receipt passed {receipt.get('checks_passed')} checks instead of 12")
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
