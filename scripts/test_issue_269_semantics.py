#!/usr/bin/env python3
"""Mutate owned offline fixtures, run the real consumer, and restore bytes."""
import json
import os
from pathlib import Path
import subprocess
import hashlib
import sqlite3

CONSUMER = Path(os.environ.get("ISSUE_269_DOWNSTREAM", str(Path.home() / "project/downstream/adk-workflow-kit-269")))


def main() -> None:
    env = dict(os.environ, ISSUE_269_TMPDIR=str((Path.home() / "tmp").resolve()))
    prepare = ["python3", str(Path(__file__).with_name("test_issue_269_downstream.py")), "--prepare"]
    subprocess.run(prepare, env=env, capture_output=True, text=True, check=True)
    failures = []
    for relative, mutation in (
        ("assets/prompt.txt", lambda value: value + "\nwrong instruction\n"),
        ("fixtures/profile.json", lambda value: value.replace("downstream proof complete", "WRONG OUTPUT")),
        ("assets/connectors/echo.json", lambda value: value.replace("connector-backed downstream effect", "WRONG EFFECT")),
    ):
        path = CONSUMER / relative
        original = path.read_bytes()
        try:
            mutated = mutation(original.decode()).encode()
            assert mutated != original, relative
            path.write_bytes(mutated)
            result = subprocess.run(["just", "acceptance"], cwd=CONSUMER, env=env, capture_output=True, text=True)
            if result.returncode == 0 or "Error:" not in result.stderr or "could not compile" in result.stderr:
                failures.append(relative)
            print(json.dumps({"negative": relative, "exit": result.returncode, "diagnostic": result.stderr[-800:]}))
        finally:
            path.write_bytes(original)
    assert not failures, f"false-green mutations: {failures}"
    profile_path = CONSUMER / "fixtures/profile.json"
    original = profile_path.read_bytes()
    for name in ("activate_skill", "read_skill_resource"):
        profile = json.loads(original)
        profile["model"]["responses"] = [response for response in profile["model"]["responses"] if not isinstance(response, dict) or response["calls"][0]["name"] != name]
        try:
            profile_path.write_text(json.dumps(profile))
            result = subprocess.run(["just", "acceptance"], cwd=CONSUMER, env=env, capture_output=True, text=True)
            assert result.returncode != 0 and "Error:" in result.stderr, name
            print(json.dumps({"missing_tool_negative": name, "exit": result.returncode}))
        finally:
            profile_path.write_bytes(original)
    result = subprocess.run(["just", "acceptance"], cwd=CONSUMER, env=env, capture_output=True, text=True, check=True)
    receipt = json.loads(next(line.removeprefix("ISSUE_269_RECEIPT=") for line in result.stdout.splitlines() if line.startswith("ISSUE_269_RECEIPT=")))
    run = Path(receipt["run_root"])
    verify = ["just", "verify", receipt["run_id"]]
    artifact = next(path for path in (run / "artifacts").rglob("*") if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == receipt["run_receipt"]["artifact_id"])
    # Only this test's generated run is mutated; each durable byte is restored.
    for path, mutation in (
        (artifact, lambda value: value.replace(b'"succeeded"', b'"CORRUPTED"')),
        (run / "run-manifest.json", lambda value: value.replace(receipt["run_receipt"]["artifact_id"].encode(), b"0" * 64)),
        (run / "events.jsonl", lambda value: value.replace(b"downstream proof complete", b"CORRUPTED RETAINED OUTPUT")),
    ):
        original = path.read_bytes()
        try:
            changed = mutation(original)
            assert changed != original
            path.write_bytes(changed)
            result = subprocess.run(verify, cwd=CONSUMER, env=env, capture_output=True, text=True)
            assert result.returncode != 0 and "Error:" in result.stderr, path
            print(json.dumps({"durable_negative": path.name, "exit": result.returncode}))
        finally:
            path.write_bytes(original)
    with sqlite3.connect(run / "effects.sqlite") as database:
        rows = database.execute("SELECT effect_key, result_json FROM kit_effects").fetchall()
        assert len(rows) == 1
        try:
            database.execute("UPDATE kit_effects SET result_json = ?", (b'{"echo":"CORRUPTED EFFECT"}',))
            database.commit()
            result = subprocess.run(verify, cwd=CONSUMER, env=env, capture_output=True, text=True)
            assert result.returncode != 0 and "check failed:" in result.stderr
            print(json.dumps({"durable_negative": "effects.sqlite", "exit": result.returncode}))
        finally:
            database.executemany("UPDATE kit_effects SET result_json = ? WHERE effect_key = ?", [(value, key) for key, value in rows])
            database.commit()
    subprocess.run(verify, cwd=CONSUMER, env=env, capture_output=True, text=True, check=True)
    data_path = CONSUMER / "assets/data/input.json"
    original = data_path.read_bytes()
    try:
        data = json.loads(original)
        data["value"] = "relocated-data-observation"
        data_path.write_text(json.dumps(data))
        result = subprocess.run(["just", "acceptance"], cwd=CONSUMER, env=env, capture_output=True, text=True, check=True)
        changed = json.loads(next(line.removeprefix("ISSUE_269_RECEIPT=") for line in result.stdout.splitlines() if line.startswith("ISSUE_269_RECEIPT=")))
        assert changed["arguments_sha256"] != receipt["arguments_sha256"]
        print("PASS changed external data reaches observed request and committed effect key")
    finally:
        data_path.write_bytes(original)
    print("PASS 9 semantic negative controls and retained-run GREEN; fixture bytes and effect values restored")
    subprocess.run(prepare, env=env, capture_output=True, text=True, check=True)


if __name__ == "__main__":
    main()
