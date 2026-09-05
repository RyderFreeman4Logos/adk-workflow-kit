#!/usr/bin/env python3
"""Real clean-start and stale-copy controls, without compiling Rust."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parent = Path.home() / "project/downstream"
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="269-bootstrap-", dir=parent) as base:
        consumer = Path(base) / "consumer"
        env = dict(os.environ, ISSUE_269_DOWNSTREAM=str(consumer))
        command = ["python3", str(ROOT / "scripts/test_issue_269_downstream.py"), "--prepare"]
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        assert (consumer / "Cargo.lock").is_file()
        assert os.readlink(consumer / "target") == f"/ssd/mirror-rootfs{consumer}/target"
        sentinel = consumer / "user-owned.txt"
        sentinel.write_text("preserve me")
        assert subprocess.run(command, env=env, capture_output=True).returncode == 0
        for relative in ("src/main.rs", "Cargo.toml", "Cargo.lock", "justfile", "assets/prompt.txt", "assets/skills/demo/references/usage.md", "fixtures/profile.json"):
            path = consumer / relative
            original = path.read_bytes()
            try:
                path.write_bytes(original + b"\nstale-copy\n")
                result = subprocess.run(command, env=env, capture_output=True, text=True)
                assert result.returncode != 0 and "candidate mismatch" in result.stderr, relative
                assert path.read_bytes().endswith(b"stale-copy\n"), "must not overwrite stale state"
            finally:
                path.write_bytes(original)
        assert sentinel.read_text() == "preserve me"
        assert subprocess.run(command, env=env, capture_output=True).returncode == 0
        print("PASS bootstrap: clean start, repeat, relocation target, 7 stale-copy negatives, preservation")


if __name__ == "__main__":
    main()
