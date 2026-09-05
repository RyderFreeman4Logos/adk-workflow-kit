#!/usr/bin/env python3
"""Path regressions: real bootstrap/Just shells, no synthetic-home Cargo."""
import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent


class PathTests(unittest.TestCase):
    def test_bootstrap_creates_missing_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="269-home-", dir=Path.home()) as base:
            home = Path(base) / "new-home"
            self.assertFalse((home / "project/downstream").exists())
            bootstrap = runpy.run_path(str(SCRIPTS / "test_issue_269_bootstrap.py"))
            # Patch only Python selection: children keep the real HOME/toolchain.
            with patch.object(Path, "home", return_value=home):
                bootstrap["main"]()
            self.assertTrue((home / "project/downstream").is_dir())

    def test_default_consumer_identity(self) -> None:
        home = Path("/synthetic-home-without-settings")
        with patch.dict(os.environ):
            os.environ.pop("ISSUE_269_DOWNSTREAM", None)
            with patch.object(Path, "home", return_value=home):
                downstream = runpy.run_path(str(SCRIPTS / "test_issue_269_downstream.py"))
                semantics = runpy.run_path(str(SCRIPTS / "test_issue_269_semantics.py"))
        expected = home / "project/downstream/adk-workflow-kit-269"
        self.assertEqual(downstream["DOWNSTREAM"], expected)
        self.assertEqual(semantics["CONSUMER"], expected)
        self.assertEqual(downstream["EXPECTED_TARGET"], f"/ssd/mirror-rootfs{expected}/target")

    def test_semantics_propagates_selected_paths(self) -> None:
        # Stop at the first child boundary: no synthetic HOME config is read.
        home = Path("/synthetic-home-too-long-for-the-runtime-temporary-base")
        consumer = home / "project/downstream/adk-workflow-kit-269"
        for explicit in (None, "/short-explicit-tmp", "relative-explicit-tmp"):
            with self.subTest(temporary=explicit), patch.dict(os.environ):
                os.environ.pop("ISSUE_269_DOWNSTREAM", None)
                os.environ.pop("ISSUE_269_TMPDIR", None)
                if explicit is not None:
                    os.environ["ISSUE_269_TMPDIR"] = explicit
                with patch.object(Path, "home", return_value=home):
                    semantics = runpy.run_path(str(SCRIPTS / "test_issue_269_semantics.py"))
                    with patch.object(subprocess, "run", side_effect=InterruptedError) as child:
                        with self.assertRaises(InterruptedError):
                            semantics["main"]()
                env = child.call_args.kwargs["env"]
                self.assertEqual(env["ISSUE_269_TMPDIR"], str(Path(explicit or home / "tmp").resolve()))
                self.assertEqual(env.get("ISSUE_269_DOWNSTREAM"), str(consumer))

    def test_just_preserves_literal_path_arguments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="269q-", dir=Path.home()) as base:
            base = Path(base)
            # Harmless expansion only: no executable side-effect payload.
            consumer = base / "literal$HOME'\"$(printf literal)"
            temporary = base / "$HOME'\""
            env = dict(os.environ, ISSUE_269_DOWNSTREAM=str(consumer), ISSUE_269_TMPDIR=str(temporary))
            result = subprocess.run(
                ["python3", str(SCRIPTS / "test_issue_269_downstream.py"), "--prepare"],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(os.readlink(consumer / "target"), f"/ssd/mirror-rootfs{consumer}/target")
            result = subprocess.run(["just", "_guard"], cwd=consumer, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            # Execute the actual recipes/shell, recording argv instead of Cargo.
            recorder = base / "record.py"
            calls = base / "calls.jsonl"
            recorder.write_text(
                "import json, sys\nfrom pathlib import Path\n"
                f"with Path({str(calls)!r}).open('a') as output:\n"
                "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            )
            run_id = "literal$HOME'\"$(printf literal)"
            for recipe in (["acceptance"], ["verify", run_id]):
                result = subprocess.run(
                    ["just", "--set", "_io", f"python3 {shlex.quote(str(recorder))}", *recipe],
                    cwd=consumer, env=env, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            arguments = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual(arguments, [
                ["cargo", "+1.98.0", "build", "--locked"],
                ["cargo", "+1.98.0", "run", "--locked", "--", str(consumer), str(temporary)],
                ["cargo", "+1.98.0", "build", "--locked"],
                ["cargo", "+1.98.0", "run", "--locked", "--", str(consumer), str(temporary), run_id],
            ])
            self.assertEqual(list(Path(f"/ssd/mirror-rootfs{consumer}/target").iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
