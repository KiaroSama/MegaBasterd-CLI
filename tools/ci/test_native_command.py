# SPDX-License-Identifier: GPL-3.0-or-later
"""One bounded real command; application text is not native harness evidence."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


class NativeCommandTests(unittest.TestCase):
    def test_application_output_cannot_override_a_successful_native_process_exit(self):
        here = Path(__file__).resolve().parent
        spec = importlib.util.spec_from_file_location("native_command_under_test", here / "run-native.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        base = here.parents[1] / ".ci-work" / "command-tooling-tests"
        base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            work = Path(temporary)
            log = runner.RunLog(work)
            try:
                environment = runner.environment(work, 1)
                code, stdout, stderr = runner.command(
                    [sys.executable, "-I", "-B", str(here / "run-native.py"),
                     "--fixture", "native-output"],
                    "native-000-run", environment, log, wall=10, idle=5, memory_mib=512)
                self.assertEqual(code, 0)
                for stream in (stdout, stderr):
                    self.assertIn(b"test application_text ... ignored", stream)
                    self.assertIn(b"1 ignored; 0 measured; 0 filtered out", stream)
            finally:
                log.close()
