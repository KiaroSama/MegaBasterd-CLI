# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded runner entry for reviewed native-build tooling tests, not application tests."""

from datetime import datetime, timezone
import logging
from pathlib import Path
import sys
import time
import unittest
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def main():
    root = HERE.parents[1]
    directory = root / ".ci-work" / "tooling-logs"
    logger = logging.getLogger("native-tooling-tests")
    logger.setLevel(logging.INFO)
    handler = None
    code = 125
    try:
        directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S_UTC")
        handler = logging.FileHandler(directory / f"tooling-tests_{stamp}_{uuid.uuid4().hex}.log",
                                      mode="x", encoding="utf-8")
        formatter = logging.Formatter("[%(asctime)s UTC] [%(levelname)s] [CI-TOOLING] %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S")
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info("Tooling tests starting; retained application modules are not imported")
        suite = unittest.defaultTestLoader.discover(str(HERE), pattern="test_*.py", top_level_dir=str(HERE))
        count = suite.countTestCases()
        if count == 0:
            raise ValueError("Native tooling test discovery was empty")
        result = unittest.TextTestRunner(stream=handler.stream, verbosity=2).run(suite)
        code = 0 if result.wasSuccessful() and not result.skipped else 1
        logger.info("Tooling tests finished discovered=%d run=%d failures=%d errors=%d skipped=%d exit=%d",
                    count, result.testsRun, len(result.failures), len(result.errors), len(result.skipped), code)
        print(f"Tooling tests: discovered={count} run={result.testsRun} failures={len(result.failures)} "
              f"errors={len(result.errors)} skipped={len(result.skipped)} exit={code}", flush=True)
    except (OSError, ValueError, ImportError) as error:
        if handler is not None:
            logger.error("Tooling test prerequisite failed category=%s", type(error).__name__)
        print(f"Tooling test prerequisite failed: {type(error).__name__}; exit=125", file=sys.stderr)
        code = 125
    finally:
        if handler is not None:
            logger.removeHandler(handler)
            handler.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
