"""Machine-readable JSONL result output for `--json` mode.

In machine mode, stdout carries ONLY structured records (one JSON object per
line); every human-facing message and progress frame goes to stderr, so a
caller such as EVdlc can parse stdout without scraping UI text. Records never
contain passwords, keys, SIDs, vault passphrases, or unredacted link keys.
"""

from __future__ import annotations

import json
import sys


class MachineOutput:
    """JSONL emitter bound to the REAL stdout captured at construction time.

    Construct it BEFORE redirecting the command's stdout to stderr: the
    emitter keeps writing records to the original stream while all human
    output is routed away from it.
    """

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self._stream = sys.stdout

    def emit(self, **record) -> None:
        if not self.enabled:
            return
        payload = {key: value for key, value in record.items() if value is not None}
        print(json.dumps(payload, ensure_ascii=False), file=self._stream, flush=True)
