"""Live pipeline progress reporter.

Writes the current analysis phase state to pipeline_status.json inside the
sample's work dir. The work dir is bind-mounted from the host, so the CLI can
poll it and render a master progress panel while the container runs.

Reporting is best-effort: a failure here must never abort the analysis, so
every write is wrapped in a bare except.
"""

import json
import os
import threading
import time
from contextlib import contextmanager

STATIC_PHASES = ["apktool", "jadx", "manifest", "assets", "trust", "yara", "triage", "stage"]
DYNAMIC_PHASES = ["emulator", "install", "frida"]


class Pipeline:
    def __init__(self, work_dir: str, dynamic: bool = False):
        self.status_file = os.path.join(work_dir, "pipeline_status.json")
        self._lock = threading.Lock()
        self._start = time.time()
        self._phases = {}
        self._order = STATIC_PHASES + (DYNAMIC_PHASES if dynamic else [])
        for name in self._order:
            self._phases[name] = {"state": "pending", "elapsed": 0, "started": None}

        self._stopped = threading.Event()
        self._ticker = threading.Thread(target=self._tick, daemon=True)
        self._ticker.start()
        self._write()

    def _tick(self):
        while not self._stopped.wait(1.0):
            self._write()

    @contextmanager
    def phase(self, name: str):
        """Mark a phase running, then done/failed when the block exits."""
        self.begin(name)
        try:
            yield
        except BaseException:
            self.fail(name)
            raise
        self.end(name)

    def begin(self, name: str):
        with self._lock:
            self._phases[name]["state"] = "running"
            self._phases[name]["started"] = time.time()
            self._phases[name]["elapsed"] = 0
            self._write()

    def end(self, name: str):
        with self._lock:
            ph = self._phases[name]
            if ph["started"] is not None:
                ph["elapsed"] = int(time.time() - ph["started"])
            ph["state"] = "done"
            ph["started"] = None
            self._write()

    def fail(self, name: str):
        with self._lock:
            ph = self._phases[name]
            if ph["started"] is not None:
                ph["elapsed"] = int(time.time() - ph["started"])
            ph["state"] = "failed"
            ph["started"] = None
            self._write()

    def close(self):
        self._stopped.set()
        self._write()

    @property
    def _percent(self) -> int:
        total = len(self._order)
        if not total:
            return 0
        score = 0
        for name in self._order:
            state = self._phases[name]["state"]
            if state == "done":
                score += 1
            elif state == "running":
                score += 0.5
        return int(score / total * 100)

    def _write(self):
        try:
            payload = {
                "pipeline": "full" if len(self._order) > len(STATIC_PHASES) else "static",
                "elapsed_total": int(time.time() - self._start),
                "percent": self._percent,
                "phases": [dict(self._phases[name], name=name) for name in self._order],
            }
            with open(self.status_file, "w") as f:
                json.dump(payload, f, indent=2)
        except Exception:
            pass
