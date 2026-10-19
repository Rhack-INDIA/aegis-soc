"""Test bootstrap.

Environment must be set *before* `app.main` is imported: the store backend and
the auto-triage flag are read at import time.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_DB = Path(tempfile.gettempdir()) / "aegis_test.db"
if _DB.exists():
    _DB.unlink()

os.environ["STORE"] = "sqlite"
os.environ["SQLITE_PATH"] = str(_DB)
os.environ["AUTO_TRIAGE"] = "0"      # deterministic: tests drive triage explicitly
os.environ.pop("GEMINI_API_KEY", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    c = TestClient(app)
    c.post("/api/reset")             # clears alerts + in-memory detection state
    return c


TS = "2026-10-19T09:00:00+00:00"


def event(**kw) -> dict:
    base = {"ts": TS, "host": "web-01", "user": "root", "event_type": "process"}
    base.update(kw)
    return base
