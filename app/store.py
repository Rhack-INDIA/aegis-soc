"""Storage: SQLite for local demo, Firestore for Cloud Run.

Cloud Run containers are ephemeral, so a SQLite file would lose every alert on
scale-to-zero — which is exactly why the cloud backend is Firestore. Local demo
uses SQLite so the whole thing runs with zero credentials.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .schema import Alert, Event, utcnow

SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class Store:
    def add_alert(self, alert: Alert) -> None: raise NotImplementedError
    def list_alerts(self, limit: int = 100) -> list[dict]: raise NotImplementedError
    def get_alert(self, alert_id: str) -> Optional[dict]: raise NotImplementedError
    def set_triage(self, alert_id: str, triage: dict) -> None: raise NotImplementedError
    def set_status(self, alert_id: str, status: str) -> None: raise NotImplementedError
    def stats(self) -> dict: raise NotImplementedError
    def recent_fingerprints(self, seconds: int) -> set[str]: raise NotImplementedError


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["event"] = json.loads(d.pop("event_json"))
    d["sources"] = json.loads(d.pop("sources_json") or "[]")
    d["triage"] = json.loads(d["triage_json"]) if d.get("triage_json") else None
    d.pop("triage_json", None)
    return d


class SqliteStore(Store):
    def __init__(self, path: str = "data/aegis.db") -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, ts TEXT, fingerprint TEXT, rule_id TEXT,
                title TEXT, severity TEXT, technique TEXT, why TEXT, score REAL,
                sources_json TEXT, event_json TEXT, triage_json TEXT,
                status TEXT, src_ip TEXT, created_at TEXT
            )""")
        # migration for databases created before `why` existed
        try:
            self._db.execute("ALTER TABLE alerts ADD COLUMN why TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        self._db.execute("CREATE INDEX IF NOT EXISTS ix_fp ON alerts(fingerprint, created_at)")
        self._db.commit()

    def add_alert(self, alert: Alert) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (alert.id, alert.ts.isoformat(), alert.fingerprint, alert.rule_id,
                 alert.title, alert.severity, alert.technique, alert.why, alert.score,
                 json.dumps(alert.sources), alert.event.model_dump_json(),
                 None, alert.status, alert.event.src_ip, alert.created_at.isoformat()),
            )
            self._db.commit()

    def list_alerts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_dict(r) for r in rows]

    def get_alert(self, alert_id: str) -> Optional[dict]:
        with self._lock:
            row = self._db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return _row_to_dict(row) if row else None

    def set_triage(self, alert_id: str, triage: dict) -> None:
        with self._lock:
            self._db.execute("UPDATE alerts SET triage_json=? WHERE id=?",
                             (json.dumps(triage), alert_id))
            self._db.commit()

    def set_status(self, alert_id: str, status: str) -> None:
        with self._lock:
            self._db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
            self._db.commit()

    def recent_fingerprints(self, seconds: int = 300,
                            ref_ts: Optional[datetime] = None) -> set[str]:
        """Fingerprints seen within `seconds` of ref_ts — compared on EVENT time.

        Using wall-clock time here breaks corpus replay: a 45-minute corpus
        processed in two seconds would look like one instant and collapse
        distinct detections into a single alert.
        """
        ref = ref_ts or datetime.now(timezone.utc)
        cutoff = (ref - timedelta(seconds=seconds)).timestamp()
        with self._lock:
            rows = self._db.execute("SELECT fingerprint, ts FROM alerts").fetchall()
        out = set()
        for r in rows:
            try:
                if datetime.fromisoformat(r["ts"]).timestamp() >= cutoff:
                    out.add(r["fingerprint"])
            except Exception:
                continue
        return out

    def stats(self) -> dict:
        with self._lock:
            total = self._db.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]
            by_sev = self._db.execute(
                "SELECT severity, COUNT(*) c FROM alerts GROUP BY severity").fetchall()
            by_rule = self._db.execute(
                "SELECT rule_id, title, technique, COUNT(*) c FROM alerts "
                "GROUP BY rule_id ORDER BY c DESC").fetchall()
            by_status = self._db.execute(
                "SELECT status, COUNT(*) c FROM alerts GROUP BY status").fetchall()
        return {
            "total": total,
            "by_severity": {r["severity"]: r["c"] for r in by_sev},
            "by_status": {r["status"]: r["c"] for r in by_status},
            "by_rule": [dict(r) for r in by_rule],
        }


class FirestoreStore(Store):
    """Firestore backend. Requires default credentials (automatic on Cloud Run)."""

    COLL = "alerts"

    def __init__(self) -> None:
        from google.cloud import firestore  # imported lazily so local demo has no dep
        project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT")
        self._client = firestore.Client(project=project) if project else firestore.Client()
        self._fs = firestore

    def add_alert(self, alert: Alert) -> None:
        doc = {
            "ts": alert.ts.isoformat(), "fingerprint": alert.fingerprint,
            "rule_id": alert.rule_id, "title": alert.title,
            "severity": alert.severity, "technique": alert.technique,
            "why": alert.why, "score": alert.score, "sources": alert.sources,
            "event": alert.event.model_dump(mode="json"), "triage": None,
            "status": alert.status, "src_ip": alert.event.src_ip,
            "created_at": alert.created_at.isoformat(),
        }
        self._client.collection(self.COLL).document(alert.id).set(doc)

    def _doc(self, d) -> dict:
        data = d.to_dict() or {}
        data["id"] = d.id
        return data

    def list_alerts(self, limit: int = 100) -> list[dict]:
        q = (self._client.collection(self.COLL)
             .order_by("created_at", direction=self._fs.Query.DESCENDING).limit(limit))
        return [self._doc(d) for d in q.stream()]

    def get_alert(self, alert_id: str) -> Optional[dict]:
        d = self._client.collection(self.COLL).document(alert_id).get()
        return self._doc(d) if d.exists else None

    def set_triage(self, alert_id: str, triage: dict) -> None:
        self._client.collection(self.COLL).document(alert_id).update({"triage": triage})

    def set_status(self, alert_id: str, status: str) -> None:
        self._client.collection(self.COLL).document(alert_id).update({"status": status})

    def recent_fingerprints(self, seconds: int = 300,
                            ref_ts: Optional[datetime] = None) -> set[str]:
        ref = ref_ts or datetime.now(timezone.utc)
        cutoff = (ref - timedelta(seconds=seconds)).isoformat()
        q = (self._client.collection(self.COLL)
             .where("ts", ">=", cutoff).select(["fingerprint"]))
        return {d.to_dict().get("fingerprint") for d in q.stream()}

    def stats(self) -> dict:
        alerts = self.list_alerts(limit=1000)
        by_rule: dict[str, dict] = {}
        by_sev: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for a in alerts:
            by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
            by_status[a["status"]] = by_status.get(a["status"], 0) + 1
            r = by_rule.setdefault(a["rule_id"], {"rule_id": a["rule_id"], "title": a["title"],
                                                  "technique": a.get("technique"), "c": 0})
            r["c"] += 1
        return {"total": len(alerts), "by_severity": by_sev, "by_status": by_status,
                "by_rule": sorted(by_rule.values(), key=lambda x: -x["c"])}


_STORE: Optional[Store] = None


def get_store() -> Store:
    global _STORE
    if _STORE is None:
        backend = os.getenv("STORE", "sqlite").lower()
        _STORE = FirestoreStore() if backend == "firestore" else SqliteStore(
            os.getenv("SQLITE_PATH", "data/aegis.db"))
    return _STORE


def new_alert_id() -> str:
    return uuid.uuid4().hex[:12]
