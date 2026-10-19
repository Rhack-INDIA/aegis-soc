"""Detection engine: 13 ATT&CK-mapped rules + statistical anomaly baseline + fusion.

Design notes for the viva:
  * Rules are cheap, explainable and precise. The anomaly scorer catches what has
    no rule, at the cost of precision. Fusion is where the trade-off is made, and
    the fusion ablation (rules-only vs anomaly-only vs fused) is the core result.
  * The anomaly scorer is a *statistical baseline*, not a trained model, on
    purpose: it keeps the container image small enough for the free tier and runs
    in ~10 ms. IsolationForest is listed as future work in the report.
"""
from __future__ import annotations

import json
import math
import os
import re
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from .schema import Event

SEV_SCORE = {"low": 0.55, "medium": 0.70, "high": 0.85, "critical": 0.95}
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

FAIL_WINDOW = 120      # seconds for brute-force counting
FAIL_THRESHOLD = 5     # failures from one source before alerting
ANOMALY_ALERT = 0.80   # fusion threshold for anomaly-only alerts


class State:
    """Per-process sliding state. In Cloud Run this is per-instance, which is
    acceptable for brute-force windows and documented as a known limitation."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.auth_fail: dict[str, deque] = defaultdict(deque)
        self.success_after_fail: dict[str, int] = defaultdict(int)
        self.seen_ips: set[str] = set()

    def record(self, ev: Event) -> None:
        with self.lock:
            now = ev.ts
            if ev.event_type == "auth" and ev.src_ip:
                q = self.auth_fail[ev.src_ip]
                if ev.status == "failure":
                    q.append(now)
                    while q and now - q[0] > timedelta(seconds=FAIL_WINDOW):
                        q.popleft()
                elif ev.status == "success":
                    self.success_after_fail[ev.src_ip] = len(q)
                self.seen_ips.add(ev.src_ip)

    def fails(self, src_ip: Optional[str], ev_ts: datetime) -> int:
        if not src_ip:
            return 0
        with self.lock:
            q = self.auth_fail.get(src_ip)
            if not q:
                return 0
            while q and ev_ts - q[0] > timedelta(seconds=FAIL_WINDOW):
                q.popleft()
            return len(q)

    def prior_success_fails(self, src_ip: Optional[str]) -> int:
        with self.lock:
            return self.success_after_fail.get(src_ip or "", 0)


STATE = State()


@dataclass
class Rule:
    id: str
    title: str
    technique: str
    severity: str
    predicate: Callable[[Event, State], bool]
    why: str


def _text(ev: Event) -> str:
    return f"{ev.process or ''} {ev.cmdline or ''} {ev.path or ''} {ev.message or ''}".lower()


RULES: list[Rule] = [
    Rule("R001", "SSH brute force from single source", "T1110", "high",
         lambda ev, st: (ev.event_type == "auth" and ev.status == "failure"
                         and st.fails(ev.src_ip, ev.ts) >= FAIL_THRESHOLD),
         "Repeated authentication failures cross the brute-force threshold"),
    Rule("R002", "Successful login after repeated failures", "T1078", "critical",
         lambda ev, st: (ev.event_type == "auth" and ev.status == "success"
                         and st.prior_success_fails(ev.src_ip) >= 5),
         "A compromised credential often succeeds right after a spray"),
    Rule("R003", "Local account creation", "T1136.001", "high",
         lambda ev, st: bool(re.search(r"\b(useradd|adduser|usermod)\b", _text(ev))),
         "New local accounts are a common persistence mechanism"),
    Rule("R004", "SSH authorized_keys modification", "T1098.004", "critical",
         lambda ev, st: "authorized_keys" in _text(ev),
         "Attacker installs a key for durable access"),
    Rule("R005", "Scheduled task persistence (cron)", "T1053.003", "medium",
         lambda ev, st: bool(re.search(r"(/etc/cron|crontab\s+-)", _text(ev))),
         "Cron entries survive reboot and re-establish access"),
    Rule("R006", "Reverse shell pattern", "T1059.004", "critical",
         lambda ev, st: bool(re.search(r"(/dev/tcp/|bash\s+-i\b|nc\s+-e\b|ncat\s+-e\b)", _text(ev))),
         "Classic interactive shell back to an external host"),
    Rule("R007", "Encoded payload piped to shell", "T1140", "high",
         lambda ev, st: bool(re.search(r"base64\s+(-d|--decode)[^|]*\|\s*(bash|sh)", _text(ev))),
         "Obfuscation is used to evade string detection"),
    Rule("R008", "Security log tampering", "T1070.002", "high",
         lambda ev, st: bool(re.search(r"(rm\s+-\w*\s*/var/log|truncate\s+-s\s*0|journalctl\s+--vacuum|history\s+-c)", _text(ev))),
         "Defence evasion: destroying evidence of the intrusion"),
    Rule("R009", "Sudoers privilege escalation", "T1548.003", "critical",
         lambda ev, st: ("/etc/sudoers" in _text(ev) or "visudo" in _text(ev)
                         or "nopasswd" in _text(ev)),
         "Passwordless sudo grants durable root"),
    Rule("R010", "Credential store access (/etc/shadow)", "T1003.008", "high",
         lambda ev, st: "/etc/shadow" in _text(ev),
         "Direct read of password hashes"),
    Rule("R011", "Web exploitation attempt (traversal/injection)", "T1190", "medium",
         lambda ev, st: bool(re.search(r"(\.\./\.\./|union\s+select|<script|%2e%2e%2f|etc/passwd)", _text(ev))),
         "Public-facing service probed with exploit payload"),
    Rule("R012", "Download and execute from remote host", "T1105", "high",
         lambda ev, st: bool(re.search(r"(curl|wget)[^|]*https?://[^|]*\|\s*(bash|sh)", _text(ev))
                             or bool(re.search(r"(curl|wget)[^\n]*/tmp/[^\s]+\s*&&\s*chmod\s+\+x", _text(ev)))),
         "Ingress tool transfer followed by execution"),
    Rule("R013", "Archive staging for exfiltration", "T1560", "medium",
         lambda ev, st: bool(re.search(r"(tar\s+-\w*c\w*f|zip\s+-r)\s+[^\n]*(/etc|/home|/root)", _text(ev))),
         "Bulk archive of sensitive directories precedes exfiltration"),
]

RULE_BY_ID = {r.id: r for r in RULES}


# --------------------------------------------------------------------------- #
# Anomaly baseline
# --------------------------------------------------------------------------- #
class Baseline:
    """Frequency/length statistics learned from the benign portion of the corpus."""

    def __init__(self, data: Optional[dict] = None) -> None:
        data = data or {}
        self.process_count: dict[str, int] = data.get("process_count", {})
        self.mean_len: float = float(data.get("mean_len", 40.0))
        self.std_len: float = float(data.get("std_len", 25.0))
        self.known_ips: set[str] = set(data.get("known_ips", []))
        self.known_users: set[str] = set(data.get("known_users", []))
        self.total: int = int(data.get("total", 0)) or sum(self.process_count.values()) or 1

    @classmethod
    def load(cls, path: str = "data/baseline.json") -> "Baseline":
        if os.path.exists(path):
            try:
                with open(path) as fh:
                    return cls(json.load(fh))
            except Exception:
                pass
        return cls()

    def score(self, ev: Event) -> tuple[float, list[str]]:
        """Returns (0..1 anomaly score, human-readable reasons)."""
        reasons: list[str] = []
        proc = (ev.process or "").lower()
        count = self.process_count.get(proc, 0)

        # Rarity: never-seen process is maximally rare.
        rarity = 0.0 if count == 0 else 1.0 / (1.0 + math.log1p(count))
        if count == 0 and proc:
            reasons.append(f"process '{proc}' never seen in baseline")

        # Command-line length deviation.
        n = len(ev.cmdline or "")
        z = abs(n - self.mean_len) / (self.std_len or 1.0)
        z_score = min(z / 6.0, 1.0)
        if z > 3:
            reasons.append(f"command length {n} is {z:.1f}σ from baseline")

        # Novelty signals.
        novelty = 0.0
        if ev.src_ip and self.known_ips and ev.src_ip not in self.known_ips:
            novelty += 0.6
            reasons.append(f"new source IP {ev.src_ip}")
        if ev.user and self.known_users and ev.user not in self.known_users:
            novelty += 0.4
            reasons.append(f"new user identity '{ev.user}'")

        # Off-hours activity (UTC), a weak but real signal.
        hour = ev.ts.hour
        off_hours = 1.0 if (hour < 5 or hour >= 23) else 0.0
        if off_hours:
            reasons.append(f"activity outside business hours ({hour:02d}:00 UTC)")

        score = 0.32 * rarity + 0.30 * z_score + 0.26 * min(novelty, 1.0) + 0.12 * off_hours
        return round(min(score, 1.0), 3), reasons


BASELINE = Baseline.load()


def reload_baseline(path: str = "data/baseline.json") -> Baseline:
    global BASELINE
    BASELINE = Baseline.load(path)
    return BASELINE


def detect(ev: Event) -> list[dict]:
    """Run all rules + anomaly scorer and return alert candidates (pre-fusion)."""
    out: list[dict] = []
    for rule in RULES:
        try:
            if rule.predicate(ev, STATE):
                out.append({
                    "rule_id": rule.id, "title": rule.title,
                    "technique": rule.technique, "severity": rule.severity,
                    "score": SEV_SCORE[rule.severity], "source": "rule",
                    "why": rule.why,
                })
        except Exception:
            continue
    return out


def fuse(ev: Event, candidates: list[dict]) -> list[dict]:
    """Combine rule hits and anomaly score.

    Returns one alert candidate *per distinct ATT&CK technique*. Emitting only the
    highest-severity match would let a generic rule (e.g. curl|bash) shadow a more
    specific one (cron persistence) and lose the technique mapping entirely — an
    error the first evaluation run actually exposed.
    """
    anom_score, reasons = BASELINE.score(ev)
    anomaly_hit = anom_score >= ANOMALY_ALERT

    if not candidates:
        if not anomaly_hit:
            return []
        return [{
            "rule_id": "ANOM", "title": "Behavioral anomaly (no rule matched)",
            "technique": "T1078", "severity": "medium",
            "score": anom_score, "sources": ["anomaly"],
            "why": "; ".join(reasons) or "statistical deviation from baseline",
            "anomaly_score": anom_score, "anomaly_reasons": reasons,
        }]

    best_by_tech: dict[str, dict] = {}
    for c in candidates:
        cur = best_by_tech.get(c["technique"])
        if cur is None or SEV_ORDER[c["severity"]] > SEV_ORDER[cur["severity"]]:
            best_by_tech[c["technique"]] = c

    out: list[dict] = []
    for tech, best in best_by_tech.items():
        sources = sorted({c["rule_id"] for c in candidates if c["technique"] == tech})
        score = best["score"]
        why = best["why"]
        if anomaly_hit:
            sources.append("anomaly")
            score = min(score + 0.05, 0.99)
            why = why + " | " + "; ".join(reasons)
        out.append({
            "rule_id": best["rule_id"], "title": best["title"],
            "technique": tech, "severity": best["severity"],
            "score": round(score, 3), "sources": sources, "why": why,
            "anomaly_score": anom_score, "anomaly_reasons": reasons,
        })
    return out
