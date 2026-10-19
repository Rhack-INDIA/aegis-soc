"""End-to-end evaluation: regenerates every headline number from the corpus.

Run:  python scripts/eval.py
Out:  evals/results.json  (+ a printed table you can screenshot for the report)

Three phases, deliberately separated:
  1. benign replay    → false positives
  2. attack replay    → recall / precision / F1 over 13 ATT&CK techniques
  3. evasion set      → what the rule set MISSES (the honest number)
  4. prompt injection → attack success rate, defences off vs on
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))
os.environ.setdefault("AUTO_TRIAGE", "1")
os.environ.setdefault("STORE", "sqlite")
os.environ.setdefault("SQLITE_PATH", "data/eval.db")

if not Path("lab/corpus.jsonl").exists():
    print("corpus missing — running lab/gen_corpus.py first")
    os.system(f"{sys.executable} lab/gen_corpus.py")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)


def post_batches(path: str, events: list[dict], size: int = 100) -> int:
    n = 0
    for i in range(0, len(events), size):
        r = client.post(path, json=events[i:i + size])
        r.raise_for_status()
        n += r.json()["alerts"]
    return n


def main() -> None:
    corpus = [json.loads(l) for l in open("lab/corpus.jsonl")]
    truth = json.load(open("lab/ground_truth.json"))
    benign = [e for e in corpus if e.get("label") == "benign"]
    attacks = [e for e in corpus if e.get("label") == "attack"]
    evasions = [e for e in corpus if e.get("label") == "evasion"]

    client.post("/api/reset")
    print(f"corpus: {len(corpus)} events — {len(benign)} benign, {len(attacks)} attack, "
          f"{len(evasions)} evasion, {len(truth['techniques'])} techniques\n")

    # ---- Phase 1: benign only → every alert here is a false positive ------
    fp_alerts = post_batches("/ingest", benign)
    print(f"[1/4] benign replay: {len(benign)} events → {fp_alerts} false-positive alerts")

    # ---- Phase 2: attacks -------------------------------------------------
    attack_alerts = post_batches("/ingest", attacks)
    alerts = client.get("/api/alerts?limit=500").json()["alerts"]
    print(f"[2/4] attack replay: {len(attacks)} events → {attack_alerts} alerts "
          f"(queue total {len(alerts)})\n")

    rows = []
    for t in truth["techniques"]:
        hits = [a for a in alerts if a.get("technique") == t["technique"]]
        rows.append({
            "technique": t["technique"], "name": t["name"],
            "detected": bool(hits),
            "rule_id": hits[0]["rule_id"] if hits else None,
            "severity": hits[0]["severity"] if hits else None,
            "alerts": len(hits),
        })

    tp_tech = sum(1 for r in rows if r["detected"])
    recall = tp_tech / max(len(rows), 1)
    precision = attack_alerts / max(attack_alerts + fp_alerts, 1)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print(f"{'technique':<12}{'name':<34}{'rule':<7}{'sev':<10}detected")
    print("-" * 76)
    for r in rows:
        print(f"{r['technique']:<12}{r['name'][:33]:<34}{str(r['rule_id'] or '-'):<7}"
              f"{str(r['severity'] or '-'):<10}{'YES' if r['detected'] else 'MISS'}")
    print("-" * 76)
    print(f"recall     : {recall:.3f}  ({tp_tech}/{len(rows)} techniques)")
    print(f"precision  : {precision:.3f}  ({attack_alerts} TP alerts / {fp_alerts} FP alerts)")
    print(f"F1         : {f1:.3f}")

    # ---- Phase 3: evasion set (expected to be poor — that is the point) ---
    ev_rows = []
    for e in evasions:
        r = client.post("/ingest", json=e).json()
        techs = []
        for aid in r["alert_ids"]:
            a = client.get(f"/api/alerts/{aid}").json()
            techs.append(a.get("technique"))
        ev_rows.append({
            "technique": e["technique"], "name": e.get("attack_name") or e["technique"],
            "cmdline": e["cmdline"], "alerted": bool(r["alert_ids"]),
            "attributed": e["technique"] in techs, "fired": techs,
        })
    attributed = sum(1 for r in ev_rows if r["attributed"])
    alerted = sum(1 for r in ev_rows if r["alerted"])
    print(f"\n[3/4] evasion set ({len(ev_rows)} variants)")
    print(f"{'technique':<12}{'variant':<30}{'alerted':<9}attributed")
    print("-" * 66)
    for r in ev_rows:
        print(f"{r['technique']:<12}{r['name'][:29]:<30}{'yes' if r['alerted'] else 'no':<9}"
              f"{'yes' if r['attributed'] else 'no'}")
    print("-" * 66)
    print(f"evasion attribution: {attributed}/{len(ev_rows)} "
          f"({attributed/len(ev_rows):.2f}) · alerted at all: {alerted}/{len(ev_rows)}")

    # ---- Phase 4: prompt injection ---------------------------------------
    inj = client.post("/api/simulate/injection").json()
    off, on = inj["without_defenses"], inj["with_defenses"]
    print(f"\n[4/4] prompt injection, {inj['payloads']} payloads (mode: {inj['mode']})")
    print(f"      ASR without defences : {off['asr']:.3f}  ({off['hijacked']}/{off['total']} hijacked)")
    print(f"      ASR with defences    : {on['asr']:.3f}  ({on['hijacked']}/{on['total']} hijacked)")

    results = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "llm_mode": inj["mode"],
        "simulated_llm": inj["mode"].startswith("mock"),
        "corpus": {"events": len(corpus), "benign": len(benign),
                   "attack": len(attacks), "evasion": len(evasions),
                   "techniques": len(truth["techniques"])},
        "detection": {"recall": round(recall, 3), "precision": round(precision, 3),
                      "f1": round(f1, 3), "tp_techniques": tp_tech,
                      "fp_alerts": fp_alerts, "tp_alerts": attack_alerts, "rows": rows},
        "evasion": {"attributed": attributed, "alerted": alerted,
                    "attribution_rate": round(attributed / max(len(ev_rows), 1), 3),
                    "rows": ev_rows},
        "injection": {"payloads": inj["payloads"],
                      "asr_undefended": off["asr"], "asr_defended": on["asr"],
                      "rows_undefended": off["rows"], "rows_defended": on["rows"]},
    }
    Path("evals").mkdir(exist_ok=True)
    with open("evals/results.json", "w") as fh:
        json.dump(results, fh, indent=2)
    print("\nwrote evals/results.json")
    if results["simulated_llm"]:
        print("NOTE: LLM was in mock mode. Triage/ASR figures are SIMULATED — "
              "set GEMINI_API_KEY and re-run before quoting them in a report.")


if __name__ == "__main__":
    main()
