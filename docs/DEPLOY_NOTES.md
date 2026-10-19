# Deployment & Cost Guardrails

Read this before running `deploy.sh`. The goal is a working demo URL that cannot generate a bill.

## 1. The one decision you must make first

Google's free tier has **no end date**, but it requires an **active billing account**. The $300
90-day trial is separate: when it expires, if you have not upgraded to a paid billing account, your
projects and resources stop.

| Path | Consequence |
|---|---|
| Stay on the trial only | Everything dies ~day 90. Fine for a 4-day demo, fatal if you demo again next semester. |
| Upgrade to paid billing, use only always-free SKUs | Free resources stay free indefinitely; a misconfiguration bills a real card. |

For a 4-day showcase the trial alone is sufficient. If you want the risk instead of the deadline,
upgrade and apply every guardrail in §2.

## 2. Guardrails — apply all five

1. **Budget alert** (manual; needs your billing account ID):
   ```bash
   gcloud billing accounts list
   gcloud billing budgets create --billing-account=XXXXXX-XXXXXX-XXXXXX \
     --display-name=aegis-guard --budget-amount=1USD \
     --threshold-rule=percent=0.5 --threshold-rule=percent=1.0
   ```
2. **Instance cap** — already in `deploy.sh`: `--max-instances=3`.
3. **No accidental paid services.** Never enable: Cloud SQL, Cloud NAT, a load balancer, GKE nodes,
   Memorystore, or GPU/TPU quotas. Each of those bills even in small amounts.
4. **Retention** — the bucket has a 14-day delete lifecycle; Firestore holds alerts only.
5. **Weekly check** while it is live: `gcloud billing accounts describe` / Billing → Reports. Expect
   ₹0 / $0.

## 3. Free-tier limits that actually bind

| Limit | Value | What hits it |
|---|---|---|
| Artifact Registry storage | 0.5 GB | Building a second fat image; keeps old tags |
| Firestore writes | 20k/day | Writing one document per *event* instead of per *alert* |
| Cloud Run memory-seconds | 360k GiB-s/month | Leaving `min-instances=1` with 2 GiB |
| Cloud Storage | 5 GB-months (US regions) | Shipping raw logs without a lifecycle rule |

The image is ~73 MB stored (351 MB on disk, measured), so you can keep several tags and still be
inside 0.5 GB. Prune anyway:

```bash
gcloud artifacts docker images list \
  ${REGION}-docker.pkg.dev/${PROJECT_ID}/aegis/aegis --include-tags
```

## 4. Regions

Free-tier compute and storage allowances apply only in **us-central1, us-west1, us-east1**. Use
`us-central1` unless it is unavailable, and keep Cloud Run in the same region as Firestore.

## 5. Verification after deploy

```bash
URL=$(gcloud run services describe aegis-soc --region us-central1 --format='value(status.url)')
curl -s "$URL/api/health"                    # store must say "firestore"
curl -s -X POST "$URL/api/simulate/attack"   # alerts must be ~12
curl -s "$URL/api/stats"                     # total must match
```

Then open the URL in a browser, press **Run attack simulation**, and confirm 12 alerts and a
populated detail panel. If Firestore is misconfigured the health check reports `store: firestore`
but `/api/alerts` returns 500 — check that the Cloud Run service account has
`roles/datastore.user`.

## 6. Failure modes and fixes

| Symptom | Cause | Fix |
|---|---|---|
| `PERMISSION_DENIED: Datastore` | service account lacks Firestore role | `gcloud projects add-iam-policy-binding $PROJECT_ID --member=serviceAccount:<sa> --role=roles/datastore.user` |
| Container fails to start, port error | `$PORT` not honoured | The Dockerfile already uses `--port ${PORT}`; check you did not override CMD |
| `429` from Gemini | free-tier rate limit | Expected. The code falls back to mock and marks `mode: gemini-fallback`; for a demo, pre-warm alerts or stay in mock mode |
| Alerts vanish after a few minutes | using SQLite on Cloud Run (ephemeral) | Set `STORE=firestore` |
| 500 on `/api/alerts` only | Firestore index/region mismatch | recreate the database in the same region as Cloud Run |

## 7. If you must demo with no internet

Everything works offline on a laptop:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8080
```

Same UI, same numbers, SQLite instead of Firestore, mock LLM labelled `simulated`. Say that plainly
if asked — it is a deliberate design decision (requirement R7 in the report), not a workaround.
