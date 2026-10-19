# 4-Day Delivery Plan

The software is already written, tested and measured. Your four days are for **deploying it,
capturing evidence, and rehearsing** — not for building. Resist the urge to add features; the
project is judged on a working demo plus an honest report.

---

## Day 1 — Get it live (6–7 h)

| Time | Task | Done when |
|---|---|---|
| 0:30 | Run locally: `pip install -r requirements.txt`, `python lab/gen_corpus.py`, `uvicorn app.main:app --port 8080` | 12 alerts appear when you press *Run attack simulation* |
| 0:30 | `python scripts/eval.py` | `evals/results.json` written; note the four numbers |
| 2:00 | Create GCP project, attach billing, **create the $1 budget alert first** | Budget alert email received |
| 0:30 | `gcloud auth login`, `export PROJECT_ID=... REGION=us-central1`, `./deploy.sh` | Script prints a `run.app` URL |
| 0:30 | Verify: `/api/health` says `store: firestore`; `/api/simulate/attack` returns ~12 | All three curls pass |
| 1:00 | Open the URL, click everything, find what breaks | List of anything visually off |
| 0:30 | Commit + push to a public GitHub repo | Repo URL works in incognito |

**If the deploy fails:** do not burn the day on GCP. Demo locally (the UI is identical), fix the
deploy in the background, and tell your guide it runs on Cloud Run once the URL is green. Never
present a dead URL.

---

## Day 2 — Evidence (5–6 h)

| Time | Task |
|---|---|
| 1:00 | Set `GEMINI_API_KEY`, re-run `python scripts/eval.py`. This replaces the mock ASR/triage numbers with real ones — required before quoting them in the report |
| 0:30 | Update `REPORT.md` §6.4 with the real numbers, and delete the mock-mode caveat sentence **only if** the run was genuinely live |
| 1:30 | Screenshots for the report: console with alerts (1600×1000), alert detail with triage, injection panel before/after, `/api/health` JSON, GCP console showing $0 billing |
| 1:30 | Fill the `⟨X⟩%` placeholders in `README.md`/resume bullets with the measured values |
| 1:00 | Export the report: `pandoc REPORT.md -o REPORT.docx` (or PDF if you have a LaTeX engine) |

**Screenshot tip:** reset first (`POST /api/reset`), then run the attack simulation — otherwise
you'll capture leftovers from earlier clicking.

---

## Day 3 — Rehearse (4–5 h)

| Time | Task |
|---|---|
| 1:30 | Build 10–12 slides: problem → architecture → demo → results (4 numbers) → limitations → future work |
| 1:00 | Run `docs/DEMO_SCRIPT.md` three times end to end, timed. If it's over 4 minutes, cut the middle, not the honesty close |
| 0:30 | Record a backup video of a clean run (screen + voice). If the live demo dies, you play this |
| 1:00 | Read `docs/VIVA_QA.md` aloud. You should be able to answer Q2 ("recall 1.0 is suspicious") without hesitation — that question *will* come |
| 0:30 | Pre-load: console tab, report at §6.3, terminal with the server already running |

**Rehearsal checklist**

- [ ] Server already started *before* you present (never start it live)
- [ ] Alerts reset, then simulation run in front of the audience
- [ ] You know which row is the reverse shell and which is the cron job by position
- [ ] You can state 13/13, 1/6 and 58%→0% without looking
- [ ] You can say "the 1.0 is circular, here's why" in one sentence

---

## Day 4 — Buffer and submit (3 h)

| Time | Task |
|---|---|
| 1:00 | Fix anything that broke on Day 3; re-run `scripts/eval.py` and confirm the numbers still match the report |
| 0:30 | Final repo pass: no `.env`, no API key in git history, `README` renders |
| 0:30 | Submit report + repo link + (optional) live URL |
| 1:00 | Free: read `REPORT.md` §7.3 once more so you know your own limitations better than the examiner does |

---

## The four numbers to memorise

| Number | Meaning |
|---|---|
| **13/13** | Techniques detected on the labelled corpus (recall 1.000 — and why that's a weak claim) |
| **1/6** | Evasions correctly attributed — the honest detector ceiling |
| **58.3% → 0%** | Prompt-injection attack success rate, undefended vs D1–D5 |
| **$0.00** | Total cloud spend, with the guardrails that keep it there |

## What not to do

- Don't add features in these four days. Every new rule is a new way the demo can break.
- Don't quote the mock triage numbers as if a model produced them. The report says which mode ran;
  keep that sentence honest.
- Don't claim live containment. It is `APPLY_BLOCKS=simulated`, and the report says so.
- Don't promise "we can detect any attack". You measured 1/6 on evasions — say that instead; it
  reads as competence, not weakness.
