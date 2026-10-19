# Viva / Reviewer Q&A

Answers are written to be defensible, including the ones where the honest answer is "that's a
limitation".

### 1. "What exactly is novel here? LLM + SIEM has been done."

Nothing algorithmically novel, and the report says so. The contributions are: (a) a **reproducible
labelled evaluation harness** with an explicit evasion set, so detection quality is a measured
number rather than a demo; and (b) an **explicit prompt-injection threat model for SOC triage** with
a before/after measurement (58.3% → 0%) and a defence stack where one layer — action separation —
makes a successful hijack unable to cause containment. The framing is engineering measurement, not
new science.

### 2. "You report recall 1.0. Isn't that suspicious?"

Yes, and the report states it in §7.1 before a reviewer can raise it. The corpus and rules were
co-designed, so 1.0 measures that ingestion → normalisation → fusion → ATT&CK mapping → storage are
wired correctly. The honest detector number is the evasion set: **1/6**. Both numbers are in the
report; quoting only the first would be misleading.

### 3. "Why only 13 rules? A real SOC has thousands."

Because the goal is coverage of a *complete attack lifecycle* on one host, not volume. 13 rules span
credential access, execution, persistence, privilege escalation, defence evasion and exfiltration —
enough to measure per-technique recall. SigmaHQ rules can be compiled in later via `pySigma`; the
`Rule` abstraction was built for that migration.

### 4. "Your rules are regexes. Why call it a detection engine?"

The rules are field predicates over normalised ECS events — the same abstraction Sigma uses — plus
two stateful windowed rules (R001, R002) that count failures over time, which pure regex cannot do,
and a statistical anomaly scorer over four features. The interesting claim is not sophistication
but that the fusion and mapping make coverage *measurable*.

### 5. "What happens if the LLM is wrong?"

Three things, in order. (a) The verdict is advisory: it's stored with the alert, not acted on.
(b) Containment requires a deterministic policy gate (severity ≥ high, score ≥ 0.80, rule match,
source IP present) — the model's opinion is explicitly not an input. (c) A `false_positive` verdict
against a high/critical rule match is overridden to `needs_review` by the critic pass (D5).

### 6. "What if the LLM API is down or rate-limited during the demo?"

Triage falls back to the deterministic mock and records `mode: gemini-fallback`. The alert is still
created, stored and displayed. Ingestion never depends on the LLM: the triage call sits inside a
`try/except` so a model failure cannot drop an event.

### 7. "Show me the injection defence actually working."

`POST /api/simulate/injection` runs all 12 payloads twice — once with the vulnerable prompt, once
with D1–D5 — and returns both success rates. The console's **Injection test** button renders the
same data side by side. `app/triage.py` holds the prompt envelope (`build_prompt`), the sanitiser
(`sanitize`) and the critic (`triage`).

### 8. "Is the containment real?"

No, and it is labelled `APPLY_BLOCKS=simulated` in code, API response and report. A real deployment
would call Cloud Armor or the host firewall. Claiming a live block from a JSON response would be
fabrication.

### 9. "Why Cloud Run instead of a VM or Kubernetes?"

Cloud Run scales to zero, has managed TLS, and gives a public HTTPS endpoint with no inbound port
management — the cheapest secure path to a demo URL. A VM would idle-bill and need hardening; GKE's
free allowance covers the cluster fee only, not nodes, so the nodes would cost money.

### 10. "What does this cost, precisely?"

$0.00 recurring on the free tier: Cloud Run within the request/vCPU-second allowance, Firestore
within 1 GiB and 50k reads/day, one 351 MB image (73 MB stored, measured) inside Artifact
Registry's 0.5 GB, Gemini free
tier or mock. Two things would break it: more than one image (0.5 GB registry cap) and per-event
Firestore writes (20k/day). Both shaped the implementation. Guardrails: budget alert at $1,
`--max-instances=3`, no Cloud SQL / NAT / load balancer.

### 11. "You found three bugs during evaluation. Which mattered most?"

The rule-shadowing bug: emitting only the highest-severity match per event meant a generic
`curl | bash` rule masked the specific cron rule, and an entire ATT&CK technique silently vanished
from coverage. Second: de-duplication on wall-clock instead of event time collapsed a 45-minute
replayed corpus into one alert per rule. Third: a brute-force threshold that produced six false
positives on benign authentication noise. None were visible in the UI — only the harness caught
them, which is the argument for building evaluation before the demo.

### 12. "What would you do with two more weeks?"

In priority order: (1) re-measure with a live Gemini key — triage accuracy and ASR are currently
mock; (2) add detections for the evasions that beat me (`openssl` decode-to-shell, systemd timers,
in-place truncation) and re-measure attribution to show improvement rather than assert it;
(3) move brute-force counters to Firestore so detection is correct across multiple instances;
(4) insert Pub/Sub between ingest and triage to decouple LLM latency; (5) add an uptime SLO — a
detection pipeline that silently stops is worse than no pipeline.

### 13. "Is any of this usable in production?"

No, and the report says so in §7.3. No authentication on the console, synthetic telemetry, simulated
containment, per-instance state, no long-term retention, no on-call story. It is a measured
reference architecture and a teaching artefact, not a product.

### 14. "Where does the ground truth come from, and could labels leak?"

`lab/gen_corpus.py` writes `label` and `technique` per event. At the ingest boundary,
`Event.from_raw()` filters through an explicit allow-list of eleven data fields, so neither field
can reach detection. The anomaly baseline is trained on the benign subset only. Without that
filter, the evaluation would be meaningless — which is why it's an assertion in the code, not a
convention.
