#!/usr/bin/env bash
# Deploy Aegis-SOC to Google Cloud on the free tier.
#
#   export PROJECT_ID=my-project
#   export REGION=us-central1
#   export GEMINI_API_KEY=...        # optional; omit to run in mock mode
#   ./deploy.sh
#
# Run this from Cloud Shell (gcloud + docker already present) or any machine with
# gcloud authenticated as a project owner.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-us-central1}"          # must be a free-tier region
SERVICE="aegis-soc"
REPO="aegis"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${SERVICE}:latest"
BUCKET="${PROJECT_ID}-aegis-logs"

say() { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }

say "Project ${PROJECT_ID} / region ${REGION}"
gcloud config set project "${PROJECT_ID}" >/dev/null

say "Enabling APIs (only what we use)"
gcloud services enable \
  run.googleapis.com \
  firestore.googleapis.com \
  storage.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  secretmanager.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com

say "Firestore (native mode) — the alert store"
if ! gcloud firestore databases describe --database="(default)" >/dev/null 2>&1; then
  gcloud firestore databases create --location="${REGION}" --type=firestore-native
else
  echo "    already exists, skipping"
fi

say "Artifact Registry — free tier is only 0.5 GB, so one image only"
if ! gcloud artifacts repositories describe "${REPO}" --location="${REGION}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${REPO}" \
    --repository-format=docker --location="${REGION}" \
    --description="Aegis-SOC images"
fi

say "Cloud Storage — corpus + archive (14-day lifecycle keeps us inside 5 GB)"
if ! gcloud storage buckets describe "gs://${BUCKET}" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${BUCKET}" --location="${REGION}" \
    --uniform-bucket-level-access
  LIFECYCLE="$(mktemp)"
  cat >"${LIFECYCLE}" <<'JSON'
{"lifecycle":{"rule":[{"action":{"type":"Delete"},"condition":{"age":14}}]}}
JSON
  gcloud storage buckets update "gs://${BUCKET}" --lifecycle-file="${LIFECYCLE}"
  rm -f "${LIFECYCLE}"
fi

if [[ -n "${GEMINI_API_KEY:-}" ]]; then
  say "Storing the Gemini key in Secret Manager (never in an env var on disk)"
  if gcloud secrets describe gemini-key >/dev/null 2>&1; then
    printf '%s' "${GEMINI_API_KEY}" | gcloud secrets versions add gemini-key --data-file=-
  else
    printf '%s' "${GEMINI_API_KEY}" | gcloud secrets create gemini-key --data-file=- --replication-policy=automatic
  fi
else
  echo "    GEMINI_API_KEY not set — the service will run in mock mode (safe for demos)"
fi

say "Building the image with Cloud Build (2,500 free minutes/month)"
gcloud builds submit --tag "${IMAGE}" --timeout=20m .

say "Deploying to Cloud Run (512 MiB, max 3 instances)"
DEPLOY_ARGS=(
  run deploy "${SERVICE}"
  --image "${IMAGE}"
  --region "${REGION}"
  --platform managed
  --allow-unauthenticated
  --memory 512Mi
  --cpu 1
  --max-instances 3
  --timeout 60
  --set-env-vars "STORE=firestore,GCP_PROJECT=${PROJECT_ID},AUTO_TRIAGE=1,DEDUPE_SECONDS=300,APPLY_BLOCKS=simulated"
)
if [[ -n "${GEMINI_API_KEY:-}" ]]; then
  DEPLOY_ARGS+=(--set-secrets "GEMINI_API_KEY=gemini-key:latest")
fi
gcloud "${DEPLOY_ARGS[@]}"

URL="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.url)')"
say "Deployed: ${URL}"

cat <<EOF

Post-deploy checklist (5 minutes, do not skip):

  1. curl ${URL}/api/health          → expect {"status":"ok","store":"firestore",...}
  2. curl -X POST ${URL}/api/simulate/attack    → expect alerts: 12
  3. Billing → Budgets & alerts → create a budget of \$1 with email alerts
  4. Cloud Run → ${SERVICE} → confirm Max instances = 3
  5. Firestore → alerts collection → confirm documents are arriving

Cost guardrails already applied by this script: 512 MiB / 1 vCPU / max 3 instances,
14-day object lifecycle, one image. Still to do by hand: the \$1 budget alert (step 3),
because it needs your billing account ID.
EOF
