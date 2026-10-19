# Single image for API + console. Kept small on purpose: Artifact Registry's
# free tier is 0.5 GB/month, so no torch, no sklearn, no Node toolchain.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    STORE=firestore \
    AUTO_TRIAGE=1

# Patch OS packages at build time: the base image ships HIGH-severity CVEs in
# util-linux and friends that Trivy flags. Rebuild regularly to pick up fixes.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY data ./data
COPY lab ./lab
COPY scripts ./scripts
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Non-root user: Cloud Run allows it, and it removes a whole privilege class.
# Numeric UID (not a name) so hadolint DL3066 is satisfied and the host can
# always resolve it.
RUN useradd --create-home --uid 10001 aegis && chown -R aegis:aegis /app
USER 10001

CMD ["/app/docker-entrypoint.sh"]
