# Single image for API + console. Kept small on purpose: Artifact Registry's
# free tier is 0.5 GB/month, so no torch, no sklearn, no Node toolchain.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    STORE=firestore \
    AUTO_TRIAGE=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY data ./data
COPY lab ./lab
COPY scripts ./scripts

# Cloud Run injects $PORT; 1 worker keeps memory inside the 512 MiB default.
CMD exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers 1
