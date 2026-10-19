#!/bin/sh
# Exec-form entrypoint: satisfies hadolint DL3025 while still expanding $PORT,
# which Cloud Run injects at runtime (a plain JSON CMD cannot do both).
set -eu
exec uvicorn app.main:app \
  --host "${HOST:-0.0.0.0}" \
  --port "${PORT:-8080}" \
  --workers "${WORKERS:-1}" \
  --log-level "${LOG_LEVEL:-info}"
