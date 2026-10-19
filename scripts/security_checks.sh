#!/usr/bin/env bash
# Local mirror of the CI security gates. Run before pushing so CI rarely surprises you.
#
#   ./scripts/security_checks.sh
#
# Requires: ruff, bandit, pip-audit (pip install ruff bandit pip-audit)
# Docker is used for trivy/gitleaks/hadolint so nothing needs sudo.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
note() { printf "\n\033[1;36m== %s\033[0m\n" "$*"; }
result() { if [ "$1" -eq 0 ]; then echo "   PASS"; else echo "   FAIL"; fail=1; fi; }

note "ruff (lint)"
ruff check app lab scripts tests; result $?

note "pytest (unit tests)"
python -m pytest -q; result $?

note "bandit (SAST, fail on MEDIUM+)"
bandit -ll -r app -f txt >/tmp/bandit.txt 2>&1; rc=$?
tail -12 /tmp/bandit.txt; result $rc

note "pip-audit (known CVEs in dependencies)"
pip-audit -r requirements.txt; result $?

note "hadolint (Dockerfile)"
docker run --rm -i hadolint/hadolint:latest < Dockerfile; result $?

note "gitleaks (secrets, full history)"
docker run --rm -v "$PWD":/repo zricethezav/gitleaks:latest \
  detect --source=/repo --no-banner --redact; result $?

note "trivy (image, actionable only)"
docker build -q -t aegis-soc:local . || { echo "build failed"; exit 1; }
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
  image --quiet --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 aegis-soc:local
result $?

note "trivy (image, full inventory — informational)"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
  image --quiet --severity HIGH,CRITICAL aegis-soc:local 2>/dev/null | grep -E "^Total:" || true

echo
if [ "$fail" -eq 0 ]; then
  echo "ALL GATES PASSED"
else
  echo "ONE OR MORE GATES FAILED"
fi
exit "$fail"
