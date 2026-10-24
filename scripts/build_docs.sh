#!/usr/bin/env bash
# Rebuild every PDF deliverable with consistent author/title metadata.
# Run from the repository root.
set -euo pipefail

AUTHOR="Rudra Pratap"
FONT=(--pdf-engine=xelatex -V mainfont="DejaVu Sans" -V monofont="DejaVu Sans Mono"
      -V geometry:margin=2cm)
META=(--metadata "author=${AUTHOR}" --metadata "lang=en-GB")

build() {  # $1 = source md, $2 = output pdf, $3 = title
  pandoc "$1" -o "$2" "${FONT[@]}" "${META[@]}" \
    --metadata "title=$3" --toc
  printf '  %-42s %s\n' "$(basename "$2")" "$(pdfinfo "$2" | awk '/^Pages:/{print $2" pages"}')"
}

echo "building PDFs:"
build REPORT.md                        docs/Aegis-SOC-Report.pdf           "Aegis-SOC: Cloud-Native, AI-Assisted Security Operations Platform"
build SECURITY-CICD-REPORT.md          docs/Aegis-SOC-Security-CICD.pdf    "Aegis-SOC: CI/CD, Security Assurance and Resource Consumption"
build docs/PRESENTATION.md             docs/Aegis-SOC-Presentation.pdf     "Aegis-SOC: Presentation Guide"
build docs/PROJECT-DETAILS.md          docs/Aegis-SOC-Project-Details.pdf  "Aegis-SOC: Complete Project Dossier"

echo "metadata check:"
for f in docs/*.pdf; do
  printf '  %-42s author=%s\n' "$(basename "$f")" "$(pdfinfo "$f" | awk -F': *' '/^Author:/{print $2}')"
done
