#!/bin/sh
set -e

STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT_FILE=$(mktemp /tmp/nikto-XXXXXX.json)

echo "[Nikto] Scan de ${TARGET_URL}..."
perl /nikto/program/nikto.pl \
    -h "${TARGET_URL}" \
    -Format json \
    -output "${OUTPUT_FILE}" \
    -nointeractive \
    -timeout 10 \
    -maxtime 1800 || true  # Nikto retourne != 0 si vulnérabilités trouvées

echo "[Nikto] Envoi des résultats au collector..."
PAYLOAD=$(python3 -c "
import json, sys
with open('${OUTPUT_FILE}') as f:
    raw = json.load(f)
findings = []
for vuln in raw.get('vulnerabilities', []):
    findings.append({
        'severity': 'MEDIUM',
        'title': vuln.get('msg', ''),
        'description': vuln.get('msg', ''),
        'url': '${TARGET_URL}' + vuln.get('url', ''),
        'cvss_score': None,
        'cve_ids': [vuln['osvdbid']] if vuln.get('osvdbid') else [],
        'remediation': ''
    })
print(json.dumps({'started_at': '${STARTED_AT}', 'findings': findings, 'raw_output': raw}))
")

curl -sf -X POST \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD}" \
    "${COLLECTOR_URL}/results/nikto/${TARGET_NAME}"

echo "[Nikto] Terminé."
