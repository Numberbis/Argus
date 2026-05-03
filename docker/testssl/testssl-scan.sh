#!/bin/bash
set -e

HOST=$(echo "${TARGET_URL}" | sed 's|https\?://||' | cut -d'/' -f1)
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT_FILE=$(mktemp /tmp/testssl-XXXXXX.json)

echo "[testssl] Analyse TLS/SSL de ${HOST}..."
/opt/testssl/testssl.sh \
    --jsonfile "${OUTPUT_FILE}" \
    --quiet \
    --color 0 \
    "${HOST}" || true

echo "[testssl] Envoi des résultats..."
PAYLOAD=$(python3 -c "
import json, sys

with open('${OUTPUT_FILE}') as f:
    raw = json.load(f)

severity_map = {'CRITICAL': 'CRITICAL', 'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW', 'OK': 'INFO', 'INFO': 'INFO', 'WARN': 'MEDIUM'}
findings = []

for entry in raw:
    sev_raw = entry.get('severity', 'INFO').upper()
    sev = severity_map.get(sev_raw, 'INFO')
    if sev_raw in ('CRITICAL', 'HIGH', 'MEDIUM', 'WARN'):
        findings.append({
            'severity': sev,
            'title': entry.get('id', '') + ': ' + entry.get('finding', ''),
            'description': entry.get('finding', ''),
            'url': '${TARGET_URL}',
            'cvss_score': None,
            'cve_ids': [entry['cve']] if entry.get('cve') else [],
            'remediation': ''
        })

print(json.dumps({'started_at': '${STARTED_AT}', 'findings': findings, 'raw_output': raw}))
")

curl -sf -X POST \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD}" \
    "${COLLECTOR_URL}/results/testssl/${TARGET_NAME}"

echo "[testssl] Terminé."
