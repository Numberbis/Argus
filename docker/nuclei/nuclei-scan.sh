#!/bin/sh
set -e

STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT_FILE=$(mktemp /tmp/nuclei-XXXXXX.jsonl)

echo "[Nuclei] Scan de ${TARGET_URL}..."
nuclei \
    -target "${TARGET_URL}" \
    -severity critical,high,medium,low \
    -json-export "${OUTPUT_FILE}" \
    -silent \
    -no-color \
    -timeout 10 \
    -bulk-size 25 || true

echo "[Nuclei] Envoi des résultats..."
PAYLOAD=$(python3 -c "
import json, sys

findings = []
raw = []

with open('${OUTPUT_FILE}') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        item = json.loads(line)
        raw.append(item)

        sev_map = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW', 'info': 'INFO'}
        info = item.get('info', {})
        findings.append({
            'severity': sev_map.get(info.get('severity', 'info').lower(), 'INFO'),
            'title': info.get('name', item.get('template-id', '')),
            'description': info.get('description', ''),
            'url': item.get('matched-at', '${TARGET_URL}'),
            'cvss_score': info.get('classification', {}).get('cvss-score'),
            'cve_ids': info.get('classification', {}).get('cve-id', []),
            'remediation': info.get('remediation', '')
        })

print(json.dumps({'started_at': '${STARTED_AT}', 'findings': findings, 'raw_output': raw}))
")

curl -sf -X POST \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD}" \
    "${COLLECTOR_URL}/results/nuclei/${TARGET_NAME}"

echo "[Nuclei] Terminé — $(wc -l < ${OUTPUT_FILE}) findings."
