#!/bin/sh
set -e

# Extraction du hostname depuis l'URL
HOST=$(echo "${TARGET_URL}" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
TARGET="${TARGET_IP:-$HOST}"
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT_FILE=$(mktemp /tmp/nmap-XXXXXX.xml)

echo "[Nmap] Scan de ${TARGET}..."
nmap -sV -sC --script vuln,ssl-enum-ciphers \
     -oX "${OUTPUT_FILE}" \
     --max-retries 2 \
     --host-timeout 15m \
     "${TARGET}" || true

echo "[Nmap] Conversion et envoi des résultats..."
PAYLOAD=$(python3 -c "
import xml.etree.ElementTree as ET, json, sys

tree = ET.parse('${OUTPUT_FILE}')
root = tree.getroot()
findings = []

for host in root.findall('host'):
    for port in host.findall('.//port'):
        state = port.find('state')
        if state is None or state.get('state') != 'open':
            continue
        service = port.find('service')
        portid = port.get('portid')
        svc_name = service.get('name', '') if service is not None else ''
        product = service.get('product', '') if service is not None else ''
        version = service.get('version', '') if service is not None else ''

        # Script outputs (vuln scripts)
        for script in port.findall('script'):
            script_id = script.get('id', '')
            output = script.get('output', '')
            if 'VULNERABLE' in output.upper():
                findings.append({
                    'severity': 'HIGH',
                    'title': f'Nmap script {script_id}: vulnerable',
                    'description': output,
                    'url': '${TARGET_URL}',
                    'cvss_score': None,
                    'cve_ids': [],
                    'remediation': ''
                })

        findings.append({
            'severity': 'INFO',
            'title': f'Port {portid} ouvert ({svc_name} {product} {version})',
            'description': f'Port {portid}/tcp ouvert, service: {svc_name} {product} {version}',
            'url': '${TARGET_URL}',
            'cvss_score': None,
            'cve_ids': [],
            'remediation': ''
        })

raw = ET.tostring(root, encoding='unicode')
print(json.dumps({'started_at': '${STARTED_AT}', 'findings': findings, 'raw_output': {'xml': raw}}))
")

curl -sf -X POST \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD}" \
    "${COLLECTOR_URL}/results/nmap/${TARGET_NAME}"

echo "[Nmap] Terminé."
