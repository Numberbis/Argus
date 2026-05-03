#!/bin/sh
# Scanner Retire.js — détecte les bibliothèques JavaScript vulnérables
# Variables d'environnement : TARGET_URL, TARGET_NAME, COLLECTOR_URL
set -e

TARGET_URL="${TARGET_URL:?Variable TARGET_URL manquante}"
TARGET_NAME="${TARGET_NAME:?Variable TARGET_NAME manquante}"
COLLECTOR_URL="${COLLECTOR_URL:-http://collector:8080}"

WORK_DIR="/tmp/retirejs-${TARGET_NAME}"
JS_DIR="${WORK_DIR}/js"
REPORT_FILE="${WORK_DIR}/report.json"

mkdir -p "${JS_DIR}"

echo "[RetireJS] Analyse de ${TARGET_URL}"

# 1. Téléchargement de la page principale
PAGE_FILE="${WORK_DIR}/index.html"
curl -sSL --max-time 30 \
    -A "Mozilla/5.0 (compatible; SecurityAudit/1.0)" \
    "${TARGET_URL}" -o "${PAGE_FILE}" || {
    echo "[RetireJS] Impossible de télécharger ${TARGET_URL}" >&2
    exit 1
}

# 2. Extraction des URLs de scripts JS (src absolues et relatives)
BASE_URL=$(echo "${TARGET_URL}" | sed 's|/[^/]*$||')
SCHEME=$(echo "${TARGET_URL}" | cut -d: -f1)
HOST=$(echo "${TARGET_URL}" | sed 's|.*://||' | cut -d/ -f1)

grep -oE 'src="[^"]+\.js[^"]*"' "${PAGE_FILE}" \
    | sed 's/src="//;s/"//' \
    | while read -r js_url; do
        case "${js_url}" in
            http://*|https://*)  full_url="${js_url}" ;;
            //*) full_url="${SCHEME}:${js_url}" ;;
            /*)  full_url="${SCHEME}://${HOST}${js_url}" ;;
            *)   full_url="${BASE_URL}/${js_url}" ;;
        esac
        fname=$(echo "${full_url}" | md5sum | cut -c1-8).js
        curl -sSL --max-time 15 "${full_url}" -o "${JS_DIR}/${fname}" 2>/dev/null || true
    done

JS_COUNT=$(find "${JS_DIR}" -name "*.js" | wc -l)
echo "[RetireJS] ${JS_COUNT} fichier(s) JS téléchargé(s)"

# 3. Analyse avec retire.js
if [ "${JS_COUNT}" -eq 0 ]; then
    echo "[RetireJS] Aucun fichier JS trouvé — envoi scan vide"
    cat > "${REPORT_FILE}" <<EOF
[]
EOF
else
    retire --path "${JS_DIR}" \
           --outputformat json \
           --outputpath "${REPORT_FILE}" \
           --exitwith 0 2>/dev/null || true
fi

# 4. Conversion en payload Collector (Python inline)
STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

python3 - <<PYEOF
import json, sys, urllib.request

report_file = "${REPORT_FILE}"
target_url  = "${TARGET_URL}"
target_name = "${TARGET_NAME}"
collector   = "${COLLECTOR_URL}"
started_at  = "${STARTED_AT}"

try:
    with open(report_file) as f:
        raw = json.load(f)
except Exception:
    raw = []

# Normalisation des résultats retire.js (format varie selon version)
findings = []
for entry in (raw if isinstance(raw, list) else raw.get("data", [])):
    file_path = entry.get("file", "")
    for result in entry.get("results", []):
        component   = result.get("component", "unknown")
        version     = result.get("version", "?")
        for vuln in result.get("vulnerabilities", [{}]):
            severity = "HIGH" if vuln.get("severity") in ("high", "critical") else "MEDIUM"
            cves     = vuln.get("identifiers", {}).get("CVE", [])
            findings.append({
                "severity":    severity,
                "title":       f"Bibliothèque JS vulnérable : {component} v{version}",
                "description": vuln.get("info", [""])[0] if vuln.get("info") else "",
                "url":         target_url,
                "cvss_score":  None,
                "cve_ids":     cves,
                "remediation": f"Mettre à jour {component} vers la dernière version stable.",
            })

payload = {
    "started_at": started_at,
    "target_url": target_url,
    "findings":   findings,
    "raw_output": raw if isinstance(raw, list) else [],
}

data = json.dumps(payload).encode()
req  = urllib.request.Request(
    f"{collector}/results/retirejs/{target_name}",
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=30) as resp:
    result = json.loads(resp.read())

print(f"[RetireJS] {len(findings)} finding(s) envoyé(s) — scan_id={result['scan_id']}")
PYEOF
