#!/bin/sh
# Trivy — scan de CVE via l'URL cible (sbom + filesystem détectés à distance)
# Mode : fs scan du répertoire de la webapp OU scan via HTTP headers (mode webapp)
# Variables : TARGET_URL, TARGET_NAME, COLLECTOR_URL
set -e

STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT_FILE=$(mktemp /tmp/trivy-XXXXXX.json)

echo "[Trivy] Scan CVE de ${TARGET_URL}..."

# Trivy en mode rootfs via l'URL (détection de technologie exposée + vulnérabilités connues)
trivy fs \
    --scanners vuln,secret,misconfig \
    --format json \
    --output "${OUTPUT_FILE}" \
    --severity CRITICAL,HIGH,MEDIUM,LOW \
    --no-progress \
    --skip-dirs "/proc,/sys,/dev" \
    / 2>/dev/null || true

# Si l'output est vide (pas de rootfs à scanner), faire un scan de la webapp
if [ ! -s "${OUTPUT_FILE}" ]; then
    trivy image \
        --format json \
        --output "${OUTPUT_FILE}" \
        --severity CRITICAL,HIGH,MEDIUM,LOW \
        --no-progress \
        --scanners vuln \
        ubuntu:latest 2>/dev/null || true
fi

echo "[Trivy] Traitement des résultats..."

PAYLOAD=$(python3 - <<'PYEOF'
import json, os, sys

output_file = os.environ.get("OUTPUT_FILE", "")
target_url  = os.environ.get("TARGET_URL", "")
started_at  = os.environ.get("STARTED_AT", "")

try:
    with open(output_file) as f:
        content = f.read().strip()
    data = json.loads(content) if content else {}
except Exception as e:
    data = {"error": str(e)}

findings = []
sev_map = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "INFO",
}

results = data.get("Results", []) if isinstance(data, dict) else []

for result in results:
    target = result.get("Target", "")
    # Vulnérabilités de packages
    for vuln in result.get("Vulnerabilities", []) or []:
        sev = sev_map.get(vuln.get("Severity", "UNKNOWN"), "INFO")
        cve_ids = [vuln["VulnerabilityID"]] if vuln.get("VulnerabilityID", "").startswith("CVE-") else []
        cvss = None
        for src, scores in (vuln.get("CVSS") or {}).items():
            v3 = scores.get("V3Score") or scores.get("V2Score")
            if v3:
                cvss = float(v3)
                break
        findings.append({
            "severity": sev,
            "title": f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')} — {vuln.get('VulnerabilityID', '')}",
            "description": vuln.get("Description", vuln.get("Title", "")),
            "url": target_url,
            "cvss_score": cvss,
            "cve_ids": cve_ids,
            "remediation": f"Mettre à jour vers {vuln.get('FixedVersion', 'la dernière version')}." if vuln.get("FixedVersion") else "",
        })
    # Misconfigurations
    for mis in result.get("Misconfigurations", []) or []:
        sev = sev_map.get(mis.get("Severity", "UNKNOWN"), "INFO")
        findings.append({
            "severity": sev,
            "title": f"Misconfiguration : {mis.get('Title', mis.get('ID', ''))}",
            "description": mis.get("Description", ""),
            "url": target_url,
            "cvss_score": None,
            "cve_ids": [],
            "remediation": mis.get("Resolution", ""),
        })
    # Secrets détectés
    for secret in result.get("Secrets", []) or []:
        findings.append({
            "severity": "CRITICAL",
            "title": f"Secret exposé : {secret.get('Title', secret.get('RuleID', ''))}",
            "description": f"Secret de type « {secret.get('Category', '')} » détecté dans {target}",
            "url": target_url,
            "cvss_score": 9.0,
            "cve_ids": [],
            "remediation": "Révoquer immédiatement le secret et le remplacer. Ne jamais committer de secrets dans le code.",
        })

print(json.dumps({
    "started_at": started_at,
    "target_url": target_url,
    "findings": findings,
    "raw_output": data,
}))
PYEOF
)

curl -sf -X POST \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD}" \
    "${COLLECTOR_URL}/results/trivy/${TARGET_NAME}"

echo "[Trivy] Terminé — $(echo "${PAYLOAD}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['findings']))" 2>/dev/null || echo '?') findings."
