#!/bin/sh
# WPScan — détecte les vulnérabilités WordPress (plugins, thèmes, users, core)
# Variables attendues : TARGET_URL, TARGET_NAME, COLLECTOR_URL, WPSCAN_API_TOKEN (optionnel)
set -e

STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
OUTPUT_FILE=$(mktemp /tmp/wpscan-XXXXXX.json)

echo "[WPScan] Scan de ${TARGET_URL}..."

# Construire les options
WP_OPTS="--url ${TARGET_URL} --format json --output ${OUTPUT_FILE} --no-banner"
WP_OPTS="${WP_OPTS} --enumerate vp,vt,u1-3,cb,dbe"  # plugins vulnérables, thèmes, users 1-3, config backups, DB exports
WP_OPTS="${WP_OPTS} --plugins-detection mixed"
WP_OPTS="${WP_OPTS} --random-user-agent"
WP_OPTS="${WP_OPTS} --request-timeout 30"

# Clé API optionnelle (augmente la base CVE)
if [ -n "${WPSCAN_API_TOKEN:-}" ]; then
    WP_OPTS="${WP_OPTS} --api-token ${WPSCAN_API_TOKEN}"
fi

wpscan ${WP_OPTS} || true

echo "[WPScan] Traitement des résultats..."

PAYLOAD=$(python3 - <<'PYEOF'
import json, os, sys

output_file = os.environ.get("OUTPUT_FILE", "")
target_url  = os.environ.get("TARGET_URL", "")
started_at  = os.environ.get("STARTED_AT", "")

try:
    with open(output_file) as f:
        data = json.load(f)
except Exception as e:
    print(json.dumps({
        "started_at": started_at,
        "findings": [],
        "raw_output": {"error": str(e)}
    }))
    sys.exit(0)

findings = []

def add_finding(severity, title, description, url=None, cve_ids=None, cvss=None, remediation=None):
    findings.append({
        "severity": severity,
        "title": title,
        "description": description or "",
        "url": url or target_url,
        "cvss_score": cvss,
        "cve_ids": cve_ids or [],
        "remediation": remediation or "",
    })

# ── Version WordPress
wp_version = data.get("version", {})
if wp_version:
    ver = wp_version.get("number", "?")
    if wp_version.get("vulnerabilities"):
        for v in wp_version["vulnerabilities"]:
            cve_ids = [r for r in v.get("references", {}).get("cve", [])]
            add_finding(
                severity="HIGH",
                title=f"WordPress {ver} vulnérable : {v.get('title', '')}",
                description=v.get("title", ""),
                cve_ids=cve_ids,
                remediation="Mettre à jour WordPress vers la dernière version stable.",
            )
    else:
        add_finding(
            severity="INFO",
            title=f"WordPress version {ver} détectée",
            description=f"Version WordPress : {ver}",
        )

# ── Plugins vulnérables
for slug, plugin in data.get("plugins", {}).items():
    pver = plugin.get("version", {}).get("number", "?")
    for v in plugin.get("vulnerabilities", []):
        cve_ids = v.get("references", {}).get("cve", [])
        add_finding(
            severity="HIGH",
            title=f"Plugin {slug} ({pver}) vulnérable : {v.get('title', '')}",
            description=v.get("title", ""),
            url=plugin.get("location", target_url),
            cve_ids=cve_ids,
            remediation=f"Mettre à jour ou désactiver le plugin {slug}.",
        )

# ── Thèmes vulnérables
for slug, theme in data.get("themes", {}).items():
    for v in theme.get("vulnerabilities", []):
        cve_ids = v.get("references", {}).get("cve", [])
        add_finding(
            severity="MEDIUM",
            title=f"Thème {slug} vulnérable : {v.get('title', '')}",
            description=v.get("title", ""),
            cve_ids=cve_ids,
            remediation=f"Mettre à jour ou remplacer le thème {slug}.",
        )

# ── Utilisateurs énumérés
users = data.get("users", {})
if users:
    user_list = ", ".join(users.keys())
    add_finding(
        severity="MEDIUM",
        title=f"Énumération utilisateurs WordPress : {user_list}",
        description=f"Les comptes suivants ont été énumérés via l'API REST ou /author/ : {user_list}",
        remediation="Désactiver l'API REST pour les non-authentifiés ou utiliser un plugin de sécurité (Wordfence, iThemes Security).",
    )

# ── Fichiers sensibles exposés (config backups, DB exports)
for item in data.get("config_backups", {}).values():
    add_finding(
        severity="CRITICAL",
        title="Sauvegarde de configuration WordPress exposée",
        description=f"Fichier sensible accessible publiquement : {item}",
        url=item if isinstance(item, str) else target_url,
        remediation="Supprimer immédiatement les sauvegardes de wp-config.php accessibles publiquement.",
    )

for item in data.get("db_exports", {}).values():
    add_finding(
        severity="CRITICAL",
        title="Export de base de données WordPress exposé",
        description=f"Dump SQL accessible publiquement : {item}",
        url=item if isinstance(item, str) else target_url,
        remediation="Supprimer immédiatement le fichier SQL et vérifier les permissions serveur.",
    )

# ── XML-RPC activé
if data.get("xmlrpc", {}).get("found"):
    add_finding(
        severity="MEDIUM",
        title="XML-RPC WordPress activé",
        description="Le endpoint xmlrpc.php est accessible. Risque de brute-force et d'amplification DDoS.",
        url=f"{target_url.rstrip('/')}/xmlrpc.php",
        remediation="Désactiver XML-RPC si non nécessaire (filtre xmlrpc_enabled ou .htaccess).",
    )

# ── readme.html exposé (fuite de version)
if data.get("readme", {}).get("found"):
    add_finding(
        severity="LOW",
        title="readme.html WordPress accessible",
        description="Le fichier readme.html révèle la version WordPress aux attaquants.",
        url=f"{target_url.rstrip('/')}/readme.html",
        remediation="Supprimer ou bloquer l'accès à readme.html via le serveur web.",
    )

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
    "${COLLECTOR_URL}/results/wpscan/${TARGET_NAME}"

echo "[WPScan] Terminé — $(echo "${PAYLOAD}" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['findings']))" 2>/dev/null || echo '?') findings."
