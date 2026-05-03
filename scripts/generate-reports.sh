#!/usr/bin/env bash
# Génère un rapport HTML d'audit de sécurité pour chaque site de config/websites.yml
#
# Usage :
#   ./scripts/generate-reports.sh                  # tous les sites
#   ./scripts/generate-reports.sh buildweb         # un seul site
#   ./scripts/generate-reports.sh --skip-observatory  # sans Mozilla Observatory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
PYTHON="$ROOT_DIR/venv_audit/bin/python"
AUDIT_SCRIPT="$SCRIPT_DIR/audit-now.py"
CONFIG="$ROOT_DIR/config/websites.yml"
REPORTS_DIR="$ROOT_DIR/reports"
DATE=$(date +%Y-%m-%d)

# ── Options ───────────────────────────────────────────────────────────────────

TARGET=""
EXTRA_ARGS=""

for arg in "$@"; do
    case "$arg" in
        --skip-observatory) EXTRA_ARGS="--skip-observatory" ;;
        --*)                echo "Option inconnue : $arg" ; exit 1 ;;
        *)                  TARGET="$arg" ;;
    esac
done

# ── Lecture des sites depuis websites.yml ─────────────────────────────────────

SITES=$("$PYTHON" - "$CONFIG" <<'EOF'
import yaml, sys
with open(sys.argv[1]) as f:
    sites = yaml.safe_load(f)["websites"]
for s in sites:
    print(s["name"])
EOF
)

# Filtre si un site spécifique est demandé
if [ -n "$TARGET" ]; then
    SITES=$(echo "$SITES" | grep -i "^${TARGET}$" || true)
    if [ -z "$SITES" ]; then
        echo "❌ Site '$TARGET' introuvable dans $CONFIG"
        exit 1
    fi
fi

mkdir -p "$REPORTS_DIR"

# ── Génération des rapports ───────────────────────────────────────────────────

COUNT=0
ERRORS=0
GENERATED=()

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Génération des rapports d'audit — $DATE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

while IFS= read -r site; do
    [ -z "$site" ] && continue

    # Nom de fichier : minuscules, espaces → tirets
    slug=$(echo "$site" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
    output="$REPORTS_DIR/audit-${slug}-${DATE}.html"

    echo ""
    echo "▶ $site"

    if "$PYTHON" "$AUDIT_SCRIPT" \
        --target "$site" \
        --output "$output" \
        $EXTRA_ARGS; then
        GENERATED+=("$output")
        COUNT=$((COUNT + 1))
    else
        echo "  ⚠  Échec pour $site"
        ERRORS=$((ERRORS + 1))
    fi

done <<< "$SITES"

# ── Résumé ────────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  $COUNT rapport(s) généré(s)  |  $ERRORS erreur(s)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
for f in "${GENERATED[@]}"; do
    echo "  ✓ $f"
done
echo ""

# Ouvre le dossier reports/ si un seul site (pratique)
if [ ${#GENERATED[@]} -eq 1 ]; then
    xdg-open "${GENERATED[0]}" 2>/dev/null || open "${GENERATED[0]}" 2>/dev/null || true
fi
