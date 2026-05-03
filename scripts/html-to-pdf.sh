#!/usr/bin/env bash
# Convertit des fichiers HTML en PDF via weasyprint (venv_audit)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_PYTHON="$PROJECT_DIR/venv_audit/bin/python"
VENV_PIP="$PROJECT_DIR/venv_audit/bin/pip"
REPORTS_DIR="$PROJECT_DIR/reports"

# ── Aide ──────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $0 [OPTIONS] [FICHIER(S).html]

Convertit des fichiers HTML en PDF en utilisant weasyprint.

OPTIONS:
  -o, --output DIR    Dossier de sortie pour les PDF (défaut: même dossier que le HTML)
  -a, --all           Convertit tous les HTML du dossier reports/
  -h, --help          Affiche cette aide

EXEMPLES:
  $0 reports/audit-foo.html
  $0 -o /tmp/pdf reports/audit-foo.html reports/audit-bar.html
  $0 --all
  $0 --all -o /tmp/pdf
EOF
  exit 0
}

# ── Vérification / installation de weasyprint ─────────────────────────────────
ensure_weasyprint() {
  if ! "$VENV_PYTHON" -c "import weasyprint" 2>/dev/null; then
    echo "[INFO] weasyprint non trouvé dans venv_audit — installation en cours..."
    "$VENV_PIP" install --quiet weasyprint
    echo "[INFO] weasyprint installé."
  fi
}

# ── Conversion d'un fichier ───────────────────────────────────────────────────
convert_file() {
  local input="$1"
  local output_dir="$2"

  if [[ ! -f "$input" ]]; then
    echo "[ERREUR] Fichier introuvable : $input" >&2
    return 1
  fi

  local basename
  basename="$(basename "$input" .html)"

  local out_dir
  if [[ -n "$output_dir" ]]; then
    out_dir="$output_dir"
    mkdir -p "$out_dir"
  else
    out_dir="$(dirname "$input")"
  fi

  local output="$out_dir/${basename}.pdf"

  echo "[INFO] Conversion : $input → $output"
  "$VENV_PYTHON" - <<PYEOF
import sys
from weasyprint import HTML, CSS

# CSS injecté pour réduire la taille de police au rendu PDF
PDF_CSS = CSS(string="""
  @page { size: A4; margin: 1.2cm; }
  body  { font-size: 0.68rem !important; }
  h1    { font-size: 1.4rem  !important; }
  h2    { font-size: 1.1rem  !important; }
  h3, h4, h5, h6 { font-size: 0.85rem !important; }
  .cover h1       { font-size: 1.6rem  !important; }
  .cover .subtitle{ font-size: 0.75rem !important; }
  .section-title  { font-size: 0.72rem !important; }
  small, .small, .text-muted { font-size: 0.62rem !important; }
  /* Forcer les couleurs des stats de couverture (inline style ignoré par weasyprint) */
  .cover-stat-red   { color: #ff6b6b !important; -webkit-text-fill-color: #ff6b6b; }
  .cover-stat-green { color: #51cf66 !important; -webkit-text-fill-color: #51cf66; }
""")

try:
    HTML(filename="${input}").write_pdf("${output}", stylesheets=[PDF_CSS])
    print(f"[OK]  ${output}")
except Exception as e:
    print(f"[ERREUR] {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

# ── Parsing des arguments ─────────────────────────────────────────────────────
OUTPUT_DIR=""
ALL_MODE=false
FILES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -a|--all)
      ALL_MODE=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    -*)
      echo "[ERREUR] Option inconnue : $1" >&2
      usage
      ;;
    *)
      FILES+=("$1")
      shift
      ;;
  esac
done

if [[ "$ALL_MODE" == false && ${#FILES[@]} -eq 0 ]]; then
  echo "[ERREUR] Aucun fichier spécifié. Utilisez --all ou passez des fichiers en argument." >&2
  usage
fi

# ── Main ──────────────────────────────────────────────────────────────────────
ensure_weasyprint

if [[ "$ALL_MODE" == true ]]; then
  mapfile -t FILES < <(find "$REPORTS_DIR" -maxdepth 1 -name "*.html" | sort)
  if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "[ERREUR] Aucun fichier HTML trouvé dans $REPORTS_DIR" >&2
    exit 1
  fi
  echo "[INFO] ${#FILES[@]} fichier(s) HTML trouvé(s) dans reports/"
fi

ERRORS=0
for f in "${FILES[@]}"; do
  convert_file "$f" "$OUTPUT_DIR" || ((ERRORS++))
done

echo ""
if [[ $ERRORS -eq 0 ]]; then
  echo "[OK] Conversion terminée : ${#FILES[@]} fichier(s) converti(s)."
else
  echo "[WARN] Conversion terminée avec $ERRORS erreur(s) sur ${#FILES[@]} fichier(s)."
  exit 1
fi
