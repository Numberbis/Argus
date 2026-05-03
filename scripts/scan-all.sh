#!/usr/bin/env bash
# Run all scanners against all (or filtered) sites from config/websites.yml
#
# Usage:
#   ./scripts/scan-all.sh                        # all tools, all sites
#   ./scripts/scan-all.sh --tool nuclei           # one tool, all sites
#   ./scripts/scan-all.sh --site my-site          # all tools, one site
#   ./scripts/scan-all.sh --tool testssl --group restaurants
#
# Requires: yq (https://github.com/mikefarah/yq) and Docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WEBSITES_FILE="$REPO_ROOT/config/websites.yml"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"

# ── Defaults ──────────────────────────────────────────────────────────────────
FILTER_TOOL=""
FILTER_SITE=""
FILTER_GROUP=""
ALL_TOOLS="zap nikto nmap testssl nuclei"
PARALLEL=0
CONCURRENCY=3   # max parallel scans (respect rate limits)

# ── Args ──────────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --tool)   FILTER_TOOL="$2"; shift 2 ;;
    --site)   FILTER_SITE="$2"; shift 2 ;;
    --group)  FILTER_GROUP="$2"; shift 2 ;;
    --parallel) PARALLEL=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

TOOLS="${FILTER_TOOL:-$ALL_TOOLS}"

# ── Dependency check ──────────────────────────────────────────────────────────
if ! command -v yq &>/dev/null; then
  echo "ERROR: yq is required. Install it: https://github.com/mikefarah/yq#install"
  exit 1
fi

if ! docker compose -f "$COMPOSE_FILE" ps collector --quiet 2>/dev/null | grep -q .; then
  echo "ERROR: collector is not running. Start the stack first:"
  echo "  docker compose up -d"
  exit 1
fi

# ── Load sites ────────────────────────────────────────────────────────────────
mapfile -t NAMES  < <(yq '.websites[].name' "$WEBSITES_FILE")
mapfile -t URLS   < <(yq '.websites[].url'  "$WEBSITES_FILE")
mapfile -t GROUPS < <(yq '.websites[].group // ""' "$WEBSITES_FILE")
mapfile -t PROFILES < <(yq '.websites[].scan_profile // "light"' "$WEBSITES_FILE")

TOTAL=${#NAMES[@]}
echo "Argus — scan runner"
echo "  Sites  : $TOTAL"
echo "  Tools  : $TOOLS"
[[ -n "$FILTER_GROUP" ]] && echo "  Group  : $FILTER_GROUP"
[[ -n "$FILTER_SITE"  ]] && echo "  Filter : $FILTER_SITE"
echo ""

# ── Run ───────────────────────────────────────────────────────────────────────
PIDS=()
JOBS=0
ERRORS=0

run_scan() {
  local tool="$1" name="$2" url="$3" profile="$4"

  # Determine if this tool is relevant for the scan profile
  if [[ "$profile" == "ssl-only" && "$tool" != "testssl" ]]; then
    return 0
  fi
  if [[ "$profile" == "light" && "$tool" == "zap" ]]; then
    return 0  # ZAP is too aggressive for light profile
  fi

  echo "[$(date +%H:%M:%S)] ▶ $tool → $name ($url)"
  docker compose -f "$COMPOSE_FILE" \
    --profile scanners \
    run --rm \
    -e TARGET_URL="$url" \
    -e TARGET_NAME="$name" \
    -e SCAN_PROFILE="$profile" \
    "$tool" \
    && echo "[$(date +%H:%M:%S)] ✓ $tool → $name" \
    || { echo "[$(date +%H:%M:%S)] ✗ $tool → $name FAILED"; return 1; }
}

for (( i=0; i<TOTAL; i++ )); do
  name="${NAMES[$i]}"
  url="${URLS[$i]}"
  group="${GROUPS[$i]}"
  profile="${PROFILES[$i]}"

  # Apply filters
  [[ -n "$FILTER_SITE"  && "$name"  != "$FILTER_SITE"  ]] && continue
  [[ -n "$FILTER_GROUP" && "$group" != "$FILTER_GROUP" ]] && continue

  for tool in $TOOLS; do
    if [[ "$PARALLEL" == "1" ]]; then
      # Background with concurrency cap
      while (( ${#PIDS[@]} >= CONCURRENCY )); do
        for j in "${!PIDS[@]}"; do
          if ! kill -0 "${PIDS[$j]}" 2>/dev/null; then
            wait "${PIDS[$j]}" || (( ERRORS++ )) || true
            unset "PIDS[$j]"
          fi
        done
        PIDS=("${PIDS[@]}")
        sleep 1
      done
      run_scan "$tool" "$name" "$url" "$profile" &
      PIDS+=($!)
    else
      run_scan "$tool" "$name" "$url" "$profile" || (( ERRORS++ )) || true
    fi
    (( JOBS++ ))
  done
done

# Wait for remaining background jobs
for pid in "${PIDS[@]}"; do
  wait "$pid" || (( ERRORS++ )) || true
done

echo ""
echo "Done — $JOBS scans launched, $ERRORS errors."
