#!/bin/bash
# Bootstrap complet de l'infrastructure d'audit.
# Usage: ./scripts/bootstrap.sh [--extra-vars "db_url=... slack_token=..."]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="${SCRIPT_DIR}/../ansible"

echo "==> Démarrage du bootstrap de l'infrastructure d'audit..."
cd "${ANSIBLE_DIR}"
ansible-playbook playbooks/setup.yml "$@"
echo "==> Bootstrap terminé."
