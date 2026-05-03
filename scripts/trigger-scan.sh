#!/bin/bash
# Déclenche manuellement un scan pour un outil et un site donnés.
# Usage: ./scripts/trigger-scan.sh TOOL TARGET
# Exemple: ./scripts/trigger-scan.sh zap buildweb
set -euo pipefail

TOOL="${1:?Usage: trigger-scan.sh <tool> <target>}"
TARGET="${2:?Usage: trigger-scan.sh <tool> <target>}"
NAMESPACE="security-audit"
CRONJOB_NAME="${TOOL}-${TARGET}"

echo "==> Déclenchement manuel du scan ${TOOL} sur ${TARGET}..."
kubectl create job \
    --from="cronjob/${CRONJOB_NAME}" \
    "${CRONJOB_NAME}-manual-$(date +%s)" \
    -n "${NAMESPACE}"

echo "==> Job créé. Suivre avec :"
echo "    kubectl get jobs -n ${NAMESPACE} -w"
echo "    kubectl logs -f -n ${NAMESPACE} -l tool=${TOOL},target=${TARGET}"
