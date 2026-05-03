#!/bin/bash
# Affiche l'état de l'infrastructure d'audit dans Kubernetes.
set -euo pipefail

NS="security-audit"

echo "=== Namespace ==="
kubectl get namespace "${NS}" 2>/dev/null || echo "Namespace non trouvé"

echo -e "\n=== Deployments ==="
kubectl get deployments -n "${NS}" 2>/dev/null

echo -e "\n=== CronJobs ==="
kubectl get cronjobs -n "${NS}" 2>/dev/null

echo -e "\n=== Jobs récents ==="
kubectl get jobs -n "${NS}" --sort-by='.metadata.creationTimestamp' 2>/dev/null | tail -20

echo -e "\n=== Pods ==="
kubectl get pods -n "${NS}" 2>/dev/null
