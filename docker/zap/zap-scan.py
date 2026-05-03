#!/usr/bin/env python3
"""ZAP scanner entry point — lance un scan actif et envoie les résultats au collector."""
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

TARGET_URL = os.environ["TARGET_URL"]
TARGET_NAME = os.environ["TARGET_NAME"]
SCAN_PROFILE = os.environ.get("SCAN_PROFILE", "full")
COLLECTOR_URL = os.environ["COLLECTOR_URL"]
ZAP_PORT = 8090


def run_zap_scan():
    from zapv2 import ZAPv2

    zap = ZAPv2(proxies={"http": f"http://localhost:{ZAP_PORT}", "https": f"http://localhost:{ZAP_PORT}"})

    print(f"[ZAP] Démarrage scan {SCAN_PROFILE} sur {TARGET_URL}")
    started_at = datetime.now(timezone.utc).isoformat()

    # Spider
    scan_id = zap.spider.scan(TARGET_URL)
    while int(zap.spider.status(scan_id)) < 100:
        time.sleep(2)

    # Scan actif uniquement pour le profil full
    if SCAN_PROFILE == "full":
        ascan_id = zap.ascan.scan(TARGET_URL)
        while int(zap.ascan.status(ascan_id)) < 100:
            time.sleep(5)

    alerts = zap.core.alerts(baseurl=TARGET_URL)
    findings = []
    for alert in alerts:
        findings.append({
            "severity": _map_severity(alert.get("risk", "Low")),
            "title": alert.get("alert", ""),
            "description": alert.get("desc", ""),
            "url": alert.get("url", ""),
            "remediation": alert.get("solution", ""),
            "cvss_score": None,
            "cve_ids": [],
        })

    return {"started_at": started_at, "findings": findings, "raw_output": alerts}


def _map_severity(risk: str) -> str:
    return {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO"}.get(risk, "INFO")


def post_results(data: dict):
    url = f"{COLLECTOR_URL}/results/zap/{TARGET_NAME}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(f"[ZAP] Résultats envoyés → {resp.status}")


if __name__ == "__main__":
    try:
        results = run_zap_scan()
        post_results(results)
        print(f"[ZAP] {len(results['findings'])} findings trouvés.")
    except Exception as exc:
        print(f"[ZAP] ERREUR: {exc}", file=sys.stderr)
        sys.exit(1)
