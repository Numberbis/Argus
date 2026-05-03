#!/usr/bin/env python3
"""
Scanner Mozilla HTTP Observatory.

Analyse les en-têtes de sécurité HTTP d'un site et remonte les lacunes
comme findings vers le Collector.

Variables d'environnement requises :
    TARGET_URL   URL complète du site (ex: https://buildweb.fr)
    TARGET_NAME  Identifiant court du site (ex: buildweb)
    COLLECTOR_URL URL du collector (ex: http://collector:8080)
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TARGET_URL    = os.environ["TARGET_URL"]
TARGET_NAME   = os.environ["TARGET_NAME"]
COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://collector:8080")

OBSERVATORY_API = "https://http-observatory.security.mozilla.org/api/v1"

# Sévérité des tests Observatory selon leur impact sur le score
SEVERITY_MAP = {
    # Pénalités importantes → HIGH
    "content-security-policy":      "HIGH",
    "cookies":                      "HIGH",
    "strict-transport-security":    "HIGH",
    "redirection":                  "HIGH",
    # Pénalités moyennes → MEDIUM
    "cross-origin-resource-sharing": "MEDIUM",
    "referrer-policy":              "MEDIUM",
    "subresource-integrity":        "MEDIUM",
    "x-frame-options":              "MEDIUM",
    # Pénalités faibles → LOW
    "x-content-type-options":       "LOW",
    "x-xss-protection":             "LOW",
}

REMEDIATION_MAP = {
    "content-security-policy":       "Ajouter un en-tête Content-Security-Policy restrictif pour limiter les sources autorisées.",
    "cookies":                        "Ajouter les flags HttpOnly, Secure et SameSite=Strict sur tous les cookies de session.",
    "strict-transport-security":      "Ajouter l'en-tête Strict-Transport-Security avec max-age=31536000; includeSubDomains.",
    "redirection":                    "S'assurer que toutes les redirections HTTP→HTTPS sont en place et permanentes (301).",
    "cross-origin-resource-sharing":  "Restreindre les origines autorisées dans Access-Control-Allow-Origin.",
    "referrer-policy":                "Ajouter l'en-tête Referrer-Policy: strict-origin-when-cross-origin.",
    "subresource-integrity":          "Ajouter les attributs integrity et crossorigin sur les balises <script> et <link> externes.",
    "x-frame-options":                "Ajouter l'en-tête X-Frame-Options: DENY ou SAMEORIGIN.",
    "x-content-type-options":         "Ajouter l'en-tête X-Content-Type-Options: nosniff.",
    "x-xss-protection":               "Ajouter l'en-tête X-XSS-Protection: 0 (désactiver le filtre XSS obsolète du navigateur).",
}


def trigger_scan(host: str) -> int:
    """Lance un scan Observatory et retourne le scan_id."""
    resp = requests.post(
        f"{OBSERVATORY_API}/analyze",
        params={"host": host},
        data={"hidden": "true", "rescan": "true"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("scan_id")


def wait_for_scan(host: str, max_wait: int = 120) -> dict:
    """Attend la fin du scan et retourne le résultat."""
    for _ in range(max_wait // 5):
        resp = requests.get(
            f"{OBSERVATORY_API}/analyze",
            params={"host": host},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        state = data.get("state", "")
        if state == "FINISHED":
            return data
        if state in ("FAILED", "ABORTED"):
            raise RuntimeError(f"Scan Observatory échoué : {state}")
        time.sleep(5)
    raise TimeoutError(f"Scan Observatory non terminé après {max_wait}s")


def get_test_results(scan_id: int) -> dict:
    """Récupère le détail des tests individuels."""
    resp = requests.get(
        f"{OBSERVATORY_API}/getScanResults",
        params={"scan": scan_id},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def build_findings(test_results: dict, target_url: str) -> list[dict]:
    """Convertit les tests échoués en findings."""
    findings = []
    for test_name, result in test_results.items():
        if result.get("pass"):
            continue
        severity = SEVERITY_MAP.get(test_name, "LOW")
        findings.append({
            "severity":    severity,
            "title":       f"En-tête de sécurité : {result.get('score_description', test_name)}",
            "description": result.get("result", ""),
            "url":         target_url,
            "remediation": REMEDIATION_MAP.get(test_name, ""),
        })
    return findings


def post_to_collector(findings: list, summary: dict, target_url: str):
    score    = summary.get("score", 0)
    grade    = summary.get("grade", "?")
    payload  = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "findings":   findings,
        "raw_output": {
            "score": score,
            "grade": grade,
            "tests_passed":  summary.get("tests_passed", 0),
            "tests_failed":  summary.get("tests_failed", 0),
            "tests_quantity": summary.get("tests_quantity", 0),
        },
    }
    resp = requests.post(
        f"{COLLECTOR_URL}/results/observatory/{TARGET_NAME}",
        json=payload,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def main():
    host = urlparse(TARGET_URL).hostname
    print(f"[Observatory] Analyse de {host} ({TARGET_URL})")

    try:
        trigger_scan(host)
        summary      = wait_for_scan(host)
        scan_id      = summary["scan_id"]
        test_results = get_test_results(scan_id)
        findings     = build_findings(test_results, TARGET_URL)

        score = summary.get("score", 0)
        grade = summary.get("grade", "?")
        print(f"[Observatory] Score : {score}/100  Grade : {grade}  "
              f"Findings : {len(findings)}")

        result = post_to_collector(findings, summary, TARGET_URL)
        print(f"[Observatory] Résultats envoyés — scan_id={result['scan_id']}")

    except Exception as e:
        print(f"[Observatory] Erreur : {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
