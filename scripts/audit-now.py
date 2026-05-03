#!/usr/bin/env python3
"""
Audit de sécurité instantané — aucune infrastructure requise.
Lance des scans réels et génère un rapport avec score de sécurité.

Dépendances : requests pyyaml  (déjà dans venv_audit)

Usage :
    python scripts/audit-now.py
    python scripts/audit-now.py --target buildweb
    python scripts/audit-now.py --output reports/audit.html
    python scripts/audit-now.py --skip-observatory   # sans Mozilla Observatory (plus rapide)
"""
from __future__ import annotations

import argparse
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml

# ─────────────────────────────────────────────────────────────────────────────
# Config & helpers communs
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parents[1]
CONFIG_PATH = BASE_DIR / "config" / "websites.yml"
REPORTS_DIR = BASE_DIR / "reports"

SCORE_PENALTIES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2, "INFO": 0}
SCORE_MAX_PEN   = {"CRITICAL": 75, "HIGH": 45, "MEDIUM": 20, "LOW": 10}
SEV_ORDER       = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

COLORS = {
    "CRITICAL": "\033[91m", "HIGH": "\033[33m", "MEDIUM": "\033[93m",
    "LOW": "\033[94m", "INFO": "\033[37m", "RESET": "\033[0m",
    "BOLD": "\033[1m", "GREEN": "\033[92m", "CYAN": "\033[96m", "GRAY": "\033[90m",
}


def c(color: str, text: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"


def compute_score(findings: list[dict]) -> int:
    cumul: dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        cumul[sev] = cumul.get(sev, 0) + SCORE_PENALTIES.get(sev, 0)
    penalty = sum(min(v, SCORE_MAX_PEN.get(s, 999)) for s, v in cumul.items())
    return max(0, 100 - penalty)


def grade(score: int) -> str:
    for threshold, g in [(95, "A+"), (85, "A"), (75, "B"), (65, "C"), (50, "D")]:
        if score >= threshold:
            return g
    return "F"


def grade_color(g: str) -> str:
    return {"A+": "GREEN", "A": "GREEN", "B": "CYAN",
            "C": "MEDIUM", "D": "HIGH", "F": "CRITICAL"}.get(g, "RESET")


# ─────────────────────────────────────────────────────────────────────────────
# Check 1 : En-têtes HTTP de sécurité
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "remediation": "Ajouter un en-tête Content-Security-Policy restrictif.",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "remediation": "Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "remediation": "Ajouter X-Frame-Options: DENY ou SAMEORIGIN.",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "remediation": "Ajouter X-Content-Type-Options: nosniff.",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "remediation": "Ajouter Referrer-Policy: strict-origin-when-cross-origin.",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "remediation": "Ajouter un en-tête Permissions-Policy pour restreindre les APIs navigateur.",
    },
}

UA = "SecurityAudit/1.0 (internal scan)"


def check_headers(url: str) -> list[dict]:
    findings: list[dict] = []
    try:
        r = requests.get(url, timeout=15, allow_redirects=True,
                         headers={"User-Agent": UA})
        hdrs = {k.lower(): v for k, v in r.headers.items()}

        for header, info in REQUIRED_HEADERS.items():
            if header.lower() not in hdrs:
                findings.append({
                    "tool": "headers", "severity": info["severity"],
                    "title": f"En-tête de sécurité absent : {header}",
                    "description": f"L'en-tête {header} est manquant dans la réponse HTTP.",
                    "url": url, "remediation": info["remediation"],
                })

        # Divulgation de version via Server:
        if "server" in hdrs and re.search(r"[\d.]{3,}", hdrs["server"]):
            findings.append({
                "tool": "headers", "severity": "LOW",
                "title": f"Version serveur divulguée : {hdrs['server']}",
                "description": "L'en-tête Server révèle des informations de version exploitables.",
                "url": url,
                "remediation": "Masquer la version (ServerTokens Prod / server_tokens off).",
            })

        # X-Powered-By
        if "x-powered-by" in hdrs:
            findings.append({
                "tool": "headers", "severity": "LOW",
                "title": f"En-tête X-Powered-By présent : {hdrs['x-powered-by']}",
                "description": "Révèle le langage ou le framework utilisé.",
                "url": url,
                "remediation": "Supprimer l'en-tête X-Powered-By.",
            })

        # Redirection HTTP → HTTPS
        if url.startswith("https://"):
            http_url = "http://" + url[8:]
            try:
                rr = requests.get(http_url, timeout=8, allow_redirects=False,
                                  headers={"User-Agent": UA})
                if rr.status_code not in (301, 302, 307, 308):
                    findings.append({
                        "tool": "headers", "severity": "MEDIUM",
                        "title": "HTTP non redirigé vers HTTPS",
                        "description": (
                            f"La version HTTP ({http_url}) répond avec le code {rr.status_code} "
                            "au lieu d'une redirection vers HTTPS."
                        ),
                        "url": http_url,
                        "remediation": "Configurer une redirection 301 permanente de HTTP vers HTTPS.",
                    })
            except Exception:
                pass

    except requests.exceptions.ConnectionError:
        findings.append({
            "tool": "headers", "severity": "CRITICAL",
            "title": "Site inaccessible",
            "description": f"Impossible de joindre {url}.",
            "url": url, "remediation": "Vérifier que le site est en ligne.",
        })
    except Exception as e:
        findings.append({
            "tool": "headers", "severity": "INFO",
            "title": f"Erreur check en-têtes : {type(e).__name__}",
            "description": str(e), "url": url, "remediation": "",
        })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check 2 : SSL / TLS
# ─────────────────────────────────────────────────────────────────────────────

def check_ssl(url: str) -> list[dict]:
    findings: list[dict] = []
    parsed   = urlparse(url)
    hostname = parsed.hostname
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "tool": "ssl", "severity": "CRITICAL",
            "title": "Site non HTTPS",
            "description": "Le site ne chiffre pas les communications (pas de TLS).",
            "url": url,
            "remediation": "Activer HTTPS avec un certificat Let's Encrypt (gratuit).",
        })
        return findings

    # ── Validité et expiration du certificat ──────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10),
                             server_hostname=hostname) as s:
            cert = s.getpeercert()

            # Détection du renouvellement automatique :
            # Let's Encrypt + durée de validité ≤ 100 jours → certificat auto-géré
            issuer_str = " ".join(
                v for rdn in cert.get("issuer", ()) for _, v in rdn
            ).lower()
            auto_renewed = "let's encrypt" in issuer_str

            not_before_str = cert.get("notBefore", "")
            not_after_str  = cert.get("notAfter", "")
            if auto_renewed and not_before_str and not_after_str:
                not_before_dt = datetime.strptime(
                    not_before_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                not_after_dt = datetime.strptime(
                    not_after_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                validity_days = (not_after_dt - not_before_dt).days
                auto_renewed = validity_days <= 100  # Let's Encrypt = 90 jours

            expire_str = not_after_str or cert.get("notAfter", "")
            if expire_str:
                expire_dt = datetime.strptime(
                    expire_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                days_left = (expire_dt - datetime.now(timezone.utc)).days
                mgmt_label = "Certificat géré automatiquement (Let's Encrypt)." if auto_renewed else "Certificat géré manuellement."
                if days_left < 0:
                    findings.append({
                        "tool": "ssl", "severity": "CRITICAL", "cert_auto": auto_renewed,
                        "title": f"Certificat SSL expiré (il y a {-days_left}j)",
                        "description": f"Expiré le {expire_str}. {mgmt_label}",
                        "url": url, "remediation": "Renouveler le certificat immédiatement.",
                    })
                elif days_left < 14:
                    findings.append({
                        "tool": "ssl", "severity": "CRITICAL", "cert_auto": auto_renewed,
                        "title": f"Certificat SSL expire dans {days_left}j",
                        "description": f"Expire le {expire_str} — renouvellement en urgence. {mgmt_label}",
                        "url": url, "remediation": "Renouveler le certificat en urgence.",
                    })
                elif days_left < 30:
                    # Même avec renouvellement automatique, < 30 jours = le renouvellement a échoué
                    findings.append({
                        "tool": "ssl", "severity": "HIGH" if not auto_renewed else "MEDIUM",
                        "cert_auto": auto_renewed,
                        "title": f"Certificat SSL expire dans {days_left}j",
                        "description": (
                            f"Expire le {expire_str}. {mgmt_label} "
                            + ("Le renouvellement automatique semble avoir échoué."
                               if auto_renewed else "")
                        ),
                        "url": url,
                        "remediation": (
                            "Vérifier le renouvellement automatique (cert-manager / Certbot)."
                            if auto_renewed else "Renouveler le certificat dès que possible."
                        ),
                    })
                elif days_left < 60:
                    if auto_renewed:
                        findings.append({
                            "tool": "ssl", "severity": "INFO", "cert_auto": True,
                            "title": f"Certificat SSL expire dans {days_left}j",
                            "description": (
                                f"Expire le {expire_str}. "
                                "Émis par Let's Encrypt avec renouvellement automatique — "
                                "aucune action requise."
                            ),
                            "url": url, "remediation": "",
                        })
                    else:
                        findings.append({
                            "tool": "ssl", "severity": "MEDIUM", "cert_auto": False,
                            "title": f"Certificat SSL expire dans {days_left}j",
                            "description": (
                                f"Expire le {expire_str}. "
                                "Certificat géré manuellement — renouvellement à planifier."
                            ),
                            "url": url, "remediation": "Planifier le renouvellement du certificat.",
                        })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "tool": "ssl", "severity": "CRITICAL",
            "title": "Certificat SSL invalide ou auto-signé",
            "description": str(e), "url": url,
            "remediation": "Utiliser un certificat signé par une autorité reconnue (Let's Encrypt).",
        })
    except Exception as e:
        findings.append({
            "tool": "ssl", "severity": "INFO",
            "title": f"SSL : vérification impossible ({type(e).__name__})",
            "description": str(e), "url": url, "remediation": "",
        })

    # ── Protocoles obsolètes TLS 1.0 / 1.1 ───────────────────────────────────
    for proto_label, attr in [("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1")]:
        try:
            ver = getattr(ssl.TLSVersion, attr)
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode    = ssl.CERT_NONE
            ctx2.minimum_version = ver
            ctx2.maximum_version = ver
            with ctx2.wrap_socket(
                socket.create_connection((hostname, port), timeout=5),
                server_hostname=hostname,
            ):
                findings.append({
                    "tool": "ssl", "severity": "HIGH",
                    "title": f"Protocole obsolète accepté : {proto_label}",
                    "description": f"Le serveur accepte {proto_label} (déprécié depuis 2020, RFC 8996).",
                    "url": url,
                    "remediation": f"Désactiver {proto_label} — n'autoriser que TLS 1.2 et TLS 1.3.",
                })
        except (ssl.SSLError, OSError):
            pass   # Refusé → correct
        except AttributeError:
            pass   # TLSVersion non disponible sur cette installation OpenSSL

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check 3 : Mozilla HTTP Observatory
# ─────────────────────────────────────────────────────────────────────────────

OBSERVATORY_API = "https://http-observatory.security.mozilla.org/api/v1"


def check_observatory(url: str) -> list[dict]:
    findings: list[dict] = []
    hostname = urlparse(url).hostname

    try:
        # Déclencher le scan
        r = requests.post(
            f"{OBSERVATORY_API}/analyze?host={hostname}",
            data={"hidden": "true", "rescan": "true"},
            timeout=30,
        )
        if r.status_code not in (200, 201):
            return findings

        # Attendre la fin (max 90 s)
        scan_id: int | None = None
        for _ in range(30):
            r   = requests.get(f"{OBSERVATORY_API}/analyze?host={hostname}", timeout=15)
            data = r.json()
            state = data.get("state", "")
            if state == "FINISHED":
                scan_id = data.get("scan_id")
                break
            if state in ("FAILED", "ABORTED"):
                return findings
            time.sleep(3)

        if not scan_id:
            return findings

        # Récupérer les résultats par test
        r = requests.get(
            f"{OBSERVATORY_API}/getScanResults?scan={scan_id}", timeout=15
        )
        tests = r.json()
        if not isinstance(tests, dict):
            return findings

        for test_name, test in tests.items():
            if test.get("pass"):
                continue
            score_mod = test.get("score_modifier", 0)
            if score_mod <= -15:
                severity = "HIGH"
            elif score_mod <= -5:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            desc = test.get("score_description") or test.get("name") or test_name
            findings.append({
                "tool": "observatory",
                "severity": severity,
                "title": f"Observatory : {test.get('name', test_name)}",
                "description": desc,
                "url": url,
                "remediation": (
                    f"Voir https://observatory.mozilla.org/faq/ — règle : {test_name}"
                ),
            })

    except Exception as e:
        findings.append({
            "tool": "observatory", "severity": "INFO",
            "title": f"Observatory : indisponible ({type(e).__name__})",
            "description": str(e), "url": url, "remediation": "",
        })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check 4 : Bibliothèques JS vulnérables (Retire.js simplifié)
# ─────────────────────────────────────────────────────────────────────────────

VULN_LIBS: list[dict] = [
    {
        "name": "jquery",
        "pattern": r"jquery[.-]v?(\d+\.\d+\.\d+)",
        "below": "3.5.0",
        "cve": ["CVE-2019-11358", "CVE-2020-11022", "CVE-2020-11023"],
        "remediation": "Mettre à jour jQuery ≥ 3.7.1.",
    },
    {
        "name": "bootstrap",
        "pattern": r"bootstrap[.-]v?(\d+\.\d+\.\d+)",
        "below": "4.3.1",
        "cve": ["CVE-2019-8331"],
        "remediation": "Mettre à jour Bootstrap ≥ 5.3.0.",
    },
    {
        "name": "angular",
        "pattern": r"angular[.-]v?(\d+\.\d+\.\d+)",
        "below": "1.8.3",
        "cve": ["CVE-2019-10768"],
        "remediation": "Migrer vers Angular 2+ ou mettre à jour AngularJS ≥ 1.8.3.",
    },
    {
        "name": "lodash",
        "pattern": r"lodash[.-]v?(\d+\.\d+\.\d+)",
        "below": "4.17.21",
        "cve": ["CVE-2021-23337", "CVE-2020-8203"],
        "remediation": "Mettre à jour lodash ≥ 4.17.21.",
    },
    {
        "name": "moment",
        "pattern": r"moment[.-]v?(\d+\.\d+\.\d+)",
        "below": "2.29.4",
        "cve": ["CVE-2022-24785"],
        "remediation": "Mettre à jour moment.js ≥ 2.29.4.",
    },
    {
        "name": "underscore",
        "pattern": r"underscore[.-]v?(\d+\.\d+\.\d+)",
        "below": "1.13.0",
        "cve": ["CVE-2021-23358"],
        "remediation": "Mettre à jour underscore.js ≥ 1.13.0.",
    },
    {
        "name": "handlebars",
        "pattern": r"handlebars[.-]v?(\d+\.\d+\.\d+)",
        "below": "4.7.7",
        "cve": ["CVE-2021-23369", "CVE-2021-23383"],
        "remediation": "Mettre à jour Handlebars ≥ 4.7.7.",
    },
]


def _ver(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0, 0, 0)


def check_retirejs(url: str) -> list[dict]:
    findings: list[dict] = []
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": UA})
        # Récupère les src des balises <script> + le contenu HTML inline
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I)
        corpus  = r.text + "\n".join(scripts)

        seen: set = set()
        for lib in VULN_LIBS:
            for match in re.finditer(lib["pattern"], corpus, re.I):
                version = match.group(1)
                key = (lib["name"], version)
                if key in seen:
                    continue
                seen.add(key)
                if _ver(version) < _ver(lib["below"]):
                    cves = ", ".join(lib["cve"])
                    findings.append({
                        "tool": "retirejs", "severity": "HIGH",
                        "title": f"Bibliothèque JS vulnérable : {lib['name']} v{version}",
                        "description": (
                            f"{lib['name']} {version} est affecté par : {cves}."
                        ),
                        "url": url,
                        "cve_ids": lib["cve"],
                        "remediation": lib["remediation"],
                    })
    except Exception:
        pass
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Check 5 : Fichiers sensibles exposés
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE: list[tuple[str, str, str]] = [
    ("/.git/config",    "CRITICAL", "Dépôt Git exposé (.git/config)"),
    ("/.git/HEAD",      "CRITICAL", "Dépôt Git exposé (.git/HEAD)"),
    ("/.env",           "CRITICAL", "Fichier .env exposé"),
    ("/wp-config.php",  "CRITICAL", "wp-config.php accessible publiquement"),
    ("/.htpasswd",      "HIGH",     "Fichier .htpasswd exposé"),
    ("/config.php",     "HIGH",     "config.php accessible"),
    ("/phpinfo.php",    "HIGH",     "phpinfo() accessible publiquement"),
    ("/adminer.php",    "HIGH",     "Adminer accessible publiquement"),
    ("/backup.zip",     "HIGH",     "Fichier backup.zip exposé"),
    ("/backup.sql",     "HIGH",     "Dump SQL exposé (backup.sql)"),
    ("/db.sql",         "HIGH",     "Dump SQL exposé (db.sql)"),
    ("/server-status",  "MEDIUM",   "Apache server-status accessible"),
    ("/server-info",    "MEDIUM",   "Apache server-info accessible"),
    ("/phpmyadmin/",    "MEDIUM",   "phpMyAdmin exposé"),
    ("/wp-login.php",   "LOW",      "Page de login WordPress exposée"),
]


def _is_soft_404_server(base: str) -> tuple[bool, int]:
    """Détecte les serveurs qui renvoient 200 pour toutes les URLs (SPA, Nuxt, etc.).

    Retourne (soft_404, taille_de_référence).
    On considère que c'est un soft-404 si une URL aléatoire retourne 200.
    """
    canary = f"{base}/this-path-does-not-exist-audit-canary-xyz123abc"
    try:
        r = requests.get(canary, timeout=8, allow_redirects=False,
                         headers={"User-Agent": UA})
        if r.status_code == 200:
            return True, len(r.content)
    except Exception:
        pass
    return False, 0


def check_exposed_files(url: str) -> list[dict]:
    findings: list[dict] = []
    base = url.rstrip("/")

    # Détection soft-404 (SPA comme Nuxt, React, Vue qui renvoient 200 partout)
    soft_404, ref_size = _is_soft_404_server(base)

    for path, severity, title in SENSITIVE:
        try:
            r = requests.get(
                f"{base}{path}", timeout=8, allow_redirects=False,
                headers={"User-Agent": UA},
            )
            if r.status_code != 200 or len(r.content) <= 10:
                continue

            # Sur un serveur soft-404, on ne remonte le finding que si le contenu
            # est sensiblement différent de la page 404 générique (taille différente
            # de plus de 20 % ou moins de 500 octets — fichiers de config courts).
            if soft_404:
                size = len(r.content)
                if size >= 500 and abs(size - ref_size) / max(ref_size, 1) < 0.20:
                    # Même taille que la page 404 générique → faux positif probable
                    continue

            findings.append({
                "tool": "exposure", "severity": severity, "title": title,
                "description": f"Ressource accessible : {base}{path}",
                "url": f"{base}{path}",
                "remediation": (
                    f"Bloquer l'accès à {path} via la configuration du serveur web."
                ),
            })
        except Exception:
            pass
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Moteur d'audit
# ─────────────────────────────────────────────────────────────────────────────

def run_audit(site: dict, skip_observatory: bool = False) -> dict:
    url  = site["url"]
    all_findings: list[dict] = []

    checks: list[tuple[str, object]] = [
        ("En-têtes HTTP",    check_headers),
        ("SSL/TLS",          check_ssl),
        ("Bibliothèques JS", check_retirejs),
        ("Fichiers exposés", check_exposed_files),
    ]
    if not skip_observatory:
        checks.insert(2, ("Mozilla Observatory", check_observatory))

    for label, fn in checks:
        print(f"    {c('GRAY', '↳')} {label}...", end=" ", flush=True)
        try:
            found = fn(url)  # type: ignore[operator]
        except Exception as e:
            print(c("GRAY", f"erreur ignorée ({type(e).__name__})"))
            continue
        all_findings.extend(found)
        issues = [f for f in found if f["severity"] not in ("INFO",)]
        if issues:
            print(c("HIGH", f"⚠  {len(issues)} problème(s)"))
        else:
            print(c("GREEN", "✓  OK"))

    score = compute_score(all_findings)
    g     = grade(score)
    return {
        "name":       site["name"],
        "url":        url,
        "score":      score,
        "grade":      g,
        "findings":   _enrich_efforts(all_findings),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


# ── Enrichissement : temps de correction estimé ───────────────────────────────

_EFFORT: dict[tuple, tuple[str, str]] = {
    # (outil, sévérité) → (durée, type_action)
    ("headers",     "HIGH"):     ("30 min",  "Configuration serveur web"),
    ("headers",     "MEDIUM"):   ("15 min",  "Configuration serveur web"),
    ("headers",     "LOW"):      ("15 min",  "Configuration serveur web"),
    ("ssl",         "CRITICAL"): ("Urgent",  "Renouvellement certificat SSL"),
    ("ssl",         "HIGH"):     ("1h",      "Désactivation protocoles obsolètes"),
    ("ssl",         "MEDIUM"):   ("15 min",  "Planification renouvellement"),
    ("retirejs",    "HIGH"):     ("2 à 4h",  "Mise à jour bibliothèque + tests"),
    ("retirejs",    "MEDIUM"):   ("1h",      "Mise à jour bibliothèque"),
    ("observatory", "HIGH"):     ("1h",      "Configuration en-têtes HTTP"),
    ("observatory", "MEDIUM"):   ("30 min",  "Configuration en-têtes HTTP"),
    ("observatory", "LOW"):      ("15 min",  "Configuration en-têtes HTTP"),
    ("exposure",    "CRITICAL"): ("5 min",   "Suppression fichier + blocage serveur"),
    ("exposure",    "HIGH"):     ("15 min",  "Suppression ou blocage fichier"),
    ("exposure",    "MEDIUM"):   ("15 min",  "Blocage accès serveur web"),
    ("exposure",    "LOW"):      ("10 min",  "Restriction d'accès"),
}


def _enrich_efforts(findings: list[dict]) -> list[dict]:
    for f in findings:
        key = (f.get("tool", ""), f.get("severity", ""))
        duration, action = _EFFORT.get(key, ("—", "—"))
        f["effort_duration"] = duration
        f["effort_action"]   = action
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Affichage terminal
# ─────────────────────────────────────────────────────────────────────────────

def print_report(results: list[dict]) -> None:
    print()
    print(c("BOLD", "=" * 72))
    print(c("BOLD", "  RAPPORT D'AUDIT DE SÉCURITÉ"))
    print(c("GRAY", f"  Généré le {datetime.now().strftime('%Y-%m-%d %H:%M')}"))
    print(c("BOLD", "=" * 72))

    for res in results:
        g      = res["grade"]
        gc     = grade_color(g)
        filled = int(res["score"] / 5)
        bar    = "█" * filled + "░" * (20 - filled)

        print(f"\n{c('BOLD', '┌─ ' + res['name'])}  {c('GRAY', res['url'])}")
        print(f"│  Score : {c(gc, str(res['score']) + '/100')}  "
              f"[{c(gc, bar)}]  Grade : {c(gc, g)}")

        real_findings = [f for f in res["findings"] if f["severity"] != "INFO"]
        if not real_findings:
            print(f"│  {c('GREEN', '✓ Aucun problème détecté')}")
        else:
            by_sev: dict[str, list] = {}
            for f in real_findings:
                by_sev.setdefault(f["severity"], []).append(f)

            counts = "  ".join(
                f"{c(s, str(len(by_sev[s])) + ' ' + s)}"
                for s in SEV_ORDER if s in by_sev
            )
            print(f"│  Résumé : {counts}")
            print("│")

            for sev in SEV_ORDER:
                for f in by_sev.get(sev, []):
                    tool = f.get("tool", "").upper()
                    print(f"│  {c(sev, '[' + sev + ']')} {f['title']}  "
                          f"{c('GRAY', '[' + tool + ']')}")
                    if f.get("url") and f["url"] != res["url"]:
                        print(f"│    {c('GRAY', '↳ URL    :')} {f['url']}")
                    if f.get("description"):
                        print(f"│    {c('GRAY', '↳ Détail :')} {f['description']}")
                    if f.get("remediation"):
                        print(f"│    {c('GRAY', '↳ Fix    :')} {f['remediation']}")
                    if f.get("cve_ids"):
                        print(f"│    {c('GRAY', '↳ CVE    :')} {', '.join(f['cve_ids'])}")

        print(c("GRAY", "└" + "─" * 70))

    # ── Tableau récapitulatif ─────────────────────────────────────────────────
    print(f"\n{c('BOLD', 'RÉCAPITULATIF')}")
    print(f"{'Site':<30} {'Score':>7}  {'Grade':>5}  "
          f"{'Critique':>8}  {'Élevé':>6}  {'Moyen':>6}  {'Faible':>6}")
    print("─" * 72)
    for res in results:
        g  = res["grade"]
        gc = grade_color(g)
        by_sev = {s: sum(1 for f in res["findings"] if f["severity"] == s) for s in SEV_ORDER}
        print(
            f"{res['name']:<30} "
            f"{c(gc, str(res['score']) + '/100'):>7}  "
            f"{c(gc, g):>5}  "
            f"{c('CRITICAL' if by_sev['CRITICAL'] else 'GRAY', str(by_sev['CRITICAL'])):>8}  "
            f"{c('HIGH'     if by_sev['HIGH']     else 'GRAY', str(by_sev['HIGH'])):>6}  "
            f"{c('MEDIUM'   if by_sev['MEDIUM']   else 'GRAY', str(by_sev['MEDIUM'])):>6}  "
            f"{c('LOW'      if by_sev['LOW']       else 'GRAY', str(by_sev['LOW'])):>6}"
        )
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Rapport HTML
# ─────────────────────────────────────────────────────────────────────────────

SEV_HEX = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107", "LOW": "#0dcaf0", "INFO": "#6c757d",
}
GRADE_HEX = {
    "A+": "#198754", "A": "#198754", "B": "#0dcaf0",
    "C": "#ffc107",  "D": "#fd7e14", "F": "#dc3545",
}


def _badge(sev: str) -> str:
    color = SEV_HEX.get(sev, "#6c757d")
    return f"<span class='badge' style='background:{color};font-size:0.75em'>{sev}</span>"


def _cert_mgmt_badge(f: dict) -> str:
    """Badge 'Auto' ou 'Manuel' pour les findings SSL avec expiration."""
    if "cert_auto" not in f:
        return ""
    if f["cert_auto"]:
        return "<span class='badge ms-1' style='background:#20c997;font-size:0.65em'>🔄 Auto</span>"
    return "<span class='badge ms-1' style='background:#6c757d;font-size:0.65em'>🔧 Manuel</span>"


def _findings_rows(findings: list[dict]) -> str:
    rows = []
    for f in findings:
        # Exclure les INFO sauf les findings SSL d'expiration (cert_auto présent)
        if f["severity"] == "INFO" and "cert_auto" not in f:
            continue
        tool   = f.get("tool", "").upper()
        cve    = ", ".join(f.get("cve_ids", []))
        desc   = f.get("description", "")
        effort = f.get("effort_duration", "—")
        # Style atténué pour les INFO (aucune action requise)
        row_style = " class='text-muted'" if f["severity"] == "INFO" else ""
        sev_cell  = (_badge(f["severity"]) if f["severity"] != "INFO"
                     else "<span class='badge bg-light text-secondary border' "
                          "style='font-size:0.75em'>OK</span>")
        rows.append(
            f"<tr{row_style}>"
            f"<td class='text-nowrap'>{sev_cell}</td>"
            f"<td><strong>{f['title']}</strong>{_cert_mgmt_badge(f)}"
            f"{'<br><small class=\"text-muted\">' + desc + '</small>' if desc else ''}"
            f"{'<br><small class=\"text-danger\">CVE : ' + cve + '</small>' if cve else ''}"
            f"</td>"
            f"<td><small>{f.get('remediation', '') or '—'}</small></td>"
            f"<td class='text-center text-nowrap'><small><strong>{effort}</strong></small></td>"
            f"<td><span class='badge bg-secondary' style='font-size:0.7em'>{tool}</span></td>"
            f"</tr>"
        )
    if not rows:
        return ("<tr><td colspan='5' class='text-success fw-bold py-3'>"
                "✓ Aucun problème de sécurité détecté</td></tr>")
    return "".join(rows)


def _remediation_plan_rows(results: list[dict]) -> str:
    """Tableau de plan de remédiation global, trié par priorité."""
    all_f: list[dict] = []
    for res in results:
        for f in res["findings"]:
            if f["severity"] == "INFO":
                continue
            all_f.append({**f, "_site": res["name"]})

    all_f.sort(key=lambda x: SEV_ORDER.index(x["severity"]))
    rows = []
    for f in all_f:
        effort   = f.get("effort_duration", "—")
        action   = f.get("effort_action", "—")
        rows.append(
            f"<tr>"
            f"<td>{_badge(f['severity'])}</td>"
            f"<td><small>{f['_site']}</small></td>"
            f"<td>{f['title']}{_cert_mgmt_badge(f)}</td>"
            f"<td><small>{action}</small></td>"
            f"<td class='text-center'><strong>{effort}</strong></td>"
            f"</tr>"
        )
    return "".join(rows) if rows else "<tr><td colspan='5'>Aucune action requise</td></tr>"


def _total_effort(results: list[dict]) -> str:
    """Calcule le temps total estimé de remédiation."""
    minutes = 0
    for res in results:
        for f in res["findings"]:
            d = f.get("effort_duration", "—")
            if "Urgent" in d:
                minutes += 15
            elif "à" in d:
                # "2 à 4h" → prend la moyenne
                parts = re.findall(r"\d+", d)
                if len(parts) == 2:
                    minutes += int((int(parts[0]) + int(parts[1])) / 2 * 60)
            else:
                parts = re.findall(r"\d+", d)
                if parts:
                    val = int(parts[0])
                    if "h" in d and "min" not in d:
                        minutes += val * 60
                    else:
                        minutes += val
    if minutes >= 60:
        h = minutes // 60
        m = minutes % 60
        return f"{h}h{m:02d}" if m else f"{h}h"
    return f"{minutes} min"


def save_html(results: list[dict], output: Path) -> None:
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    total_effort = _total_effort(results)

    # ── Résumé global ─────────────────────────────────────────────────────────
    summary_rows = []
    for res in results:
        g      = res["grade"]
        gcolor = GRADE_HEX.get(g, "#6c757d")
        by_sev = {s: sum(1 for f in res["findings"] if f["severity"] == s)
                  for s in SEV_ORDER}
        bar = (f"<div class='progress' style='height:12px;min-width:80px'>"
               f"<div class='progress-bar' style='width:{res['score']}%;background:{gcolor}'>"
               f"</div></div>")
        summary_rows.append(
            f"<tr>"
            f"<td><strong>{res['name']}</strong><br>"
            f"<small class='text-muted'>{res['url']}</small></td>"
            f"<td class='text-center'>{bar}"
            f"<small>{res['score']}/100</small></td>"
            f"<td class='text-center'>"
            f"<span class='badge fs-6' style='background:{gcolor}'>{g}</span></td>"
            f"<td class='text-center text-danger fw-bold'>{by_sev['CRITICAL'] or '—'}</td>"
            f"<td class='text-center' style='color:#fd7e14'>{by_sev['HIGH'] or '—'}</td>"
            f"<td class='text-center' style='color:#856404'>{by_sev['MEDIUM'] or '—'}</td>"
            f"<td class='text-center text-primary'>{by_sev['LOW'] or '—'}</td>"
            f"</tr>"
        )

    # ── Détail par site ────────────────────────────────────────────────────────
    site_sections = []
    for res in results:
        g      = res["grade"]
        gcolor = GRADE_HEX.get(g, "#6c757d")
        crit   = sum(1 for f in res["findings"] if f["severity"] == "CRITICAL")
        high   = sum(1 for f in res["findings"] if f["severity"] == "HIGH")
        site_sections.append(f"""
        <div class="card mb-4 shadow-sm page-break-inside-avoid">
          <div class="card-header d-flex justify-content-between align-items-center py-2"
               style="background:{gcolor}20;border-left:5px solid {gcolor}">
            <div>
              <h5 class="mb-0">{res['name']}</h5>
              <small class="text-muted">{res['url']}</small>
            </div>
            <div class="text-end">
              <span class="badge fs-4 px-3 py-2" style="background:{gcolor}">{g}</span>
              <div class="text-muted small mt-1">{res['score']}/100 — scanné le {res['scanned_at']}</div>
            </div>
          </div>
          <div class="card-body p-0">
            <table class="table table-sm table-hover mb-0">
              <thead class="table-light">
                <tr>
                  <th style="width:90px">Sévérité</th>
                  <th>Problème détecté</th>
                  <th>Action corrective</th>
                  <th style="width:80px" class="text-center">Durée</th>
                  <th style="width:80px">Outil</th>
                </tr>
              </thead>
              <tbody>{_findings_rows(res['findings'])}</tbody>
            </table>
          </div>
        </div>""")

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rapport d'audit de sécurité — {generated}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet" crossorigin="anonymous">
  <style>
    body {{ font-size: 0.9rem; }}
    .cover {{ background: #1a1a2e; color: white; padding: 60px 40px; margin-bottom: 2rem; }}
    .cover h1 {{ font-size: 2.2rem; font-weight: 700; }}
    .cover .subtitle {{ color: #aaa; font-size: 1rem; margin-top: 0.5rem; }}
    .section-title {{
      font-size: 1rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 1px; color: #444; border-bottom: 2px solid #dee2e6;
      padding-bottom: 6px; margin: 2rem 0 1rem;
    }}
    .page-break-inside-avoid {{ break-inside: avoid; }}
    @media print {{
      .cover {{ background: #1a1a2e !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .badge {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .progress-bar {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .card {{ break-inside: avoid; }}
      @page {{ margin: 1.5cm; }}
    }}
  </style>
</head>
<body class="bg-light">

<!-- Page de couverture -->
<div class="cover">
  <h1>Rapport d'audit de sécurité</h1>
  <div class="subtitle">Analyse automatisée — {generated}</div>
  <div class="mt-4 d-flex gap-4 flex-wrap">
    <div><div style="color:#aaa;font-size:0.8rem">SITES AUDITÉS</div>
         <div style="font-size:1.8rem;font-weight:700">{len(results)}</div></div>
    <div><div style="color:#aaa;font-size:0.8rem">VULNÉRABILITÉS CRITIQUES</div>
         <div style="font-size:1.8rem;font-weight:700;color:#ff6b6b">
           {sum(sum(1 for f in r["findings"] if f["severity"]=="CRITICAL") for r in results)}
         </div></div>
    <div><div style="color:#aaa;font-size:0.8rem">TEMPS DE CORRECTION ESTIMÉ</div>
         <div style="font-size:1.8rem;font-weight:700;color:#51cf66">{total_effort}</div></div>
  </div>
</div>

<div class="container-lg pb-5">

  <!-- Résumé exécutif -->
  <div class="section-title">Résumé exécutif</div>
  <div class="card shadow-sm mb-4">
    <div class="card-body p-0">
      <table class="table table-hover mb-0">
        <thead class="table-light">
          <tr>
            <th>Site</th>
            <th style="width:140px">Score</th>
            <th style="width:80px" class="text-center">Grade</th>
            <th style="width:80px" class="text-center text-danger">Critique</th>
            <th style="width:80px" class="text-center" style="color:#fd7e14">Élevé</th>
            <th style="width:80px" class="text-center" style="color:#856404">Moyen</th>
            <th style="width:80px" class="text-center text-primary">Faible</th>
          </tr>
        </thead>
        <tbody>{"".join(summary_rows)}</tbody>
      </table>
    </div>
  </div>

  <!-- Plan de remédiation -->
  <div class="section-title">Plan de remédiation — temps total estimé : {total_effort}</div>
  <div class="card shadow-sm mb-4">
    <div class="card-body p-0">
      <table class="table table-sm table-hover mb-0">
        <thead class="table-light">
          <tr>
            <th style="width:90px">Priorité</th>
            <th style="width:130px">Site</th>
            <th>Problème</th>
            <th>Action</th>
            <th style="width:80px" class="text-center">Durée</th>
          </tr>
        </thead>
        <tbody>{_remediation_plan_rows(results)}</tbody>
      </table>
    </div>
  </div>

  <!-- Détail par site -->
  <div class="section-title">Détail par site</div>
  {"".join(site_sections)}

  <footer class="text-muted small text-center mt-4 pt-3 border-top">
    Rapport généré le {generated} par <strong>Build Web</strong> —
    <a href="mailto:contact@buildweb.fr">contact@buildweb.fr</a> —
    07 81 55 02 56 —
    toutes les vulnérabilités sont issues de scans réels.
  </footer>
</div>
</body>
</html>"""

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    print(c("GREEN", f"\n✓ Rapport HTML enregistré : {output}"))
    print(c("GRAY",  f"  → Ouvrez dans un navigateur puis Fichier → Imprimer → Enregistrer en PDF"))


# ─────────────────────────────────────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit de sécurité instantané — aucune infrastructure requise.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Exemples :
  python scripts/audit-now.py
  python scripts/audit-now.py --target buildweb
  python scripts/audit-now.py --group restaurants
  python scripts/audit-now.py --output reports/audit.html
  python scripts/audit-now.py --skip-observatory --output reports/audit-rapide.html
""",
    )
    parser.add_argument("--target", metavar="NOM",
                        help="Scanner uniquement ce site (nom dans config/websites.yml)")
    parser.add_argument("--group", metavar="GROUPE",
                        help="Scanner uniquement les sites d'un groupe (ex: restaurants, vignobles, agence, media, divers)")
    parser.add_argument("--output", metavar="FICHIER",
                        help="Chemin du rapport HTML à générer")
    parser.add_argument("--skip-observatory", action="store_true",
                        help="Ne pas appeler Mozilla Observatory (scan ~2× plus rapide)")
    args = parser.parse_args()

    with open(CONFIG_PATH) as f:
        sites: list[dict] = yaml.safe_load(f)["websites"]

    if args.target:
        sites = [s for s in sites if s["name"] == args.target]
        if not sites:
            print(f"Aucun site '{args.target}' dans {CONFIG_PATH}", file=sys.stderr)
            sys.exit(1)

    if args.group:
        sites = [s for s in sites if s.get("group") == args.group]
        if not sites:
            print(f"Aucun site dans le groupe '{args.group}' dans {CONFIG_PATH}", file=sys.stderr)
            sys.exit(1)

    skip_obs = args.skip_observatory
    print(c("BOLD", "\n▶ Audit de sécurité en cours..."))
    if skip_obs:
        print(c("GRAY", "  Mozilla Observatory désactivé (--skip-observatory)"))
    else:
        print(c("GRAY", "  Mozilla Observatory activé — ajoutez --skip-observatory pour aller plus vite"))

    results: list[dict] = []
    for site in sites:
        print(f"\n{c('BOLD', '▶')} {c('CYAN', site['name'])}  {c('GRAY', site['url'])}")
        results.append(run_audit(site, skip_observatory=skip_obs))

    print_report(results)

    if args.output:
        output_path = Path(args.output)
    elif args.group:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        output_path = REPORTS_DIR / f"audit-{args.group}.html"
    elif args.target:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        output_path = REPORTS_DIR / f"audit-{args.target}.html"
    else:
        output_path = None

    if output_path:
        save_html(results, output_path)


if __name__ == "__main__":
    main()
