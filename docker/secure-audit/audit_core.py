"""
Moteur d'audit de sécurité — extrait de scripts/audit-now.py.
Fonctions utilisées par l'application web Secure Audit.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# ─── Constantes ───────────────────────────────────────────────────────────────

SCORE_PENALTIES = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2, "INFO": 0}
SCORE_MAX_PEN   = {"CRITICAL": 75, "HIGH": 45, "MEDIUM": 20, "LOW": 10}
SEV_ORDER       = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

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

UA = "SecurityAudit/1.0 (Build Web)"

OBSERVATORY_API = "https://http-observatory.security.mozilla.org/api/v1"

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

SENSITIVE: list[tuple[str, str, str]] = [
    ("/.git/config",   "CRITICAL", "Dépôt Git exposé (.git/config)"),
    ("/.git/HEAD",     "CRITICAL", "Dépôt Git exposé (.git/HEAD)"),
    ("/.env",          "CRITICAL", "Fichier .env exposé"),
    ("/wp-config.php", "CRITICAL", "wp-config.php accessible publiquement"),
    ("/.htpasswd",     "HIGH",     "Fichier .htpasswd exposé"),
    ("/config.php",    "HIGH",     "config.php accessible"),
    ("/phpinfo.php",   "HIGH",     "phpinfo() accessible publiquement"),
    ("/adminer.php",   "HIGH",     "Adminer accessible publiquement"),
    ("/backup.zip",    "HIGH",     "Fichier backup.zip exposé"),
    ("/backup.sql",    "HIGH",     "Dump SQL exposé (backup.sql)"),
    ("/db.sql",        "HIGH",     "Dump SQL exposé (db.sql)"),
    ("/server-status", "MEDIUM",   "Apache server-status accessible"),
    ("/server-info",   "MEDIUM",   "Apache server-info accessible"),
    ("/phpmyadmin/",   "MEDIUM",   "phpMyAdmin exposé"),
    ("/wp-login.php",  "LOW",      "Page de login WordPress exposée"),
]

_EFFORT: dict[tuple, tuple[str, str]] = {
    ("headers",     "HIGH"):     ("30 min", "Configuration serveur web"),
    ("headers",     "MEDIUM"):   ("15 min", "Configuration serveur web"),
    ("headers",     "LOW"):      ("15 min", "Configuration serveur web"),
    ("ssl",         "CRITICAL"): ("Urgent", "Renouvellement certificat SSL"),
    ("ssl",         "HIGH"):     ("1h",     "Désactivation protocoles obsolètes"),
    ("ssl",         "MEDIUM"):   ("15 min", "Planification renouvellement"),
    ("retirejs",    "HIGH"):     ("2 à 4h", "Mise à jour bibliothèque + tests"),
    ("retirejs",    "MEDIUM"):   ("1h",     "Mise à jour bibliothèque"),
    ("observatory", "HIGH"):     ("1h",     "Configuration en-têtes HTTP"),
    ("observatory", "MEDIUM"):   ("30 min", "Configuration en-têtes HTTP"),
    ("observatory", "LOW"):      ("15 min", "Configuration en-têtes HTTP"),
    ("exposure",    "CRITICAL"): ("5 min",  "Suppression fichier + blocage serveur"),
    ("exposure",    "HIGH"):     ("15 min", "Suppression ou blocage fichier"),
    ("exposure",    "MEDIUM"):   ("15 min", "Blocage accès serveur web"),
    ("exposure",    "LOW"):      ("10 min", "Restriction d'accès"),
}

SEV_HEX = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
    "MEDIUM":   "#ffc107", "LOW":  "#0dcaf0", "INFO": "#6c757d",
}
GRADE_HEX = {
    "A+": "#198754", "A": "#198754", "B": "#0dcaf0",
    "C":  "#ffc107", "D": "#fd7e14", "F": "#dc3545",
}


# ─── Scores & grades ──────────────────────────────────────────────────────────

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


# ─── Checks de sécurité ───────────────────────────────────────────────────────

def check_headers(url: str) -> list[dict]:
    findings: list[dict] = []
    try:
        r = requests.get(url, timeout=15, allow_redirects=True, headers={"User-Agent": UA})
        hdrs = {k.lower(): v for k, v in r.headers.items()}

        for header, info in REQUIRED_HEADERS.items():
            if header.lower() not in hdrs:
                findings.append({
                    "tool": "headers", "severity": info["severity"],
                    "title": f"En-tête de sécurité absent : {header}",
                    "description": f"L'en-tête {header} est manquant dans la réponse HTTP.",
                    "url": url, "remediation": info["remediation"],
                })

        if "server" in hdrs and re.search(r"[\d.]{3,}", hdrs["server"]):
            findings.append({
                "tool": "headers", "severity": "LOW",
                "title": f"Version serveur divulguée : {hdrs['server']}",
                "description": "L'en-tête Server révèle des informations de version exploitables.",
                "url": url, "remediation": "Masquer la version (ServerTokens Prod / server_tokens off).",
            })

        if "x-powered-by" in hdrs:
            findings.append({
                "tool": "headers", "severity": "LOW",
                "title": f"En-tête X-Powered-By présent : {hdrs['x-powered-by']}",
                "description": "Révèle le langage ou le framework utilisé.",
                "url": url, "remediation": "Supprimer l'en-tête X-Powered-By.",
            })

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
                            f"La version HTTP ({http_url}) répond avec le code "
                            f"{rr.status_code} au lieu d'une redirection vers HTTPS."
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


def check_ssl(url: str) -> list[dict]:
    findings: list[dict] = []
    parsed   = urlparse(url)
    hostname = parsed.hostname
    port     = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "tool": "ssl", "severity": "CRITICAL", "title": "Site non HTTPS",
            "description": "Le site ne chiffre pas les communications (pas de TLS).",
            "url": url, "remediation": "Activer HTTPS avec un certificat Let's Encrypt (gratuit).",
        })
        return findings

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=10),
            server_hostname=hostname,
        ) as s:
            cert = s.getpeercert()

            issuer_str  = " ".join(v for rdn in cert.get("issuer", ()) for _, v in rdn).lower()
            auto_renewed = "let's encrypt" in issuer_str

            not_before_str = cert.get("notBefore", "")
            not_after_str  = cert.get("notAfter",  "")
            if auto_renewed and not_before_str and not_after_str:
                nb = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                na = datetime.strptime(not_after_str,  "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                auto_renewed = (na - nb).days <= 100

            if not_after_str:
                expire_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left  = (expire_dt - datetime.now(timezone.utc)).days
                mgmt       = ("Certificat géré automatiquement (Let's Encrypt)."
                              if auto_renewed else "Certificat géré manuellement.")

                if days_left < 0:
                    findings.append({"tool": "ssl", "severity": "CRITICAL", "cert_auto": auto_renewed,
                        "title": f"Certificat SSL expiré (il y a {-days_left}j)",
                        "description": f"Expiré le {not_after_str}. {mgmt}",
                        "url": url, "remediation": "Renouveler le certificat immédiatement."})
                elif days_left < 14:
                    findings.append({"tool": "ssl", "severity": "CRITICAL", "cert_auto": auto_renewed,
                        "title": f"Certificat SSL expire dans {days_left}j",
                        "description": f"Expire le {not_after_str} — renouvellement en urgence. {mgmt}",
                        "url": url, "remediation": "Renouveler le certificat en urgence."})
                elif days_left < 30:
                    findings.append({"tool": "ssl",
                        "severity": "HIGH" if not auto_renewed else "MEDIUM",
                        "cert_auto": auto_renewed,
                        "title": f"Certificat SSL expire dans {days_left}j",
                        "description": (
                            f"Expire le {not_after_str}. {mgmt} "
                            + ("Le renouvellement automatique semble avoir échoué."
                               if auto_renewed else "")
                        ),
                        "url": url,
                        "remediation": ("Vérifier le renouvellement automatique."
                                        if auto_renewed else "Renouveler le certificat dès que possible.")})
                elif days_left < 60:
                    if auto_renewed:
                        findings.append({"tool": "ssl", "severity": "INFO", "cert_auto": True,
                            "title": f"Certificat SSL expire dans {days_left}j",
                            "description": (
                                f"Expire le {not_after_str}. "
                                "Let's Encrypt avec renouvellement automatique — aucune action requise."
                            ),
                            "url": url, "remediation": ""})
                    else:
                        findings.append({"tool": "ssl", "severity": "MEDIUM", "cert_auto": False,
                            "title": f"Certificat SSL expire dans {days_left}j",
                            "description": f"Expire le {not_after_str}. Certificat géré manuellement.",
                            "url": url, "remediation": "Planifier le renouvellement du certificat."})

    except ssl.SSLCertVerificationError as e:
        findings.append({"tool": "ssl", "severity": "CRITICAL",
            "title": "Certificat SSL invalide ou auto-signé", "description": str(e),
            "url": url, "remediation": "Utiliser un certificat signé par une autorité reconnue (Let's Encrypt)."})
    except Exception as e:
        findings.append({"tool": "ssl", "severity": "INFO",
            "title": f"SSL : vérification impossible ({type(e).__name__})",
            "description": str(e), "url": url, "remediation": ""})

    # Protocoles obsolètes TLS 1.0 / 1.1
    for proto_label, attr in [("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1")]:
        try:
            ver  = getattr(ssl.TLSVersion, attr)
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname    = False
            ctx2.verify_mode       = ssl.CERT_NONE
            ctx2.minimum_version   = ver
            ctx2.maximum_version   = ver
            with ctx2.wrap_socket(
                socket.create_connection((hostname, port), timeout=5),
                server_hostname=hostname,
            ):
                findings.append({"tool": "ssl", "severity": "HIGH",
                    "title": f"Protocole obsolète accepté : {proto_label}",
                    "description": f"Le serveur accepte {proto_label} (déprécié depuis 2020, RFC 8996).",
                    "url": url,
                    "remediation": f"Désactiver {proto_label} — n'autoriser que TLS 1.2 et TLS 1.3."})
        except (ssl.SSLError, OSError, AttributeError):
            pass

    return findings


def check_observatory(url: str) -> list[dict]:
    findings: list[dict] = []
    hostname = urlparse(url).hostname
    try:
        r = requests.post(
            f"{OBSERVATORY_API}/analyze?host={hostname}",
            data={"hidden": "true", "rescan": "true"},
            timeout=30,
        )
        if r.status_code not in (200, 201):
            return findings

        scan_id: int | None = None
        for _ in range(30):
            r    = requests.get(f"{OBSERVATORY_API}/analyze?host={hostname}", timeout=15)
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

        r = requests.get(f"{OBSERVATORY_API}/getScanResults?scan={scan_id}", timeout=15)
        tests = r.json()
        if not isinstance(tests, dict):
            return findings

        for test_name, test in tests.items():
            if test.get("pass"):
                continue
            score_mod = test.get("score_modifier", 0)
            severity  = "HIGH" if score_mod <= -15 else "MEDIUM" if score_mod <= -5 else "LOW"
            desc      = test.get("score_description") or test.get("name") or test_name
            findings.append({"tool": "observatory", "severity": severity,
                "title": f"Observatory : {test.get('name', test_name)}", "description": desc,
                "url": url, "remediation": f"Voir https://observatory.mozilla.org/faq/ — règle : {test_name}"})
    except Exception as e:
        findings.append({"tool": "observatory", "severity": "INFO",
            "title": f"Observatory : indisponible ({type(e).__name__})",
            "description": str(e), "url": url, "remediation": ""})
    return findings


def _ver(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return (0, 0, 0)


def check_retirejs(url: str) -> list[dict]:
    findings: list[dict] = []
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent": UA})
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
                    findings.append({"tool": "retirejs", "severity": "HIGH",
                        "title": f"Bibliothèque JS vulnérable : {lib['name']} v{version}",
                        "description": f"{lib['name']} {version} est affecté par : {', '.join(lib['cve'])}.",
                        "url": url, "cve_ids": lib["cve"], "remediation": lib["remediation"]})
    except Exception:
        pass
    return findings


def _is_soft_404_server(base: str) -> tuple[bool, int]:
    canary = f"{base}/this-path-does-not-exist-audit-canary-xyz123abc"
    try:
        r = requests.get(canary, timeout=8, allow_redirects=False, headers={"User-Agent": UA})
        if r.status_code == 200:
            return True, len(r.content)
    except Exception:
        pass
    return False, 0


def check_exposed_files(url: str) -> list[dict]:
    findings: list[dict] = []
    base = url.rstrip("/")
    soft_404, ref_size = _is_soft_404_server(base)

    for path, severity, title in SENSITIVE:
        try:
            r = requests.get(f"{base}{path}", timeout=8, allow_redirects=False,
                             headers={"User-Agent": UA})
            if r.status_code != 200 or len(r.content) <= 10:
                continue
            if soft_404:
                size = len(r.content)
                if size >= 500 and abs(size - ref_size) / max(ref_size, 1) < 0.20:
                    continue
            findings.append({"tool": "exposure", "severity": severity, "title": title,
                "description": f"Ressource accessible : {base}{path}",
                "url": f"{base}{path}",
                "remediation": f"Bloquer l'accès à {path} via la configuration du serveur web."})
        except Exception:
            pass
    return findings


def _enrich_efforts(findings: list[dict]) -> list[dict]:
    for f in findings:
        key = (f.get("tool", ""), f.get("severity", ""))
        duration, action = _EFFORT.get(key, ("—", "—"))
        f["effort_duration"] = duration
        f["effort_action"]   = action
    return findings


# ─── Orchestration ─────────────────────────────────────────────────────────────

def run_audit(
    site: dict,
    skip_observatory: bool = False,
    progress_cb=None,
) -> dict:
    """Lance tous les checks sur `site['url']` et retourne le résultat."""
    url = site["url"]
    all_findings: list[dict] = []

    def log(msg: str) -> None:
        if progress_cb:
            progress_cb(msg)

    checks: list[tuple[str, object]] = [
        ("Vérification des en-têtes HTTP",    check_headers),
        ("Analyse SSL/TLS",                   check_ssl),
        ("Vérification des bibliothèques JS", check_retirejs),
        ("Recherche de fichiers sensibles",   check_exposed_files),
    ]
    if not skip_observatory:
        checks.insert(2, ("Mozilla Observatory (peut prendre 1 min)", check_observatory))

    total = len(checks)
    for i, (label, fn) in enumerate(checks, 1):
        log(f"[{i}/{total}] {label}...")
        try:
            found = fn(url)  # type: ignore[operator]
        except Exception as e:
            log(f"Erreur ignorée ({label}) : {type(e).__name__}")
            continue
        all_findings.extend(found)

    log("Génération du rapport...")
    sc = compute_score(all_findings)
    g  = grade(sc)

    return {
        "name":       site["name"],
        "url":        url,
        "score":      sc,
        "grade":      g,
        "findings":   _enrich_efforts(all_findings),
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


# ─── Génération du rapport HTML ────────────────────────────────────────────────

def _badge(sev: str) -> str:
    color = SEV_HEX.get(sev, "#6c757d")
    return f"<span class='badge' style='background:{color};font-size:0.75em'>{sev}</span>"


def _cert_mgmt_badge(f: dict) -> str:
    if "cert_auto" not in f:
        return ""
    if f["cert_auto"]:
        return ("<span class='badge ms-1' style='background:#20c997;font-size:0.65em'>"
                "Auto</span>")
    return ("<span class='badge ms-1' style='background:#6c757d;font-size:0.65em'>"
            "Manuel</span>")


def _findings_rows(findings: list[dict]) -> str:
    rows = []
    for f in findings:
        if f["severity"] == "INFO" and "cert_auto" not in f:
            continue
        tool   = f.get("tool", "").upper()
        cve    = ", ".join(f.get("cve_ids", []))
        desc   = f.get("description", "")
        effort = f.get("effort_duration", "—")
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
    all_f: list[dict] = []
    for res in results:
        for f in res["findings"]:
            if f["severity"] == "INFO":
                continue
            all_f.append({**f, "_site": res["name"]})
    all_f.sort(key=lambda x: SEV_ORDER.index(x["severity"]))
    rows = []
    for f in all_f:
        rows.append(
            f"<tr>"
            f"<td>{_badge(f['severity'])}</td>"
            f"<td><small>{f['_site']}</small></td>"
            f"<td>{f['title']}{_cert_mgmt_badge(f)}</td>"
            f"<td><small>{f.get('effort_action', '—')}</small></td>"
            f"<td class='text-center'><strong>{f.get('effort_duration', '—')}</strong></td>"
            f"</tr>"
        )
    return "".join(rows) if rows else "<tr><td colspan='5'>Aucune action requise</td></tr>"


def _total_effort(results: list[dict]) -> str:
    minutes = 0
    for res in results:
        for f in res["findings"]:
            d = f.get("effort_duration", "—")
            if "Urgent" in d:
                minutes += 15
            elif "à" in d:
                parts = re.findall(r"\d+", d)
                if len(parts) == 2:
                    minutes += int((int(parts[0]) + int(parts[1])) / 2 * 60)
            else:
                parts = re.findall(r"\d+", d)
                if parts:
                    val = int(parts[0])
                    minutes += val * 60 if ("h" in d and "min" not in d) else val
    if minutes >= 60:
        h, m = minutes // 60, minutes % 60
        return f"{h}h{m:02d}" if m else f"{h}h"
    return f"{minutes} min"


def generate_report_html(results: list[dict]) -> str:
    """Génère le rapport HTML complet et retourne une chaîne (pas d'écriture fichier)."""
    generated    = datetime.now().strftime("%Y-%m-%d %H:%M")
    total_effort = _total_effort(results)

    summary_rows = []
    for res in results:
        g      = res["grade"]
        gcolor = GRADE_HEX.get(g, "#6c757d")
        by_sev = {s: sum(1 for f in res["findings"] if f["severity"] == s) for s in SEV_ORDER}
        bar = (f"<div class='progress' style='height:12px;min-width:80px'>"
               f"<div class='progress-bar' style='width:{res['score']}%;background:{gcolor}'>"
               f"</div></div>")
        summary_rows.append(
            f"<tr>"
            f"<td><strong>{res['name']}</strong><br>"
            f"<small class='text-muted'>{res['url']}</small></td>"
            f"<td class='text-center'>{bar}<small>{res['score']}/100</small></td>"
            f"<td class='text-center'>"
            f"<span class='badge fs-6' style='background:{gcolor}'>{g}</span></td>"
            f"<td class='text-center text-danger fw-bold'>{by_sev['CRITICAL'] or '—'}</td>"
            f"<td class='text-center' style='color:#fd7e14'>{by_sev['HIGH'] or '—'}</td>"
            f"<td class='text-center' style='color:#856404'>{by_sev['MEDIUM'] or '—'}</td>"
            f"<td class='text-center text-primary'>{by_sev['LOW'] or '—'}</td>"
            f"</tr>"
        )

    site_sections = []
    for res in results:
        g      = res["grade"]
        gcolor = GRADE_HEX.get(g, "#6c757d")
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

    critical_total = sum(
        sum(1 for f in r["findings"] if f["severity"] == "CRITICAL") for r in results
    )

    return f"""<!DOCTYPE html>
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
      .cover {{ background: #1a1a2e !important;
               -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .badge, .progress-bar {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
      .card {{ break-inside: avoid; }}
      @page {{ margin: 1.5cm; }}
    }}
  </style>
</head>
<body class="bg-light">

<div class="cover">
  <h1>Rapport d'audit de sécurité</h1>
  <div class="subtitle">Analyse automatisée — {generated}</div>
  <div class="mt-4 d-flex gap-4 flex-wrap">
    <div>
      <div style="color:#aaa;font-size:0.8rem">SITES AUDITÉS</div>
      <div style="font-size:1.8rem;font-weight:700">{len(results)}</div>
    </div>
    <div>
      <div style="color:#aaa;font-size:0.8rem">VULNÉRABILITÉS CRITIQUES</div>
      <div style="font-size:1.8rem;font-weight:700;color:#ff6b6b">{critical_total}</div>
    </div>
    <div>
      <div style="color:#aaa;font-size:0.8rem">TEMPS DE CORRECTION ESTIMÉ</div>
      <div style="font-size:1.8rem;font-weight:700;color:#51cf66">{total_effort}</div>
    </div>
  </div>
</div>

<div class="container-lg pb-5">

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
