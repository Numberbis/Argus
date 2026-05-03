#!/usr/bin/env python3
"""
Rapport d'audit de sécurité — organisé par site avec score de sécurité.

Affiche pour chaque site configuré dans config/websites.yml :
  - score de sécurité (0-100) et grade (A+ à F)
  - outils appliqués et leur statut
  - findings triés par sévérité

Usage :
    python scripts/show-audit-results.py
    DB_URL=postgresql://audit:test@localhost:5433/audit_test python scripts/show-audit-results.py
    python scripts/show-audit-results.py --target buildweb
    python scripts/show-audit-results.py --severity CRITICAL HIGH
    python scripts/show-audit-results.py --max-findings 10
"""
import argparse
import os
import sys
from pathlib import Path
from collections import defaultdict

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("❌  psycopg2 manquant. Lancez : pip install psycopg2-binary")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("❌  pyyaml manquant. Lancez : pip install pyyaml")
    sys.exit(1)

# ── Couleurs ANSI ─────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
GREEN  = "\033[32m"
GREY   = "\033[90m"
WHITE  = "\033[97m"

SEVERITY_ORDER = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}

SEVERITY_COLOR = {
    "CRITICAL": f"\033[41m{BOLD} CRITICAL {RESET}",
    "HIGH":     f"{RED}{BOLD} HIGH     {RESET}",
    "MEDIUM":   f"{YELLOW} MEDIUM   {RESET}",
    "LOW":      f"{CYAN} LOW      {RESET}",
    "INFO":     f"{GREY} INFO     {RESET}",
}

ALL_TOOLS = ["zap", "nikto", "nmap", "testssl", "nuclei", "observatory", "retirejs"]

CONFIG_PATH = Path(__file__).parents[1] / "config" / "websites.yml"

# ── Calcul du score de sécurité ───────────────────────────────────────────────
#
# Score de base : 100 points
# Pénalités par finding (plafonnées pour éviter qu'un seul type écrase tout) :
#   CRITICAL : -25 pts chacun, max -75
#   HIGH     : -15 pts chacun, max -45
#   MEDIUM   :  -5 pts chacun, max -20
#   LOW      :  -2 pts chacun, max -10
#   INFO     :   0 pt
#
SCORE_PENALTY  = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 2, "INFO": 0}
SCORE_CAP      = {"CRITICAL": 75, "HIGH": 45, "MEDIUM": 20, "LOW": 10, "INFO": 0}

GRADE_THRESHOLDS = [
    (95, "A+", f"\033[92m{BOLD}"),   # vert brillant
    (85, "A",  f"{GREEN}{BOLD}"),
    (70, "B",  f"\033[32m"),
    (50, "C",  f"{YELLOW}"),
    (25, "D",  f"\033[33m{BOLD}"),
    (0,  "F",  f"{RED}{BOLD}"),
]


def calculate_score(findings: list[dict]) -> tuple[int, str, str]:
    """Retourne (score 0-100, grade, couleur ANSI)."""
    from collections import Counter
    counts = Counter(f["severity"].upper() for f in findings)
    score  = 100
    for sev, penalty in SCORE_PENALTY.items():
        deduction = min(counts.get(sev, 0) * penalty, SCORE_CAP[sev])
        score    -= deduction
    score = max(0, score)
    for threshold, grade, color in GRADE_THRESHOLDS:
        if score >= threshold:
            return score, grade, color
    return score, "F", f"{RED}{BOLD}"


def score_bar(score: int, color: str, width: int = 20) -> str:
    filled = round(score / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    return f"{color}{bar}{RESET}"


# ── Chargement config ─────────────────────────────────────────────────────────

def load_websites(target_filter=None) -> list[dict]:
    with open(CONFIG_PATH) as f:
        sites = yaml.safe_load(f)["websites"]
    if target_filter:
        sites = [s for s in sites if s["name"] == target_filter]
    return sites


# ── Connexion ─────────────────────────────────────────────────────────────────

def get_conn(db_url: str):
    return psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)


# ── Requêtes ──────────────────────────────────────────────────────────────────

def fetch_last_scan_per_tool(conn, target: str) -> dict[str, dict]:
    with conn.cursor() as cur:
        cur.execute(
            """SELECT DISTINCT ON (tool)
                   id, tool, target, target_url, started_at, finished_at, status
               FROM scans
               WHERE target = %s
               ORDER BY tool, started_at DESC""",
            (target,),
        )
        return {row["tool"]: dict(row) for row in cur.fetchall()}


def fetch_all_findings_for_site(conn, target: str) -> list[dict]:
    """
    Findings du DERNIER scan par outil uniquement.
    Les données de test (titre préfixé [TEST]) sont exclues.
    """
    with conn.cursor() as cur:
        cur.execute(
            """SELECT
                   f.severity, f.title, f.description, f.url,
                   f.cvss_score, f.cve_ids, f.remediation, f.notified_at,
                   s.tool, s.started_at
               FROM findings f
               JOIN scans s ON s.id = f.scan_id
               WHERE s.id IN (
                   SELECT DISTINCT ON (tool) id
                   FROM scans
                   WHERE target = %s
                   ORDER BY tool, started_at DESC
               )
               AND f.title NOT LIKE '[TEST]%%'
               ORDER BY
                   CASE f.severity
                     WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                     WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5
                   END,
                   s.tool""",
            (target,),
        )
        return [dict(row) for row in cur.fetchall()]


def fetch_global_summary(conn, site_names: list[str]) -> dict[str, dict]:
    """Comptage sur le dernier scan par outil, hors données de test."""
    if not site_names:
        return {}
    with conn.cursor() as cur:
        cur.execute(
            """SELECT s.target, f.severity, COUNT(*) AS total
               FROM findings f
               JOIN scans s ON s.id = f.scan_id
               WHERE s.target = ANY(%s)
                 AND s.id IN (
                     SELECT DISTINCT ON (tool, target) id
                     FROM scans
                     WHERE target = ANY(%s)
                     ORDER BY tool, target, started_at DESC
                 )
                 AND f.title NOT LIKE '[TEST]%%'
               GROUP BY s.target, f.severity""",
            (site_names, site_names),
        )
        result = defaultdict(lambda: {sev: 0 for sev in SEVERITY_ORDER})
        for row in cur.fetchall():
            result[row["target"]][row["severity"]] = row["total"]
        return result


def fetch_all_findings_for_summary(conn, site_names: list[str]) -> dict[str, list]:
    """Findings du dernier scan par outil par site, pour le calcul des scores."""
    if not site_names:
        return {}
    with conn.cursor() as cur:
        cur.execute(
            """SELECT s.target, f.severity
               FROM findings f
               JOIN scans s ON s.id = f.scan_id
               WHERE s.target = ANY(%s)
                 AND s.id IN (
                     SELECT DISTINCT ON (tool, target) id
                     FROM scans
                     WHERE target = ANY(%s)
                     ORDER BY tool, target, started_at DESC
                 )
                 AND f.title NOT LIKE '[TEST]%%'""",
            (site_names, site_names),
        )
        result = defaultdict(list)
        for row in cur.fetchall():
            result[row["target"]].append({"severity": row["severity"]})
        return result


# ── Formatage ─────────────────────────────────────────────────────────────────

def fmt_date(d) -> str:
    if d is None:
        return f"{GREY}—{RESET}"
    if isinstance(d, str):
        return d[:16]
    return d.strftime("%Y-%m-%d %H:%M")


def fmt_status(s: str) -> str:
    colors = {
        "completed": f"{GREEN}✔ completed{RESET}",
        "running":   f"{YELLOW}⟳ running  {RESET}",
    }
    return colors.get(s, f"{RED}✘ {s}{RESET}")


def colored_sev(s: str) -> str:
    return SEVERITY_COLOR.get(s.upper(), f" {s:<8} ")


# ── Affichage ─────────────────────────────────────────────────────────────────

def print_global_summary(summary: dict, findings_by_site: dict, sites: list[dict]):
    severities  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_colors  = [
        f"\033[41m{BOLD}CRIT{RESET}", f"{RED}{BOLD}HIGH{RESET}",
        f"{YELLOW}MED {RESET}",       f"{CYAN}LOW {RESET}",
        f"{GREY}INFO{RESET}",
    ]

    print(f"\n{BOLD}{'═'*80}{RESET}")
    print(f"  {BOLD}RÉSUMÉ GLOBAL — Score de sécurité par site{RESET}")
    print(f"{BOLD}{'═'*80}{RESET}")
    header = (f"  {'Site':<26} {'Score':>6}  {'Grade':>5}  "
              + "".join(f"  {c}" for c in sev_colors))
    print(header)
    print(f"  {'─'*76}")

    grand_total = {sev: 0 for sev in severities}
    for site in sites:
        name     = site["name"]
        counts   = summary.get(name, {})
        findings = findings_by_site.get(name, [])
        score, grade, color = calculate_score(findings)
        bar      = score_bar(score, color, width=12)

        row = (f"  {name:<26} {color}{BOLD}{score:>3}/100{RESET}  "
               f"{color}{BOLD}{grade:>5}{RESET}  {bar}"
               + "".join(f"  {counts.get(sev, 0):>4}" for sev in severities))
        print(row)
        for sev in severities:
            grand_total[sev] += counts.get(sev, 0)

    print(f"  {'─'*76}")
    total_all = sum(grand_total.values())
    print(f"  {BOLD}{'TOTAL':<26} {'':>6}  {'':>5}  {'':12}"
          + "".join(f"  {grand_total[sev]:>4}" for sev in severities)
          + f"  = {total_all}{RESET}")
    print()
    print(f"  {GREY}Grille : A+(95-100)  A(85-94)  B(70-84)  C(50-69)  D(25-49)  F(<25){RESET}\n")


def print_site_report(site: dict, scans_by_tool: dict, findings: list,
                      severities_filter, max_findings):
    name  = site["name"]
    url   = site["url"]
    score, grade, color = calculate_score(findings)
    bar   = score_bar(score, color, width=20)

    # Couverture : nombre d'outils ayant tourné
    coverage = len(scans_by_tool)
    total_tools = len(ALL_TOOLS)

    print(f"\n{BOLD}{'━'*80}{RESET}")
    print(f"  {BOLD}SITE : {name}{RESET}   {GREY}{url}{RESET}")
    print(f"  Score : {color}{BOLD}{score}/100  {grade}{RESET}  {bar}  "
          f"  Couverture : {coverage}/{total_tools} outils")
    print(f"{BOLD}{'━'*80}{RESET}\n")

    # ── Outils appliqués ──────────────────────────────────────────────────────
    print(f"  {BOLD}Outils de scan appliqués :{RESET}")
    print(f"  {'Outil':<12}  {'Dernier scan':<18}  {'Statut':<20}  {'Terminé':<18}  Findings")
    print(f"  {'─'*82}")
    for tool in ALL_TOOLS:
        if tool in scans_by_tool:
            scan = scans_by_tool[tool]
            nb   = sum(1 for f in findings if f["tool"] == tool)
            has_high = any(f["severity"] in ("CRITICAL", "HIGH")
                           for f in findings if f["tool"] == tool)
            nb_str = f"{RED}{BOLD}{nb}{RESET}" if has_high else (
                     f"{YELLOW}{nb}{RESET}" if nb else str(nb))
            print(f"  {GREEN}✔{RESET} {tool:<10}  "
                  f"{fmt_date(scan['started_at']):<18}  "
                  f"{fmt_status(scan['status']):<20}  "
                  f"{fmt_date(scan['finished_at']):<18}  {nb_str}")
        else:
            print(f"  {GREY}—{RESET} {tool:<10}  {GREY}jamais exécuté{RESET}")
    print()

    # ── Score détaillé ────────────────────────────────────────────────────────
    from collections import Counter
    counts = Counter(f["severity"].upper() for f in findings)
    print(f"  {BOLD}Décomposition du score :{RESET}")
    print(f"  {'Sévérité':<12}  {'Findings':>8}  {'Pénalité/finding':>18}  {'Total déduit':>14}")
    print(f"  {'─'*56}")
    total_deducted = 0
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        nb_sev   = counts.get(sev, 0)
        penalty  = SCORE_PENALTY[sev]
        deducted = min(nb_sev * penalty, SCORE_CAP[sev])
        total_deducted += deducted
        if nb_sev or sev in ("CRITICAL", "HIGH"):
            color_sev = (RED if sev in ("CRITICAL", "HIGH")
                         else YELLOW if sev == "MEDIUM"
                         else CYAN if sev == "LOW" else GREY)
            print(f"  {color_sev}{sev:<12}{RESET}  {nb_sev:>8}  "
                  f"  -{penalty} pts{' (plafonné)' if nb_sev * penalty > SCORE_CAP[sev] else '':>9}"
                  f"  {'-' + str(deducted):>14}")
    print(f"  {'─'*56}")
    print(f"  {'Score final':<12}  {'':>8}  {'100 -' + str(total_deducted):>18}  "
          f"  {color}{BOLD}{score}/100  {grade}{RESET}\n")

    # ── Findings ──────────────────────────────────────────────────────────────
    filtered = [f for f in findings
                if not severities_filter or f["severity"].upper() in severities_filter]
    if max_findings:
        filtered = filtered[:max_findings]

    if not filtered:
        msg = "Aucun finding" + (" pour ce filtre de sévérité" if severities_filter else "")
        print(f"  {GREEN}✔ {msg} — site sûr sur les critères testés{RESET}\n")
        return

    print(f"  {BOLD}Findings ({len(filtered)}) :{RESET}")
    print(f"  {'─'*70}")

    current_sev = None
    for f in filtered:
        if f["severity"] != current_sev:
            current_sev = f["severity"]
            print(f"\n  {colored_sev(f['severity'])}")

        cvss    = f"  CVSS={BOLD}{f['cvss_score']}{RESET}" if f["cvss_score"] else ""
        cves    = f"  {GREY}{' '.join(f['cve_ids'])}{RESET}" if f.get("cve_ids") else ""
        notif   = f"  {GREEN}✔ notifié{RESET}" if f["notified_at"] else ""
        tool_tag = f"  [{CYAN}{f['tool'].upper()}{RESET}]"

        print(f"    {BOLD}{f['title']}{RESET}{tool_tag}{cvss}{cves}{notif}")
        if f.get("url"):
            print(f"    {GREY}↳ URL        : {f['url']}{RESET}")
        if f.get("description"):
            desc = f["description"][:120] + ("…" if len(f["description"]) > 120 else "")
            print(f"    {GREY}↳ Détail     : {desc}{RESET}")
        if f.get("remediation"):
            rem = f["remediation"][:120] + ("…" if len(f["remediation"]) > 120 else "")
            print(f"    {GREY}↳ Remédiation: {rem}{RESET}")
        print()

    if max_findings and len(findings) > max_findings:
        remaining = len(findings) - max_findings
        print(f"  {GREY}… {remaining} finding(s) supplémentaire(s) "
              f"(--max-findings pour ajuster){RESET}\n")


# ── Point d'entrée ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Rapport d'audit de sécurité par site")
    parser.add_argument("--target",       "-t", help="Un seul site (ex: buildweb)")
    parser.add_argument("--severity",     "-s", nargs="+", metavar="SEV",
                        help="CRITICAL HIGH MEDIUM LOW INFO")
    parser.add_argument("--max-findings", "-m", type=int, default=0,
                        help="Nombre max de findings par site (0 = tous)")
    args = parser.parse_args()

    db_url = os.environ.get("DB_URL") or os.environ.get("INTEGRATION_TEST_DB_URL")
    if not db_url:
        print("❌  Variable DB_URL non définie.")
        sys.exit(1)

    severities_filter = {s.upper() for s in args.severity} if args.severity else None
    max_findings      = args.max_findings or 0

    try:
        sites = load_websites(args.target)
    except FileNotFoundError:
        print(f"❌  Fichier introuvable : {CONFIG_PATH}")
        sys.exit(1)

    if not sites:
        print(f"❌  Aucun site trouvé{' pour ' + args.target if args.target else ''}.")
        sys.exit(1)

    try:
        conn = get_conn(db_url)
    except Exception as e:
        print(f"❌  Connexion impossible : {e}")
        sys.exit(1)

    try:
        host = db_url.split("@")[-1] if "@" in db_url else db_url
        print(f"\n{BOLD}{'═'*80}{RESET}")
        print(f"  {BOLD}RAPPORT D'AUDIT DE SÉCURITÉ{RESET}   {GREY}Base : {host}{RESET}")
        print(f"{BOLD}{'═'*80}{RESET}")

        site_names       = [s["name"] for s in sites]
        summary          = fetch_global_summary(conn, site_names)
        findings_by_site = fetch_all_findings_for_summary(conn, site_names)

        print_global_summary(summary, findings_by_site, sites)

        for site in sites:
            scans_by_tool = fetch_last_scan_per_tool(conn, site["name"])
            findings      = fetch_all_findings_for_site(conn, site["name"])
            print_site_report(site, scans_by_tool, findings, severities_filter, max_findings)

    finally:
        conn.close()


if __name__ == "__main__":
    main()
