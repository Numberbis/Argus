"""
Demo Seeder — insère des données réalistes pour la démonstration de Argus.
Lance via : make demo   ou   docker compose --profile demo run --rm demo-seeder
"""
import os
import json
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta, timezone
import random

DB_URL = os.environ["DB_URL"]

# ── Données de démo ────────────────────────────────────────────────────────────

SITES = [
    {"name": "example-blog",       "url": "https://blog.example.com"},
    {"name": "example-shop",       "url": "https://shop.example.com"},
    {"name": "example-restaurant", "url": "https://restaurant.example.com"},
    {"name": "example-wp-site",    "url": "https://wp.example.com"},
    {"name": "example-portfolio",  "url": "https://portfolio.example.com"},
    {"name": "example-api",        "url": "https://api.example.com"},
]

TOOLS = ["zap", "nikto", "nmap", "testssl", "nuclei", "wpscan", "trivy"]

# Findings réalistes par outil
FINDINGS_TEMPLATES = {
    "zap": [
        {"severity": "HIGH",     "title": "SQL Injection",                         "description": "Une injection SQL a été détectée dans le paramètre `id` de la page de recherche. Un attaquant peut extraire ou modifier la base de données.", "url": "/search?id=1", "cvss_score": 9.8, "cve_ids": ["CVE-2023-1234"], "remediation": "Utiliser des requêtes préparées (PDO/MySQLi). Ne jamais concatener l'input utilisateur dans une requête SQL."},
        {"severity": "HIGH",     "title": "Cross-Site Scripting (Reflected)",      "description": "Une faille XSS reflétée a été détectée dans le paramètre `q`. L'input utilisateur est renvoyé sans encodage dans la réponse HTML.", "url": "/recherche?q=test", "cvss_score": 7.4, "cve_ids": [], "remediation": "Encoder toutes les sorties HTML avec htmlspecialchars(). Implémenter une CSP stricte."},
        {"severity": "MEDIUM",   "title": "Missing Anti-CSRF Tokens",              "description": "Les formulaires POST ne contiennent pas de token CSRF, permettant des attaques Cross-Site Request Forgery.", "url": "/contact", "cvss_score": 6.5, "cve_ids": [], "remediation": "Ajouter un token CSRF synchronisé dans chaque formulaire POST."},
        {"severity": "MEDIUM",   "title": "X-Frame-Options Header Missing",        "description": "L'en-tête X-Frame-Options est absent, permettant le clickjacking via un iframe malveillant.", "url": "/", "cvss_score": 4.3, "cve_ids": [], "remediation": "Ajouter l'en-tête : X-Frame-Options: SAMEORIGIN"},
        {"severity": "LOW",      "title": "Cookie Without Secure Flag",            "description": "Le cookie de session est transmis sans le flag Secure, le rendant lisible en HTTP clair.", "url": "/login", "cvss_score": 3.7, "cve_ids": [], "remediation": "Ajouter le flag Secure et HttpOnly aux cookies de session."},
        {"severity": "INFO",     "title": "Informations serveur divulguées",       "description": "L'en-tête Server révèle la version Apache : Apache/2.4.51. Cela aide les attaquants à cibler des CVE connues.", "url": "/", "cvss_score": None, "cve_ids": [], "remediation": "Supprimer ou généraliser l'en-tête Server dans la configuration Apache."},
    ],
    "nikto": [
        {"severity": "HIGH",     "title": "phpMyAdmin accessible publiquement",    "description": "L'interface phpMyAdmin est accessible sans restriction à /phpmyadmin. Risque d'accès direct à la base de données.", "url": "/phpmyadmin/", "cvss_score": 8.1, "cve_ids": [], "remediation": "Restreindre l'accès à phpMyAdmin par IP ou supprimer si non nécessaire."},
        {"severity": "MEDIUM",   "title": "Répertoire .git exposé",               "description": "Le répertoire .git est accessible publiquement, révélant le code source et l'historique du projet.", "url": "/.git/HEAD", "cvss_score": 7.5, "cve_ids": [], "remediation": "Bloquer l'accès au répertoire .git via la configuration serveur (Deny from all)."},
        {"severity": "MEDIUM",   "title": "Fichier .env exposé",                  "description": "Le fichier .env contenant des variables d'environnement (credentials, clés API) est accessible publiquement.", "url": "/.env", "cvss_score": 7.5, "cve_ids": [], "remediation": "Bloquer l'accès aux fichiers .env et les exclure du dossier web public."},
        {"severity": "LOW",      "title": "Méthode HTTP TRACE activée",           "description": "La méthode TRACE est activée sur le serveur, permettant des attaques XST (Cross-Site Tracing).", "url": "/", "cvss_score": 3.4, "cve_ids": [], "remediation": "Désactiver la méthode TRACE dans la configuration Apache : TraceEnable Off"},
        {"severity": "INFO",     "title": "Page d'index Apache par défaut",       "description": "La page d'accueil par défaut Apache est affichée, révélant la version et la configuration du serveur.", "url": "/", "cvss_score": None, "cve_ids": [], "remediation": "Remplacer la page par défaut par la vraie application."},
    ],
    "nmap": [
        {"severity": "MEDIUM",   "title": "Port 8080 ouvert (HTTP alternatif)",   "description": "Le port 8080 est ouvert et expose un service HTTP non chiffré. Potentiel panneau d'administration accessible.", "url": ":8080/", "cvss_score": 5.3, "cve_ids": [], "remediation": "Fermer le port 8080 ou le restreindre par firewall. Forcer HTTPS."},
        {"severity": "MEDIUM",   "title": "Port 22 SSH accessible depuis Internet","description": "Le port 22 SSH est exposé publiquement. Risque de brute-force et d'exploitation de vulnérabilités SSH.", "url": ":22", "cvss_score": 5.9, "cve_ids": [], "remediation": "Restreindre l'accès SSH par IP. Utiliser des clés SSH et désactiver l'authentification par mot de passe."},
        {"severity": "LOW",      "title": "Bannière SSH divulguée",               "description": "La bannière SSH révèle la version OpenSSH : OpenSSH_8.4p1.", "url": ":22", "cvss_score": 2.6, "cve_ids": [], "remediation": "Configurer une bannière neutre dans sshd_config."},
        {"severity": "INFO",     "title": "Port 443 HTTPS ouvert",                "description": "Port HTTPS standard ouvert — comportement attendu.", "url": ":443", "cvss_score": None, "cve_ids": [], "remediation": ""},
    ],
    "testssl": [
        {"severity": "CRITICAL", "title": "Certificat SSL expiré",                "description": "Le certificat TLS a expiré il y a 14 jours. Les navigateurs affichent une erreur de sécurité aux visiteurs.", "url": "/", "cvss_score": 9.1, "cve_ids": [], "remediation": "Renouveler le certificat immédiatement via Let's Encrypt (certbot renew) ou votre autorité de certification."},
        {"severity": "HIGH",     "title": "TLS 1.0 et TLS 1.1 activés",          "description": "Les protocoles obsolètes TLS 1.0 et 1.1 sont acceptés. Vulnérables aux attaques POODLE et BEAST.", "url": "/", "cvss_score": 7.5, "cve_ids": ["CVE-2014-3566"], "remediation": "Désactiver TLS 1.0 et 1.1 dans la configuration du serveur. Accepter uniquement TLS 1.2+."},
        {"severity": "MEDIUM",   "title": "Cipher suite faible (RC4)",            "description": "Le chiffrement RC4 est accepté. Cet algorithme est considéré cassé depuis 2015 (RFC 7465).", "url": "/", "cvss_score": 5.9, "cve_ids": ["CVE-2013-2566"], "remediation": "Supprimer RC4 de la liste des cipher suites autorisées."},
        {"severity": "LOW",      "title": "HSTS absent",                          "description": "L'en-tête Strict-Transport-Security (HSTS) est absent. Les navigateurs n'imposent pas HTTPS pour les visites suivantes.", "url": "/", "cvss_score": 4.0, "cve_ids": [], "remediation": "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains"},
        {"severity": "INFO",     "title": "Certificat valide Let's Encrypt",      "description": "Certificat TLS valide, émis par Let's Encrypt. Expire dans 45 jours.", "url": "/", "cvss_score": None, "cve_ids": [], "remediation": ""},
    ],
    "nuclei": [
        {"severity": "CRITICAL", "title": "CVE-2023-44487 — HTTP/2 Rapid Reset",  "description": "La version de nginx est vulnérable à l'attaque HTTP/2 Rapid Reset permettant un DDoS à très haute intensité avec peu de ressources.", "url": "/", "cvss_score": 9.8, "cve_ids": ["CVE-2023-44487"], "remediation": "Mettre à jour nginx vers 1.25.3+ ou désactiver HTTP/2 temporairement."},
        {"severity": "HIGH",     "title": "Panneau WordPress wp-login.php exposé", "description": "La page de connexion WordPress est accessible publiquement et n'est pas protégée contre le brute-force.", "url": "/wp-login.php", "cvss_score": 7.2, "cve_ids": [], "remediation": "Limiter l'accès à wp-login.php par IP. Activer la double authentification (2FA)."},
        {"severity": "MEDIUM",   "title": "API REST WordPress non authentifiée",  "description": "L'API REST WordPress /wp-json/wp/v2/users expose la liste des utilisateurs du site sans authentification.", "url": "/wp-json/wp/v2/users", "cvss_score": 5.3, "cve_ids": [], "remediation": "Désactiver l'API REST pour les visiteurs non authentifiés."},
        {"severity": "LOW",      "title": "Fichier xmlrpc.php accessible",        "description": "Le fichier xmlrpc.php est accessible et peut être utilisé pour des attaques de brute-force amplifiées.", "url": "/xmlrpc.php", "cvss_score": 4.3, "cve_ids": [], "remediation": "Désactiver XML-RPC via le filtre WordPress ou bloquer l'accès dans .htaccess."},
    ],
    "wpscan": [
        {"severity": "HIGH",     "title": "WordPress 6.3.1 — vulnérabilité XSS",  "description": "La version WordPress 6.3.1 installée est vulnérable à une injection XSS dans le bloc Gutenberg.", "url": "/wp-admin/", "cvss_score": 7.1, "cve_ids": ["CVE-2023-5561"], "remediation": "Mettre à jour WordPress vers 6.4.2 ou supérieur."},
        {"severity": "HIGH",     "title": "Plugin Contact Form 7 v5.7.5 vulnérable","description": "Contact Form 7 v5.7.5 est vulnérable à une faille de type Unrestricted File Upload.", "url": "/wp-content/plugins/contact-form-7/", "cvss_score": 7.5, "cve_ids": ["CVE-2023-6449"], "remediation": "Mettre à jour Contact Form 7 vers 5.8.4+."},
        {"severity": "MEDIUM",   "title": "Utilisateurs WordPress énumérés",      "description": "Les comptes admin, editor ont été énumérés via l'API REST /wp-json/wp/v2/users.", "url": "/wp-json/wp/v2/users", "cvss_score": 5.3, "cve_ids": [], "remediation": "Désactiver l'API REST pour les non-authentifiés (plugin ou filtre WordPress)."},
        {"severity": "MEDIUM",   "title": "Thème Divi v4.22 vulnérable",         "description": "Thème Divi v4.22 contient une vulnérabilité XSS persistant dans le module de commentaires.", "url": "/wp-content/themes/divi/", "cvss_score": 6.1, "cve_ids": ["CVE-2023-3413"], "remediation": "Mettre à jour le thème Divi vers 4.24+."},
        {"severity": "LOW",      "title": "readme.html WordPress accessible",     "description": "Le fichier readme.html révèle la version exacte de WordPress installée.", "url": "/readme.html", "cvss_score": 2.0, "cve_ids": [], "remediation": "Supprimer readme.html ou bloquer l'accès via .htaccess."},
    ],
    "trivy": [
        {"severity": "CRITICAL", "title": "openssl 3.0.2 — CVE-2022-0778",       "description": "La version openssl installée est vulnérable à une boucle infinie lors du traitement de certificats malformés (DoS).", "url": "/", "cvss_score": 9.8, "cve_ids": ["CVE-2022-0778"], "remediation": "Mettre à jour openssl : apt-get upgrade openssl"},
        {"severity": "HIGH",     "title": "libssl1.1 — CVE-2023-0286",           "description": "Vulnérabilité de type confusion dans la gestion des types X.400 d'OpenSSL.", "url": "/", "cvss_score": 7.4, "cve_ids": ["CVE-2023-0286"], "remediation": "Mettre à jour libssl : apt-get upgrade libssl1.1"},
        {"severity": "HIGH",     "title": "curl 7.68.0 — CVE-2023-23914",        "description": "Vulnérabilité dans le traitement des cookies permettant un SSRF dans certaines configurations.", "url": "/", "cvss_score": 7.5, "cve_ids": ["CVE-2023-23914"], "remediation": "Mettre à jour curl vers 8.0+."},
        {"severity": "MEDIUM",   "title": "python3.8 — CVE-2022-45061",          "description": "Déni de service lors du décodage de noms de domaine encodés en IDNA.", "url": "/", "cvss_score": 5.3, "cve_ids": ["CVE-2022-45061"], "remediation": "Mettre à jour Python vers 3.8.17+ ou 3.11+."},
        {"severity": "LOW",      "title": "tar 1.30 — CVE-2019-9923",            "description": "Déréférencement de pointeur null lors de la lecture d'un fichier tar vide.", "url": "/", "cvss_score": 3.3, "cve_ids": ["CVE-2019-9923"], "remediation": "Mettre à jour tar : apt-get upgrade tar"},
    ],
}


def now_minus(days: int = 0, hours: int = 0) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days, hours=hours)


def seed(conn):
    cur = conn.cursor()

    print("  → Nettoyage des données existantes...")
    cur.execute("DELETE FROM findings")
    cur.execute("DELETE FROM scans")
    cur.execute("DELETE FROM reports")
    cur.execute("DELETE FROM root_causes")
    cur.execute("DELETE FROM agent_runs")

    scan_count = 0
    finding_count = 0

    print("  → Insertion des scans de démo...")

    # Pour chaque site, insérer 3-5 scans avec des outils différents
    for site_idx, site in enumerate(SITES):
        # Décaler les dates pour simuler plusieurs jours de scans
        base_days_ago = (len(SITES) - site_idx) * 2

        for tool in TOOLS:
            # Certains sites n'ont pas tous les outils (wpscan uniquement sur WordPress)
            if tool == "wpscan" and site["name"] not in ("example-wp-site", "example-blog"):
                continue

            started = now_minus(days=base_days_ago, hours=random.randint(0, 12))
            finished = started + timedelta(minutes=random.randint(3, 25))

            cur.execute(
                """INSERT INTO scans (tool, target, target_url, started_at, finished_at, status, raw_output)
                   VALUES (%s, %s, %s, %s, %s, 'completed', %s) RETURNING id""",
                (
                    tool,
                    site["name"],
                    site["url"],
                    started,
                    finished,
                    psycopg2.extras.Json({"demo": True, "tool": tool}),
                ),
            )
            scan_id = cur.fetchone()[0]
            scan_count += 1

            templates = FINDINGS_TEMPLATES.get(tool, [])
            # Prendre un sous-ensemble aléatoire des findings (pas toujours tous)
            subset = random.sample(templates, k=random.randint(
                max(1, len(templates) - 2), len(templates)
            ))

            for f in subset:
                url = site["url"].rstrip("/") + f["url"]
                cur.execute(
                    """INSERT INTO findings
                       (scan_id, severity, title, description, url, cvss_score, cve_ids, remediation)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        scan_id,
                        f["severity"],
                        f["title"],
                        f["description"],
                        url,
                        f["cvss_score"],
                        f["cve_ids"],
                        f["remediation"],
                    ),
                )
                finding_count += 1

    conn.commit()
    print(f"  ✓ {scan_count} scans insérés")
    print(f"  ✓ {finding_count} findings insérés")

    # Simuler le triage IA pour la démo (sans clé API)
    triage_stats = simulate_triage(cur)
    conn.commit()
    cur.close()
    print(f"  ✓ Triage IA simulé : {triage_stats['real']} real issues "
          f"({triage_stats['fp']} FP filtrés, {triage_stats['dup']} doublons fusionnés)")
    print(f"  ✓ {triage_stats['root_causes']} causes racines identifiées")
    print()
    print("  Dashboard global  : http://localhost:5000")
    print("  Real Issues view  : http://localhost:5000/real-issues")


def simulate_triage(cur) -> dict:
    """Simule un triage IA réaliste pour la démo (sans appeler de vraie API LLM).

    Marque comme faux positifs les findings de type INFO (la plupart) et certains LOW
    "bannière révélée" / "page par défaut", crée des doublons quand plusieurs scans
    détectent la même CVE, regroupe les faiblesses TLS en cause racine commune.
    """
    fp_count = 0
    dup_count = 0
    real_count = 0

    # 1. Récupérer tous les findings groupés par site
    cur.execute(
        """SELECT f.id, f.severity, f.title, f.cve_ids, s.target, s.tool, s.id AS scan_id
           FROM findings f JOIN scans s ON s.id = f.scan_id
           ORDER BY s.target, f.severity, f.title"""
    )
    rows = cur.fetchall()

    # 2. Marquer les faux positifs (heuristique : INFO + certains LOW peu actionnables)
    fp_titles = {
        "Informations serveur divulguées",
        "Page d'index Apache par défaut",
        "readme.html WordPress accessible",
        "Bannière SSH divulguée",
        "Port 443 HTTPS ouvert",
        "Certificat valide Let's Encrypt",
        "Méthode HTTP TRACE activée",
    }
    fp_ids = [r[0] for r in rows if r[2] in fp_titles]
    for fid in fp_ids:
        cur.execute(
            """UPDATE findings
               SET ai_is_false_positive = TRUE, ai_severity = severity,
                   ai_confidence = 0.85, ai_triaged_at = NOW()
               WHERE id = %s""",
            (fid,),
        )
        fp_count += 1

    # 3. Doublons : même CVE détectée par plusieurs scanners → garder un canonique
    cve_to_findings: dict[tuple[str, str], list[int]] = {}
    for r in rows:
        if r[0] in fp_ids or not r[3]:
            continue
        for cve in r[3]:
            key = (r[4], cve)  # (target, cve)
            cve_to_findings.setdefault(key, []).append(r[0])
    for ids in cve_to_findings.values():
        if len(ids) > 1:
            canonical = ids[0]
            for dup in ids[1:]:
                cur.execute(
                    """UPDATE findings
                       SET ai_dedup_of = %s, ai_severity = severity,
                           ai_confidence = 0.95, ai_triaged_at = NOW()
                       WHERE id = %s""",
                    (canonical, dup),
                )
                dup_count += 1

    # 4. Regrouper les faiblesses TLS par site en root cause
    rc_count = 0
    cur.execute("SELECT DISTINCT target FROM scans ORDER BY target")
    targets = [r[0] for r in cur.fetchall()]
    for target in targets:
        cur.execute(
            """SELECT f.id, COALESCE(f.ai_severity, f.severity) AS sev
               FROM findings f JOIN scans s ON s.id = f.scan_id
               WHERE s.target = %s AND s.tool = 'testssl'
                 AND f.ai_is_false_positive IS NOT TRUE
                 AND f.ai_dedup_of IS NULL
                 AND f.title IN ('TLS 1.0 et TLS 1.1 activés', 'Cipher suite faible (RC4)',
                                 'HSTS absent')""",
            (target,),
        )
        tls_findings = cur.fetchall()
        if len(tls_findings) >= 2:
            severity = "HIGH" if any(r[1] in ("CRITICAL", "HIGH") for r in tls_findings) else "MEDIUM"
            cur.execute(
                """INSERT INTO root_causes (target, summary, severity, suggested_fix, finding_count)
                   VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                (
                    target,
                    "Configuration TLS obsolète : protocoles et chiffrements faibles, headers HSTS absents",
                    severity,
                    "Mettre à jour la configuration TLS (nginx/apache) : désactiver TLS<1.2, retirer "
                    "RC4/3DES, ajouter Strict-Transport-Security: max-age=31536000",
                    len(tls_findings),
                ),
            )
            rc_id = cur.fetchone()[0]
            rc_count += 1
            for fid, _ in tls_findings:
                cur.execute(
                    """UPDATE findings SET ai_root_cause_id = %s,
                              ai_severity = COALESCE(ai_severity, severity),
                              ai_confidence = COALESCE(ai_confidence, 0.9),
                              ai_triaged_at = NOW()
                       WHERE id = %s""",
                    (rc_id, fid),
                )

    # 5. Triager les autres findings restants (sans changer la sévérité)
    cur.execute(
        """UPDATE findings SET
             ai_severity = severity,
             ai_confidence = 0.8,
             ai_triaged_at = NOW()
           WHERE ai_triaged_at IS NULL"""
    )

    cur.execute(
        """SELECT COUNT(*) FROM findings
           WHERE ai_is_false_positive = FALSE AND ai_dedup_of IS NULL"""
    )
    real_count = cur.fetchone()[0]

    # 6. Faux entry agent_runs (pour montrer le widget budget dans le dashboard)
    cur.execute(
        """INSERT INTO agent_runs (run_type, target, provider, model, input_tokens,
                                   output_tokens, cost_usd, duration_ms, status)
           VALUES ('triage', NULL, 'demo', 'simulated', 0, 0, 0, 0, 'success')"""
    )

    return {"fp": fp_count, "dup": dup_count, "real": real_count, "root_causes": rc_count}


if __name__ == "__main__":
    print()
    print("Argus Demo Seeder")
    print("=" * 40)
    conn = psycopg2.connect(DB_URL)
    try:
        seed(conn)
    finally:
        conn.close()
