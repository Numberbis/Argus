"""
Tests d'intégration du Collector avec une vraie base PostgreSQL.
Les sites testés sont lus dynamiquement depuis config/websites.yml.

Ces tests vérifient uniquement le comportement de l'API (codes HTTP, persistence,
cohérence des données). Les findings insérés sont explicitement marqués comme
données de test — ils ne reflètent aucune vulnérabilité réelle.

Prérequis :
    docker compose -f docker-compose.test.yml up -d
    INTEGRATION_TEST_DB_URL=postgresql://audit:test@localhost:5433/audit_test pytest tests/integration/ -v
"""
import os
import sys
import time
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.skipif(
    not os.environ.get("INTEGRATION_TEST_DB_URL"),
    reason="Variable INTEGRATION_TEST_DB_URL non définie — tests d'intégration ignorés",
)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docker/collector")))

os.environ["DB_URL"] = os.environ.get(
    "INTEGRATION_TEST_DB_URL",
    "postgresql://audit:test@localhost:5433/audit_test",
)

from fastapi.testclient import TestClient
import main


# ── Chargement de la config des sites ─────────────────────────────────────────

CONFIG_PATH = Path(__file__).parents[2] / "config" / "websites.yml"

def load_websites() -> list[dict]:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)["websites"]

WEBSITES    = load_websites()
WEBSITE_IDS = [site["name"] for site in WEBSITES]


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    with TestClient(main.app) as c:
        yield c


@pytest.fixture(scope="module", autouse=True)
def prepare_db():
    """Attend que PostgreSQL soit prêt puis purge les données de test précédentes."""
    import psycopg2
    db_url = os.environ["DB_URL"]

    # Attente démarrage PostgreSQL
    for _ in range(30):
        try:
            conn = psycopg2.connect(db_url)
            conn.close()
            break
        except Exception:
            time.sleep(1)
    else:
        pytest.fail("Impossible de se connecter à la base de données de test")

    # Nettoyage des données laissées par un run précédent
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE findings, scans, reports RESTART IDENTITY CASCADE")
        conn.commit()
    finally:
        conn.close()


# ── Helpers ───────────────────────────────────────────────────────────────────

def build_payload(site: dict, tool: str, started_at: str, findings: list) -> dict:
    """Construit un payload de test avec des findings clairement marqués comme fictifs."""
    return {
        "started_at": started_at,
        "target_url": site["url"],
        "findings": findings,
        "raw_output": {"source": "integration-test", "target": site["name"], "tool": tool},
    }


def make_finding(severity: str, label: str) -> dict:
    """
    Finding utilisé uniquement pour tester la persistence de l'API.
    Le titre préfixé [TEST] signale qu'il ne s'agit pas d'une vulnérabilité réelle.
    """
    return {
        "severity": severity,
        "title":    f"[TEST] Donnée fictive — vérification persistence ({label})",
        "description": "Finding synthétique injecté par les tests d'intégration. Ne reflète aucune vulnérabilité réelle.",
        "remediation": "Aucune action requise — donnée de test.",
    }


# ── Tests généraux ────────────────────────────────────────────────────────────

class TestIntegrationCollectorApi:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_outil_invalide_rejete(self, client):
        site = WEBSITES[0]
        payload = build_payload(site, "unknown", "2026-03-21T12:00:00Z", [])
        response = client.post(f"/results/unknown_tool/{site['name']}", json=payload)
        assert response.status_code == 400

    def test_payload_malformed_rejete(self, client):
        site = WEBSITES[0]
        response = client.post(f"/results/zap/{site['name']}", json={"invalid": "data"})
        assert response.status_code == 422


# ── Tests paramétrés par site ─────────────────────────────────────────────────

class TestParSite:
    @pytest.mark.parametrize("site", WEBSITES, ids=WEBSITE_IDS)
    def test_soumission_scan_acceptee(self, client, site):
        """L'API doit accepter un résultat de scan pour chaque site configuré."""
        payload = build_payload(
            site, "zap", "2026-03-21T10:00:00Z",
            [make_finding("HIGH", f"zap/{site['name']}")],
        )
        response = client.post(f"/results/zap/{site['name']}", json=payload)
        assert response.status_code == 202, f"Échec pour {site['name']} ({site['url']})"
        data = response.json()
        assert data["scan_id"] > 0
        assert data["accepted"] == 1

    @pytest.mark.parametrize("site", WEBSITES, ids=WEBSITE_IDS)
    def test_scan_sans_finding_accepte(self, client, site):
        """Un scan sans finding doit être accepté (cible sans anomalie détectée)."""
        payload = build_payload(site, "testssl", "2026-03-21T10:30:00Z", [])
        response = client.post(f"/results/testssl/{site['name']}", json=payload)
        assert response.status_code == 202
        assert response.json()["accepted"] == 0

    @pytest.mark.parametrize("site", WEBSITES, ids=WEBSITE_IDS)
    def test_target_url_persistee(self, client, site):
        """L'URL de la cible doit être correctement persistée en base."""
        time.sleep(1)
        response = client.get(f"/scans?target={site['name']}&limit=1")
        assert response.status_code == 200
        scans = response.json()
        assert len(scans) >= 1, f"Aucun scan trouvé pour {site['name']}"
        assert scans[0]["target"] == site["name"]

    @pytest.mark.parametrize("site", WEBSITES, ids=WEBSITE_IDS)
    def test_tous_les_outils_acceptes(self, client, site):
        """Les 7 outils de scan doivent pouvoir soumettre des résultats pour chaque site."""
        for outil in ["zap", "nikto", "nmap", "testssl", "nuclei", "observatory", "retirejs"]:
            payload = build_payload(
                site, outil, "2026-03-21T11:00:00Z",
                [make_finding("INFO", f"{outil}/{site['name']}")],
            )
            response = client.post(f"/results/{outil}/{site['name']}", json=payload)
            assert response.status_code == 202, \
                f"Outil {outil} a échoué sur {site['name']} ({site['url']})"

    @pytest.mark.parametrize("site", WEBSITES, ids=WEBSITE_IDS)
    def test_observatory_en_tetes_manquants(self, client, site):
        """Observatory doit pouvoir remonter des lacunes d'en-têtes de sécurité."""
        findings = [
            {
                "severity":    "HIGH",
                "title":       "En-tête de sécurité : Content-Security-Policy absent",
                "description": "Aucun en-tête Content-Security-Policy détecté.",
                "url":         site["url"],
                "remediation": "Ajouter un en-tête Content-Security-Policy restrictif.",
            },
            {
                "severity":    "MEDIUM",
                "title":       "En-tête de sécurité : Referrer-Policy absent",
                "description": "L'en-tête Referrer-Policy n'est pas défini.",
                "url":         site["url"],
                "remediation": "Ajouter Referrer-Policy: strict-origin-when-cross-origin.",
            },
        ]
        payload = {
            "started_at": "2026-03-21T14:00:00Z",
            "target_url": site["url"],
            "findings":   findings,
            "raw_output": {"score": 55, "grade": "C", "tests_passed": 5, "tests_failed": 2},
        }
        response = client.post(f"/results/observatory/{site['name']}", json=payload)
        assert response.status_code == 202
        assert response.json()["accepted"] == 2

    @pytest.mark.parametrize("site", WEBSITES, ids=WEBSITE_IDS)
    def test_retirejs_bibliotheques_vulnerables(self, client, site):
        """RetireJS doit pouvoir remonter des bibliothèques JS vulnérables."""
        findings = [
            {
                "severity":    "HIGH",
                "title":       "Bibliothèque JS vulnérable : jquery v2.1.4",
                "description": "jQuery 2.1.4 est affecté par une vulnérabilité XSS.",
                "url":         site["url"],
                "cve_ids":     ["CVE-2019-11358"],
                "remediation": "Mettre à jour jQuery vers la version 3.6.0 ou supérieure.",
            },
        ]
        payload = {
            "started_at": "2026-03-21T13:00:00Z",
            "target_url": site["url"],
            "findings":   findings,
            "raw_output": [],
        }
        response = client.post(f"/results/retirejs/{site['name']}", json=payload)
        assert response.status_code == 202
        assert response.json()["accepted"] == 1

    @pytest.mark.parametrize("site", WEBSITES, ids=WEBSITE_IDS)
    def test_persistence_multiples_severites(self, client, site):
        """Toutes les sévérités doivent être persistées correctement."""
        findings = [make_finding(sev, site["name"])
                    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]]
        payload = build_payload(site, "nuclei", "2026-03-21T11:30:00Z", findings)
        response = client.post(f"/results/nuclei/{site['name']}", json=payload)
        assert response.status_code == 202
        assert response.json()["accepted"] == 5
