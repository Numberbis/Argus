"""Tests complémentaires — validation des outils et des cibles."""
import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docker/collector")))

os.environ.setdefault("DB_URL", "postgresql://audit:test@localhost:5432/audit_test")

from fastapi.testclient import TestClient


@pytest.fixture()
def client(mock_db):
    import main
    with TestClient(main.app) as c:
        yield c


class TestValidationOutils:
    OUTILS_VALIDES = ["zap", "nikto", "nmap", "testssl", "nuclei"]
    OUTILS_INVALIDES = ["burp", "sqlmap", "metasploit", "wfuzz", "dirbuster", ""]

    @pytest.mark.parametrize("outil", OUTILS_VALIDES)
    def test_outil_valide_accepte(self, client, sample_scan_result, mock_db, outil):
        response = client.post(f"/results/{outil}/buildweb", json=sample_scan_result)
        assert response.status_code == 202, f"L'outil '{outil}' devrait être accepté"

    @pytest.mark.parametrize("outil", OUTILS_INVALIDES)
    def test_outil_invalide_rejete(self, client, sample_scan_result, outil):
        if outil == "":
            # Chemin vide → 404 ou 405 selon FastAPI routing
            response = client.post("/results//buildweb", json=sample_scan_result)
            assert response.status_code in (404, 405, 422)
        else:
            response = client.post(f"/results/{outil}/buildweb", json=sample_scan_result)
            assert response.status_code == 400


class TestSeveritesFinding:
    """Vérification que les findings sont bien transmis avec tous les niveaux de sévérité."""

    @pytest.mark.parametrize("severity,cvss", [
        ("CRITICAL", 9.8),
        ("HIGH", 8.1),
        ("MEDIUM", 5.3),
        ("LOW", 2.7),
        ("INFO", None),
    ])
    def test_finding_par_severite(self, client, mock_db, severity, cvss):
        payload = {
            "started_at": "2026-03-21T02:00:00Z",
            "findings": [
                {
                    "severity": severity,
                    "title": f"Test finding {severity}",
                    "cvss_score": cvss,
                }
            ],
            "raw_output": {},
        }
        response = client.post("/results/zap/buildweb", json=payload)
        assert response.status_code == 202
        assert response.json()["accepted"] == 1


class TestCiblesMultiples:
    """Les noms de cibles peuvent contenir des tirets."""

    @pytest.mark.parametrize("target", [
        "buildweb",
        "tarifs-transporteurs",
        "yotalent",
        "mon-site-123",
    ])
    def test_cible_valide(self, client, sample_scan_result, mock_db, target):
        response = client.post(f"/results/zap/{target}", json=sample_scan_result)
        assert response.status_code == 202
