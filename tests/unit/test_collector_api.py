"""Tests unitaires de l'API FastAPI (main.py) avec base de données mockée."""
import sys
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Ajout du chemin collector
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docker/collector")))


# Mock de la variable d'environnement DB_URL avant l'import de main
os.environ.setdefault("DB_URL", "postgresql://audit:test@localhost:5432/audit_test")


@pytest.fixture()
def client(mock_db):
    """Client de test FastAPI avec db mocké."""
    import main
    with TestClient(main.app) as c:
        yield c


class TestHealthEndpoint:
    def test_health_retourne_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestReceiveResult:
    def test_reception_valide_zap(self, client, sample_scan_result, mock_db):
        response = client.post(
            "/results/zap/buildweb",
            json=sample_scan_result,
        )
        assert response.status_code == 202
        data = response.json()
        assert data["scan_id"] == 42
        assert data["accepted"] == 1
        mock_db.save_scan.assert_called_once()

    def test_reception_valide_nikto(self, client, sample_scan_result, mock_db):
        response = client.post(
            "/results/nikto/tarifs-transporteurs",
            json=sample_scan_result,
        )
        assert response.status_code == 202

    @pytest.mark.parametrize("tool", ["zap", "nikto", "nmap", "testssl", "nuclei"])
    def test_tous_les_outils_acceptes(self, client, sample_scan_result, mock_db, tool):
        response = client.post(
            f"/results/{tool}/buildweb",
            json=sample_scan_result,
        )
        assert response.status_code == 202

    def test_outil_inconnu_retourne_400(self, client, sample_scan_result):
        response = client.post(
            "/results/burpsuite/buildweb",
            json=sample_scan_result,
        )
        assert response.status_code == 400
        assert "inconnu" in response.json()["detail"].lower()

    def test_scan_sans_findings(self, client, sample_scan_result_no_findings, mock_db):
        response = client.post(
            "/results/zap/buildweb",
            json=sample_scan_result_no_findings,
        )
        assert response.status_code == 202
        assert response.json()["accepted"] == 0

    def test_payload_invalide_retourne_422(self, client):
        """Un payload sans 'started_at' doit être rejeté."""
        response = client.post(
            "/results/zap/buildweb",
            json={"findings": []},
        )
        assert response.status_code == 422

    def test_payload_vide_retourne_422(self, client):
        response = client.post("/results/zap/buildweb", json={})
        assert response.status_code == 422

    def test_save_scan_appele_avec_bons_arguments(self, client, sample_scan_result, mock_db):
        client.post("/results/zap/buildweb", json=sample_scan_result)
        call_kwargs = mock_db.save_scan.call_args
        assert call_kwargs.kwargs["tool"] == "zap" or call_kwargs.args[0] == "zap"

    def test_target_url_extraite_du_premier_finding(self, client, sample_scan_result, mock_db):
        client.post("/results/zap/buildweb", json=sample_scan_result)
        call = mock_db.save_scan.call_args
        # L'URL doit correspondre au premier finding
        args = call.kwargs if call.kwargs else {}
        target_url = args.get("target_url", call.args[2] if len(call.args) > 2 else None)
        assert target_url == "https://buildweb.fr/login"


class TestListScans:
    def test_list_scans_retourne_liste(self, client, mock_db):
        response = client.get("/scans")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_list_scans_filtrage_par_target(self, client, mock_db):
        response = client.get("/scans?target=buildweb")
        assert response.status_code == 200
        mock_db.list_scans.assert_called_with(target="buildweb", limit=50)

    def test_list_scans_limite_personnalisee(self, client, mock_db):
        response = client.get("/scans?limit=10")
        assert response.status_code == 200
        mock_db.list_scans.assert_called_with(target=None, limit=10)

    def test_list_scans_sans_filtre(self, client, mock_db):
        response = client.get("/scans")
        mock_db.list_scans.assert_called_with(target=None, limit=50)

    def test_list_scans_structure_reponse(self, client, mock_db):
        response = client.get("/scans")
        data = response.json()
        assert len(data) == 1
        scan = data[0]
        assert "id" in scan
        assert "tool" in scan
        assert "target" in scan
        assert "status" in scan
