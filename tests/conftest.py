"""Configuration partagée pour tous les tests pytest."""
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

# Ajout du chemin collector au sys.path pour les imports
COLLECTOR_PATH = os.path.join(
    os.path.dirname(__file__), "..", "docker", "collector"
)
sys.path.insert(0, os.path.abspath(COLLECTOR_PATH))


# ---------------------------------------------------------------------------
# Fixtures partagées
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_finding():
    """Un finding de sécurité valide."""
    return {
        "severity": "HIGH",
        "title": "SQL Injection détectée",
        "description": "Paramètre vulnérable à l'injection SQL",
        "url": "https://buildweb.fr/login",
        "cvss_score": 8.5,
        "cve_ids": ["CVE-2023-1234"],
        "remediation": "Utiliser des requêtes paramétrées",
    }


@pytest.fixture()
def sample_scan_result(sample_finding):
    """Un ScanResult complet avec un finding."""
    return {
        "started_at": "2026-03-21T02:00:00Z",
        "target_url": "https://buildweb.fr",
        "findings": [sample_finding],
        "raw_output": {"alerts": [{"risk": "High", "name": "SQL Injection"}]},
    }


@pytest.fixture()
def sample_scan_result_no_findings():
    """Un ScanResult sans finding."""
    return {
        "started_at": "2026-03-21T02:00:00Z",
        "target_url": "https://buildweb.fr",
        "findings": [],
        "raw_output": {"alerts": []},
    }


@pytest.fixture()
def mock_db(monkeypatch):
    """Mock complet du module db pour les tests unitaires."""
    mock = MagicMock()
    mock.save_scan.return_value = 42
    mock.save_findings.return_value = None
    mock.list_scans.return_value = [
        {
            "id": 1,
            "tool": "zap",
            "target": "buildweb",
            "started_at": "2026-03-21T02:00:00Z",
            "finished_at": "2026-03-21T04:00:00Z",
            "status": "completed",
        }
    ]
    monkeypatch.setattr("main.db", mock)
    return mock
