"""Tests unitaires pour les modèles Pydantic (models.py)."""
import sys
import os

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docker/collector")))

from models import Finding, ScanResult


class TestFinding:
    def test_finding_valide_complet(self):
        f = Finding(
            severity="HIGH",
            title="XSS réfléchi",
            description="Script injecté via paramètre GET",
            url="https://buildweb.fr/?q=<script>",
            cvss_score=7.4,
            cve_ids=["CVE-2023-9999"],
            remediation="Encoder les sorties HTML",
        )
        assert f.severity == "HIGH"
        assert f.cvss_score == 7.4
        assert f.cve_ids == ["CVE-2023-9999"]

    def test_finding_minimal(self):
        """Seuls severity et title sont obligatoires."""
        f = Finding(severity="LOW", title="En-tête X-Frame-Options manquant")
        assert f.description is None
        assert f.url is None
        assert f.cvss_score is None
        assert f.cve_ids == []
        assert f.remediation is None

    def test_finding_sans_title_leve_erreur(self):
        with pytest.raises(ValidationError):
            Finding(severity="HIGH")

    def test_finding_sans_severity_leve_erreur(self):
        with pytest.raises(ValidationError):
            Finding(title="Problème détecté")

    @pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    def test_severites_acceptees(self, severity):
        f = Finding(severity=severity, title="Test")
        assert f.severity == severity

    def test_cve_ids_liste_vide_par_defaut(self):
        f = Finding(severity="INFO", title="Test")
        assert isinstance(f.cve_ids, list)
        assert len(f.cve_ids) == 0

    def test_plusieurs_cve(self):
        f = Finding(
            severity="CRITICAL",
            title="Multiples CVE",
            cve_ids=["CVE-2023-1", "CVE-2023-2", "CVE-2023-3"],
        )
        assert len(f.cve_ids) == 3


class TestScanResult:
    def test_scan_result_valide(self):
        result = ScanResult(
            started_at="2026-03-21T02:00:00Z",
            findings=[
                Finding(severity="HIGH", title="SQL Injection")
            ],
            raw_output={"alerts": []},
        )
        assert len(result.findings) == 1
        assert result.findings[0].severity == "HIGH"

    def test_scan_result_sans_findings(self):
        result = ScanResult(
            started_at="2026-03-21T02:00:00Z",
            findings=[],
        )
        assert result.findings == []
        assert result.raw_output == {}

    def test_scan_result_raw_output_liste(self):
        """raw_output peut être une liste ou un dict."""
        result = ScanResult(
            started_at="2026-03-21T02:00:00Z",
            findings=[],
            raw_output=[{"key": "value"}],
        )
        assert isinstance(result.raw_output, list)

    def test_scan_result_sans_started_at_leve_erreur(self):
        with pytest.raises(ValidationError):
            ScanResult(findings=[])

    def test_scan_result_multiples_findings(self):
        findings = [
            Finding(severity="CRITICAL", title="Finding 1"),
            Finding(severity="HIGH", title="Finding 2"),
            Finding(severity="LOW", title="Finding 3"),
        ]
        result = ScanResult(started_at="2026-03-21T02:00:00Z", findings=findings)
        assert len(result.findings) == 3
