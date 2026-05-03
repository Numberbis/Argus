"""Tests unitaires des fonctions de base de données (db.py) avec psycopg2 mocké."""
import sys
import os
from unittest.mock import MagicMock, patch, call
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docker/collector")))

os.environ.setdefault("DB_URL", "postgresql://audit:test@localhost:5432/audit_test")

from models import Finding


class TestSaveScan:
    @patch("db.psycopg2.connect")
    def test_save_scan_retourne_un_id(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value.__enter__ = MagicMock(return_value=mock_conn)
        mock_connect.return_value.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_cursor.fetchone.return_value = (99,)

        import db
        with patch("db.psycopg2.connect") as mock_c:
            mock_c.return_value = mock_conn
            mock_conn.__enter__ = lambda s: mock_conn
            mock_conn.__exit__ = MagicMock(return_value=False)
            mock_conn.cursor.return_value.__enter__ = lambda s: mock_cursor
            mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
            mock_cursor.fetchone.return_value = (99,)

            scan_id = db.save_scan(
                tool="zap",
                target="buildweb",
                target_url="https://buildweb.fr",
                started_at="2026-03-21T02:00:00Z",
                raw_output={"alerts": []},
            )
            assert scan_id == 99

    @patch("db.psycopg2.connect")
    def test_save_scan_execute_insert(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = (1,)
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value.__enter__ = lambda s: mock_cursor
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_conn

        import db
        db.save_scan(
            tool="nikto",
            target="yotalent",
            target_url="https://yotalent.example.com",
            started_at="2026-03-21T03:00:00Z",
            raw_output={},
        )
        mock_cursor.execute.assert_called_once()
        sql_call = mock_cursor.execute.call_args[0][0]
        assert "INSERT INTO scans" in sql_call


class TestSaveFindings:
    @patch("db.psycopg2.connect")
    def test_save_findings_insere_chaque_finding(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value.__enter__ = lambda s: mock_cursor
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_conn

        findings = [
            Finding(severity="HIGH", title="SQL Injection"),
            Finding(severity="MEDIUM", title="XSS"),
        ]

        import db
        db.save_findings(scan_id=1, findings=findings)

        # 2 INSERT findings + 1 UPDATE status
        assert mock_cursor.execute.call_count == 3

    @patch("db.psycopg2.connect")
    def test_save_findings_vide_met_a_jour_status(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value.__enter__ = lambda s: mock_cursor
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_conn

        import db
        db.save_findings(scan_id=5, findings=[])

        # Seulement le UPDATE status, aucun INSERT finding
        assert mock_cursor.execute.call_count == 1
        sql_call = mock_cursor.execute.call_args[0][0]
        assert "UPDATE scans" in sql_call
        assert "completed" in sql_call


class TestListScans:
    @patch("db.psycopg2.connect")
    def test_list_scans_sans_filtre(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_conn

        # Simuler cursor avec RealDictCursor
        mock_conn.cursor.return_value.__enter__ = lambda s: mock_cursor
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)

        import db
        result = db.list_scans()
        assert isinstance(result, list)

    @patch("db.psycopg2.connect")
    def test_list_scans_avec_target(self, mock_connect):
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn.__enter__ = lambda s: mock_conn
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.cursor.return_value.__enter__ = lambda s: mock_cursor
        mock_conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
        mock_connect.return_value = mock_conn

        import db
        db.list_scans(target="buildweb")
        sql_call = mock_cursor.execute.call_args[0][0]
        assert "WHERE target" in sql_call
