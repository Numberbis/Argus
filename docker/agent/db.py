from __future__ import annotations
import os
from contextlib import contextmanager

import psycopg2
import psycopg2.extras


DB_URL = os.environ["DB_URL"]


@contextmanager
def get_conn():
    conn = psycopg2.connect(DB_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def fetch_scan_with_findings(scan_id: int) -> dict | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, tool, target, target_url, started_at, status FROM scans WHERE id = %s",
                (scan_id,),
            )
            scan = cur.fetchone()
            if not scan:
                return None
            cur.execute(
                """SELECT id, severity, title, description, url, cvss_score, cve_ids, remediation
                   FROM findings WHERE scan_id = %s ORDER BY severity, id""",
                (scan_id,),
            )
            findings = [dict(r) for r in cur.fetchall()]
            return {**dict(scan), "findings": findings}


def fetch_finding(finding_id: int) -> dict | None:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT f.*, s.tool, s.target, s.target_url
                   FROM findings f JOIN scans s ON f.scan_id = s.id
                   WHERE f.id = %s""",
                (finding_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None


def upsert_root_cause(target: str, summary: str, severity: str, suggested_fix: str | None,
                      finding_count: int) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO root_causes (target, summary, severity, suggested_fix, finding_count)
                   VALUES (%s, %s, %s, %s, %s) RETURNING id""",
                (target, summary, severity, suggested_fix, finding_count),
            )
            return cur.fetchone()[0]


def apply_triage(triaged: list[dict]) -> None:
    """Met à jour les findings avec les enrichissements IA.

    triaged: liste de dicts {id, ai_severity, ai_is_false_positive, ai_root_cause_id,
             ai_dedup_of, ai_confidence}
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            for t in triaged:
                cur.execute(
                    """UPDATE findings SET
                         ai_severity          = %s,
                         ai_is_false_positive = %s,
                         ai_root_cause_id     = %s,
                         ai_dedup_of          = %s,
                         ai_confidence        = %s,
                         ai_triaged_at        = NOW()
                       WHERE id = %s""",
                    (
                        t.get("ai_severity"),
                        t.get("ai_is_false_positive", False),
                        t.get("ai_root_cause_id"),
                        t.get("ai_dedup_of"),
                        t.get("ai_confidence"),
                        t["id"],
                    ),
                )


def set_remediation(finding_id: int, remediation: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE findings SET ai_remediation = %s WHERE id = %s",
                (remediation, finding_id),
            )


def log_run(run_type: str, scan_id: int | None, target: str | None, provider: str, model: str,
            input_tokens: int, output_tokens: int, cost_usd: float, duration_ms: int,
            status: str, error: str | None = None) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO agent_runs
                   (run_type, scan_id, target, provider, model, input_tokens, output_tokens,
                    cost_usd, duration_ms, status, error)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (run_type, scan_id, target, provider, model, input_tokens, output_tokens,
                 cost_usd, duration_ms, status, error),
            )


def today_spend_usd() -> float:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT COALESCE(SUM(cost_usd), 0)
                   FROM agent_runs
                   WHERE created_at >= CURRENT_DATE AND status = 'success'"""
            )
            return float(cur.fetchone()[0])


# --- read-only SQL pour le chat (avec garde-fous) ---

ALLOWED_TABLES = {"scans", "findings", "root_causes", "reports", "agent_runs"}


def safe_select(query: str, row_limit: int) -> list[dict]:
    """Exécute une requête SELECT avec garde-fous : pas de DML, limite de lignes, transaction read-only."""
    q = query.strip().rstrip(";")
    lower = q.lower()
    if not lower.startswith("select"):
        raise ValueError("Seules les requêtes SELECT sont autorisées")
    forbidden = ("insert", "update", "delete", "drop", "alter", "truncate", "grant",
                 "revoke", "create", "copy", " into ", "pg_", "current_setting", ";--")
    for kw in forbidden:
        if kw in lower:
            raise ValueError(f"Mot-clé interdit dans la requête : {kw.strip()}")
    if "limit" not in lower:
        q = f"{q} LIMIT {row_limit}"
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(f"SET statement_timeout = '5s'")
            cur.execute(q)
            return [dict(r) for r in cur.fetchall()]
