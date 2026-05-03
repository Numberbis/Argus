import os
import psycopg2
import psycopg2.extras
from contextlib import contextmanager
from models import Finding

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


def save_scan(tool: str, target: str, target_url: str, started_at: str, raw_output) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO scans (tool, target, target_url, started_at, status, raw_output)
                   VALUES (%s, %s, %s, %s, 'running', %s) RETURNING id""",
                (tool, target, target_url, started_at, psycopg2.extras.Json(raw_output)),
            )
            return cur.fetchone()[0]


def save_findings(scan_id: int, findings: list[Finding]):
    with get_conn() as conn:
        with conn.cursor() as cur:
            for f in findings:
                cur.execute(
                    """INSERT INTO findings
                       (scan_id, severity, title, description, url, cvss_score, cve_ids, remediation)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (scan_id, f.severity, f.title, f.description, f.url,
                     f.cvss_score, f.cve_ids, f.remediation),
                )
            cur.execute(
                "UPDATE scans SET status='completed', finished_at=NOW() WHERE id=%s",
                (scan_id,),
            )


def count_running_scans() -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM scans WHERE status = 'running'")
            return cur.fetchone()[0]


def list_scans(target: str | None = None, limit: int = 50) -> list[dict]:
    query = "SELECT id, tool, target, started_at, finished_at, status FROM scans"
    params: list = []
    if target:
        query += " WHERE target = %s"
        params.append(target)
    query += " ORDER BY started_at DESC LIMIT %s"
    params.append(limit)
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]
