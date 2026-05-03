"""Génère un rapport HTML + PDF par site à partir des données en base."""
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

import psycopg2
import psycopg2.extras
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

DB_URL = os.environ["DB_URL"]
OUTPUT_DIR = Path(os.environ.get("REPORT_OUTPUT_DIR", "/reports"))
TEMPLATE_DIR = Path(__file__).parent / "templates"
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "24"))


def fetch_findings_by_target() -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT f.*, s.tool, s.target, s.target_url, s.started_at
                   FROM findings f
                   JOIN scans s ON s.id = f.scan_id
                   WHERE s.started_at >= %s
                   ORDER BY s.target, f.severity, f.title""",
                (since,),
            )
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    by_target: dict = {}
    for row in rows:
        target = row["target"]
        by_target.setdefault(target, []).append(row)
    return by_target


def generate_reports():
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    report_tmpl = env.get_template("report.html.j2")
    summary_tmpl = env.get_template("summary.html.j2")

    by_target = fetch_findings_by_target()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    all_findings = []
    for target, findings in by_target.items():
        all_findings.extend(findings)
        html_content = report_tmpl.render(
            target=target,
            findings=findings,
            generated_at=generated_at,
        )
        html_path = OUTPUT_DIR / f"{date_str}-{target}.html"
        pdf_path = OUTPUT_DIR / f"{date_str}-{target}.pdf"

        html_path.write_text(html_content)
        HTML(string=html_content).write_pdf(str(pdf_path))
        print(f"[Report] {target}: {len(findings)} findings → {pdf_path}")

    # Rapport de synthèse global
    summary_html = summary_tmpl.render(
        findings=all_findings,
        generated_at=generated_at,
    )
    summary_path = OUTPUT_DIR / f"{date_str}-summary.html"
    summary_pdf_path = OUTPUT_DIR / f"{date_str}-summary.pdf"
    summary_path.write_text(summary_html)
    HTML(string=summary_html).write_pdf(str(summary_pdf_path))
    print(f"[Report] Synthèse globale: {len(all_findings)} findings → {summary_pdf_path}")


if __name__ == "__main__":
    generate_reports()
