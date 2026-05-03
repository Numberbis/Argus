"""Notifier : envoie des alertes email + Slack pour les nouveaux findings non notifiés."""
import os
import smtplib
import json
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import psycopg2
import psycopg2.extras
import requests
from jinja2 import Environment, FileSystemLoader

DB_URL = os.environ["DB_URL"]
SLACK_TOKEN = os.environ.get("SLACK_TOKEN", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "audit@example.com")

IMMEDIATE_SEVERITIES = {"CRITICAL", "HIGH"}
TEMPLATE_DIR = Path(__file__).parent / "templates"


def fetch_pending_findings() -> list[dict]:
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """SELECT f.*, s.tool, s.target, s.target_url
                   FROM findings f
                   JOIN scans s ON s.id = f.scan_id
                   WHERE f.notified_at IS NULL
                     AND f.severity = ANY(%s)
                   ORDER BY s.target, f.severity
                   LIMIT 100""",
                (list(IMMEDIATE_SEVERITIES),),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def mark_notified(finding_ids: list[int]):
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE findings SET notified_at = NOW() WHERE id = ANY(%s)",
                (finding_ids,),
            )
        conn.commit()
    finally:
        conn.close()


def send_slack(channel: str, message: str):
    if not SLACK_TOKEN:
        return
    requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {SLACK_TOKEN}"},
        json={"channel": channel, "text": message},
        timeout=10,
    )


def send_email(to: str, subject: str, html_body: str):
    if not SMTP_HOST:
        return
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to
    msg.attach(MIMEText(html_body, "html"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, to, msg.as_string())


def notify():
    findings = fetch_pending_findings()
    if not findings:
        print("[Notifier] Aucun finding en attente.")
        return

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    email_tmpl = env.get_template("email.html.j2")

    # Grouper par target
    by_target: dict = {}
    for f in findings:
        by_target.setdefault(f["target"], []).append(f)

    notified_ids = []
    for target, target_findings in by_target.items():
        count = len(target_findings)
        critical_count = sum(1 for f in target_findings if f["severity"] == "CRITICAL")
        subject = f"[AUDIT] {count} finding(s) sur {target} ({critical_count} CRITICAL)"

        html_body = email_tmpl.render(
            target=target,
            findings=target_findings,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

        # Récupération de l'email et du canal Slack depuis les findings
        notify_email = os.environ.get(f"NOTIFY_EMAIL_{target.upper().replace('-', '_')}", "")
        slack_channel = os.environ.get(f"SLACK_CHANNEL_{target.upper().replace('-', '_')}", "#security-alerts")

        slack_msg = f":warning: *{subject}*\n" + "\n".join(
            f"• `{f['severity']}` {f['title']}" for f in target_findings[:10]
        )
        if len(target_findings) > 10:
            slack_msg += f"\n_...et {len(target_findings) - 10} autres_"

        send_slack(slack_channel, slack_msg)
        if notify_email:
            send_email(notify_email, subject, html_body)

        notified_ids.extend(f["id"] for f in target_findings)
        print(f"[Notifier] {target}: {count} alertes envoyées.")

    mark_notified(notified_ids)


if __name__ == "__main__":
    notify()
