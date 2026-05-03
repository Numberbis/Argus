"""Argus Dashboard — visualisation des audits et interface IA (triage, remédiation, chat)."""
import os
import functools
import logging

import httpx
import markdown as md_lib
from flask import Flask, render_template, abort, request, Response, jsonify
import psycopg2
import psycopg2.extras


logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("argus.dashboard")

app = Flask(__name__)
DB_URL = os.environ["DB_URL"]
AGENT_URL = os.environ.get("AGENT_URL", "").strip().rstrip("/")
AGENT_AVAILABLE = bool(AGENT_URL)

# ── Authentification HTTP Basic (optionnelle) ────────────────────────────────
_DASH_USER = os.environ.get("DASHBOARD_USER", "")
_DASH_PASS = os.environ.get("DASHBOARD_PASSWORD", "")
_AUTH_ENABLED = bool(_DASH_USER and _DASH_PASS)


def _unauthorized():
    return Response(
        "Accès refusé — identifiants requis.",
        401,
        {"WWW-Authenticate": 'Basic realm="Argus"'},
    )


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not _AUTH_ENABLED:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or auth.username != _DASH_USER or auth.password != _DASH_PASS:
            return _unauthorized()
        return f(*args, **kwargs)
    return decorated


def query(sql: str, params=()) -> list[dict]:
    conn = psycopg2.connect(DB_URL)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


@app.context_processor
def inject_globals():
    return {"agent_available": AGENT_AVAILABLE}


# ── Vue principale (raw) ─────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    sites = query(
        """SELECT s.target,
                  COUNT(DISTINCT s.id)                              AS total_scans,
                  MAX(s.finished_at)                                AS last_scan,
                  COUNT(f.id)                                        AS raw_findings,
                  COUNT(f.id) FILTER (
                      WHERE f.ai_is_false_positive = FALSE
                        AND f.ai_dedup_of IS NULL
                        AND f.ai_triaged_at IS NOT NULL
                  )                                                  AS real_issues,
                  COUNT(f.id) FILTER (
                      WHERE COALESCE(f.ai_severity, f.severity) = 'CRITICAL'
                        AND f.ai_is_false_positive = FALSE
                        AND f.ai_dedup_of IS NULL
                  )                                                  AS critical,
                  COUNT(f.id) FILTER (
                      WHERE COALESCE(f.ai_severity, f.severity) = 'HIGH'
                        AND f.ai_is_false_positive = FALSE
                        AND f.ai_dedup_of IS NULL
                  )                                                  AS high
           FROM scans s
           LEFT JOIN findings f ON f.scan_id = s.id
           GROUP BY s.target
           ORDER BY critical DESC, high DESC, s.target"""
    )
    return render_template("index.html", sites=sites)


@app.route("/site/<target>")
@login_required
def site(target: str):
    scans = query(
        """SELECT s.id, s.tool, s.started_at, s.finished_at, s.status,
                  COUNT(f.id) AS total_findings,
                  COUNT(f.id) FILTER (WHERE f.severity = 'CRITICAL') AS critical,
                  COUNT(f.id) FILTER (WHERE f.severity = 'HIGH')     AS high,
                  COUNT(f.id) FILTER (WHERE f.ai_triaged_at IS NOT NULL) AS triaged
           FROM scans s
           LEFT JOIN findings f ON f.scan_id = s.id
           WHERE s.target = %s
           GROUP BY s.id
           ORDER BY s.started_at DESC
           LIMIT 50""",
        (target,),
    )
    if not scans:
        abort(404)
    return render_template("site.html", target=target, scans=scans)


@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id: int):
    findings = query(
        """SELECT f.*, s.tool, s.target, s.target_url
           FROM findings f
           JOIN scans s ON s.id = f.scan_id
           WHERE f.scan_id = %s
           ORDER BY f.severity, f.title""",
        (scan_id,),
    )
    if not findings:
        abort(404)
    return render_template("finding.html", scan_id=scan_id, findings=findings)


# ── Vue "Real Issues" (post-triage IA) ───────────────────────────────────────
@app.route("/real-issues")
@login_required
def real_issues():
    target = request.args.get("target")
    where = "f.ai_is_false_positive = FALSE AND f.ai_dedup_of IS NULL AND f.ai_triaged_at IS NOT NULL"
    params: list = []
    if target:
        where += " AND s.target = %s"
        params.append(target)

    issues = query(
        f"""SELECT f.id, f.title, f.url, f.severity AS raw_severity,
                   COALESCE(f.ai_severity, f.severity) AS severity,
                   f.cvss_score, f.cve_ids, f.ai_confidence,
                   f.ai_root_cause_id, f.ai_remediation,
                   s.tool, s.target, s.target_url, s.started_at
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE {where}
            ORDER BY
              CASE COALESCE(f.ai_severity, f.severity)
                WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4 WHEN 'INFO' THEN 5 ELSE 6
              END,
              f.cvss_score DESC NULLS LAST,
              s.started_at DESC
            LIMIT 500""",
        tuple(params),
    )

    root_causes = query(
        """SELECT rc.id, rc.target, rc.summary, rc.severity, rc.suggested_fix, rc.finding_count,
                  rc.created_at
           FROM root_causes rc
           WHERE rc.finding_count > 0
             AND (%s::text IS NULL OR rc.target = %s)
           ORDER BY
             CASE rc.severity
               WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3
               WHEN 'LOW' THEN 4 WHEN 'INFO' THEN 5 ELSE 6
             END,
             rc.finding_count DESC""",
        (target, target),
    )

    stats = query(
        f"""SELECT
              COUNT(f.id)                                        AS total_real,
              COUNT(f.id) FILTER (WHERE COALESCE(f.ai_severity, f.severity) = 'CRITICAL') AS critical,
              COUNT(f.id) FILTER (WHERE COALESCE(f.ai_severity, f.severity) = 'HIGH')     AS high,
              COUNT(f.id) FILTER (WHERE COALESCE(f.ai_severity, f.severity) = 'MEDIUM')   AS medium,
              (SELECT COUNT(*) FROM findings ff JOIN scans ss ON ss.id = ff.scan_id
                 WHERE ff.ai_is_false_positive = TRUE
                   AND (%s::text IS NULL OR ss.target = %s))     AS false_positives,
              (SELECT COUNT(*) FROM findings ff JOIN scans ss ON ss.id = ff.scan_id
                 WHERE ff.ai_dedup_of IS NOT NULL
                   AND (%s::text IS NULL OR ss.target = %s))     AS duplicates
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE {where}""",
        (target, target, target, target, *params),
    )

    return render_template(
        "real_issues.html",
        issues=issues,
        root_causes=root_causes,
        stats=stats[0] if stats else {},
        target=target,
    )


# ── Chat ─────────────────────────────────────────────────────────────────────
@app.route("/chat")
@login_required
def chat_page():
    if not AGENT_AVAILABLE:
        return render_template("chat_disabled.html")
    return render_template("chat.html")


@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    if not AGENT_AVAILABLE:
        return jsonify({"error": "Agent IA non configuré"}), 503
    payload = {
        "question": (request.json or {}).get("question", "").strip(),
        "context_target": (request.json or {}).get("context_target"),
    }
    if not payload["question"]:
        return jsonify({"error": "question manquante"}), 400
    try:
        with httpx.Client(timeout=120) as client:
            r = client.post(f"{AGENT_URL}/chat", json=payload)
            r.raise_for_status()
            data = r.json()
            data["answer_html"] = md_lib.markdown(data.get("answer", ""), extensions=["fenced_code", "tables"])
            return jsonify(data)
    except httpx.HTTPStatusError as e:
        return jsonify({"error": f"agent: {e.response.text}"}), e.response.status_code
    except Exception as e:
        log.exception("Chat proxy error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/remediate/<int:finding_id>", methods=["POST"])
@login_required
def api_remediate(finding_id: int):
    if not AGENT_AVAILABLE:
        return jsonify({"error": "Agent IA non configuré"}), 503
    try:
        with httpx.Client(timeout=120) as client:
            r = client.post(f"{AGENT_URL}/remediate", json={"finding_id": finding_id})
            r.raise_for_status()
            data = r.json()
            data["remediation_html"] = md_lib.markdown(
                data.get("remediation", ""), extensions=["fenced_code", "tables"]
            )
            return jsonify(data)
    except httpx.HTTPStatusError as e:
        return jsonify({"error": f"agent: {e.response.text}"}), e.response.status_code
    except Exception as e:
        log.exception("Remediate proxy error")
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return {"status": "ok", "agent": AGENT_AVAILABLE}
