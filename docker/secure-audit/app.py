"""
Secure Audit (By Build Web) — Application web d'audit de sécurité
Authentification par session + audit asynchrone en thread.
Multi-utilisateur avec restrictions d'URL par compte.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask, Response, jsonify, redirect, render_template,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from audit_core import generate_report_html, run_audit

# ─── Application Flask ─────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")

# ─── Authentification multi-utilisateur ───────────────────────────────────────

USERS_FILE = Path(os.environ.get("USERS_FILE", "/app/data/users.json"))

# Compte de secours via variables d'environnement (utilisé si users.json absent)
_FALLBACK_USER: str = os.environ.get("AUDIT_USERNAME", "admin")
_FALLBACK_HASH: str = generate_password_hash(os.environ.get("AUDIT_PASSWORD", "changeme"))


def _init_users_from_env() -> None:
    """Crée users.json au premier démarrage si INITIAL_USERS est défini.

    Format INITIAL_USERS (JSON) :
    [
      {"username": "admin", "password": "MonPass"},
      {"username": "chez-meilan", "password": "MonPass",
       "allowed_urls": ["https://chez-meilan.fr"], "description": "Client Chez Meilan"}
    ]
    Sans allowed_urls (ou null) → accès illimité.
    """
    if USERS_FILE.exists():
        return  # déjà initialisé, on ne touche à rien

    initial_json = os.environ.get("INITIAL_USERS", "").strip()
    if not initial_json:
        return  # pas de variable définie, on utilisera le fallback

    try:
        users_list = json.loads(initial_json)
        users: dict = {}
        for u in users_list:
            username = u["username"]
            users[username] = {
                "password_hash": generate_password_hash(u["password"]),
                "allowed_urls":  u.get("allowed_urls"),
                "description":   u.get("description", ""),
            }
        USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        print(f"[init] {len(users)} utilisateur(s) initialisé(s) → {USERS_FILE}",
              flush=True)
    except Exception as exc:
        print(f"[init] Erreur INITIAL_USERS : {exc}", file=sys.stderr, flush=True)


_init_users_from_env()


def _load_users() -> dict:
    """Charge les utilisateurs depuis users.json, ou retourne le compte de secours."""
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    # Fallback : compte unique défini par variables d'environnement
    return {
        _FALLBACK_USER: {
            "password_hash": _FALLBACK_HASH,
            "allowed_urls":  None,
        }
    }


def _url_allowed(url: str, allowed_urls: list[str] | None) -> bool:
    """Vérifie que l'URL soumise est autorisée pour cet utilisateur."""
    if allowed_urls is None:
        return True  # accès illimité
    hostname = urlparse(url).hostname or ""
    for allowed in allowed_urls:
        if urlparse(allowed).hostname == hostname:
            return True
    return False


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ─── Gestion des jobs ──────────────────────────────────────────────────────────

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _audit_worker(job_id: str, url: str, name: str, skip_obs: bool) -> None:
    def on_progress(msg: str) -> None:
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id]["progress"] = msg

    with _jobs_lock:
        _jobs[job_id]["status"] = "running"

    try:
        result = run_audit(
            {"name": name, "url": url},
            skip_observatory=skip_obs,
            progress_cb=on_progress,
        )
        html = generate_report_html([result])

        with _jobs_lock:
            _jobs[job_id].update({
                "status":      "done",
                "result":      result,
                "html":        html,
                "progress":    "Audit terminé",
                "finished_at": datetime.now(timezone.utc).isoformat(),
            })
    except Exception as exc:
        with _jobs_lock:
            _jobs[job_id].update({
                "status":      "error",
                "error":       str(exc),
                "progress":    f"Erreur : {exc}",
                "finished_at": datetime.now(timezone.utc).isoformat(),
            })


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        users    = _load_users()
        user     = users.get(username)
        if user and check_password_hash(user["password_hash"], password):
            session["logged_in"]    = True
            session["username"]     = username
            session["allowed_urls"] = user.get("allowed_urls")  # None = illimité
            return redirect(url_for("index"))
        error = "Identifiants incorrects."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    with _jobs_lock:
        username = session.get("username")
        recent = sorted(
            (j for j in _jobs.values() if j.get("owner") == username),
            key=lambda j: j["created_at"],
            reverse=True,
        )[:20]
    return render_template(
        "index.html",
        jobs=recent,
        allowed_urls=session.get("allowed_urls"),
    )


@app.route("/audit", methods=["POST"])
@login_required
def start_audit():
    url = request.form.get("url", "").strip()
    if not url:
        return redirect(url_for("index"))

    # Normalisation de l'URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.hostname:
        return redirect(url_for("index"))

    # Vérification de la restriction d'URL
    allowed_urls = session.get("allowed_urls")
    if not _url_allowed(url, allowed_urls):
        return render_template(
            "index.html",
            jobs=[],
            allowed_urls=allowed_urls,
            error=f"Accès refusé : votre compte n'est pas autorisé à auditer cette URL.",
        ), 403

    skip_obs = request.form.get("skip_observatory") == "1"
    name     = parsed.hostname

    job_id = str(uuid.uuid4())[:8]
    with _jobs_lock:
        _jobs[job_id] = {
            "id":          job_id,
            "url":         url,
            "name":        name,
            "owner":       session.get("username"),
            "status":      "pending",
            "progress":    "En attente de démarrage...",
            "created_at":  datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "result":      None,
            "html":        None,
            "error":       None,
        }

    threading.Thread(
        target=_audit_worker,
        args=(job_id, url, name, skip_obs),
        daemon=True,
    ).start()

    return redirect(url_for("job_page", job_id=job_id))


@app.route("/job/<job_id>")
@login_required
def job_page(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return render_template("404.html"), 404
    return render_template("job.html", job=job)


@app.route("/job/<job_id>/status")
@login_required
def job_status(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job:
        return jsonify({"error": "introuvable"}), 404
    result = job.get("result") or {}
    return jsonify({
        "status":   job["status"],
        "progress": job["progress"],
        "score":    result.get("score"),
        "grade":    result.get("grade"),
    })


@app.route("/job/<job_id>/report")
@login_required
def job_report(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job or not job.get("html"):
        return "Rapport non disponible", 404
    return Response(job["html"], content_type="text/html; charset=utf-8")


@app.route("/job/<job_id>/download")
@login_required
def job_download(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job or not job.get("html"):
        return "Rapport non disponible", 404
    name     = (job.get("name") or "audit").replace("/", "_")
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"audit-{name}-{date_str}.html"
    return Response(
        job["html"],
        content_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
