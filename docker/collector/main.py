"""Collector FastAPI — seul composant qui écrit en base de données."""
from __future__ import annotations

import threading

from fastapi import FastAPI, HTTPException, Response
from models import ScanResult
import db
from agent_hook import trigger_triage
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI(title="Security Audit Collector")

# ── Métriques Prometheus ──────────────────────────────────────────────────────
scans_total = Counter(
    "audit_scans_total",
    "Nombre total de scans reçus",
    ["tool", "target"],
)
findings_total = Counter(
    "audit_findings_total",
    "Nombre total de findings reçus",
    ["tool", "severity"],
)
scan_duration = Histogram(
    "audit_scan_findings_count",
    "Distribution du nombre de findings par scan",
    ["tool"],
    buckets=[0, 1, 5, 10, 25, 50, 100, 250, 500],
)
active_scans = Gauge(
    "audit_active_scans",
    "Scans en cours (status=running)",
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics")
def metrics():
    """Endpoint Prometheus — expose les métriques au format text/plain."""
    # Mise à jour du gauge en temps réel
    try:
        running = db.count_running_scans()
        active_scans.set(running)
    except Exception:
        pass
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/results/{tool}/{target}", status_code=202)
def receive_result(tool: str, target: str, result: ScanResult):
    """Reçoit les résultats d'un scanner et les persiste en base."""
    allowed_tools = {
        "zap", "nikto", "nmap", "testssl", "nuclei",
        "observatory", "retirejs", "wpscan", "trivy",
    }
    if tool not in allowed_tools:
        raise HTTPException(status_code=400, detail=f"Outil inconnu: {tool}")

    # URL cible : champ explicite du payload, sinon premier finding, sinon chaîne vide
    target_url = result.target_url or (result.findings[0].url if result.findings else None) or ""
    scan_id = db.save_scan(
        tool=tool,
        target=target,
        target_url=target_url,
        started_at=result.started_at,
        raw_output=result.raw_output,
    )

    # Métriques
    scans_total.labels(tool=tool, target=target).inc()
    scan_duration.labels(tool=tool).observe(len(result.findings))
    for f in result.findings:
        findings_total.labels(tool=tool, severity=f.severity).inc()

    # Persistance des findings + déclenchement triage IA en arrière-plan
    def _persist_and_triage():
        db.save_findings(scan_id, result.findings)
        trigger_triage(scan_id)

    thread = threading.Thread(target=_persist_and_triage, daemon=True)
    thread.start()

    return {"scan_id": scan_id, "accepted": len(result.findings)}


@app.get("/scans")
def list_scans(target: str | None = None, limit: int = 50):
    return db.list_scans(target=target, limit=limit)
