"""Hook vers le service Agent IA : déclenche le triage après chaque scan finalisé.

Désactivé silencieusement si AGENT_URL n'est pas défini — Argus marche très bien sans
agent IA, mais perd alors la fonctionnalité de tri/dédoublonnage automatique.
"""
from __future__ import annotations
import logging
import os

import httpx

log = logging.getLogger(__name__)

AGENT_URL = os.environ.get("AGENT_URL", "").strip().rstrip("/")
TRIAGE_ENABLED = os.environ.get("AGENT_TRIAGE_ENABLED", "true").lower() == "true"
TIMEOUT_SECONDS = float(os.environ.get("AGENT_TIMEOUT_SECONDS", "60"))


def trigger_triage(scan_id: int) -> None:
    """Appelle /triage du service agent. Best-effort : échec silencieux si l'agent est down."""
    if not AGENT_URL or not TRIAGE_ENABLED:
        return
    try:
        with httpx.Client(timeout=TIMEOUT_SECONDS) as client:
            r = client.post(f"{AGENT_URL}/triage", json={"scan_id": scan_id})
            if r.status_code == 429:
                log.info("Triage scan_id=%s : budget LLM journalier atteint", scan_id)
                return
            r.raise_for_status()
            data = r.json()
            log.info(
                "Triage scan_id=%s : %d findings → %d real issues, %d FP, %d dup, $%.4f",
                scan_id,
                data.get("findings_count", 0),
                data.get("real_issues_count", 0),
                data.get("false_positives_count", 0),
                data.get("duplicates_count", 0),
                data.get("cost_usd", 0.0),
            )
    except httpx.HTTPError as e:
        log.warning("Triage scan_id=%s échoué (agent indisponible ?) : %s", scan_id, e)
    except Exception:
        log.exception("Triage scan_id=%s : erreur inattendue", scan_id)
