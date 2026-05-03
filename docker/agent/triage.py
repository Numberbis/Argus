from __future__ import annotations
import logging

from config import Config
from llm import LLMClient
from prompts.triage import SYSTEM_PROMPT, build_user_prompt
import db

log = logging.getLogger(__name__)


def run_triage(cfg: Config, llm: LLMClient, scan_id: int) -> dict:
    scan = db.fetch_scan_with_findings(scan_id)
    if not scan:
        raise ValueError(f"scan_id {scan_id} introuvable")

    findings = scan.get("findings", [])
    if not findings:
        return {
            "scan_id": scan_id, "findings_count": 0, "real_issues_count": 0,
            "false_positives_count": 0, "duplicates_count": 0, "root_causes_count": 0,
            "cost_usd": 0.0, "duration_ms": 0,
        }

    # Tronque si trop de findings (limite tokens + coût)
    if len(findings) > cfg.triage_max_findings:
        log.warning("Scan %s : %d findings, tronqué à %d", scan_id, len(findings),
                    cfg.triage_max_findings)
        scan["findings"] = findings[: cfg.triage_max_findings]

    user_prompt = build_user_prompt(scan)
    resp = llm.call(SYSTEM_PROMPT, user_prompt, json_mode=True)

    try:
        data = resp.parse_json()
    except Exception as e:
        log.exception("Réponse LLM non-JSON pour scan %s", scan_id)
        db.log_run("triage", scan_id, scan.get("target"), llm.provider, llm.model,
                   resp.input_tokens, resp.output_tokens, resp.cost_usd, resp.duration_ms,
                   "failed", error=str(e))
        raise

    # Crée les root_causes en DB et résout les refs
    ref_to_id: dict[str, int] = {}
    for rc in data.get("root_causes", []):
        rc_id = db.upsert_root_cause(
            target=scan["target"],
            summary=rc["summary"],
            severity=rc.get("severity", "MEDIUM"),
            suggested_fix=rc.get("suggested_fix"),
            finding_count=0,  # mis à jour après application
        )
        ref_to_id[rc["ref"]] = rc_id

    triaged = []
    rc_counts: dict[int, int] = {}
    fp_count = 0
    dup_count = 0

    for f in data.get("findings", []):
        rc_ref = f.get("root_cause_ref")
        rc_id = ref_to_id.get(rc_ref) if rc_ref else None
        if rc_id is not None:
            rc_counts[rc_id] = rc_counts.get(rc_id, 0) + 1
        if f.get("is_false_positive"):
            fp_count += 1
        if f.get("dedup_of"):
            dup_count += 1
        triaged.append({
            "id": f["id"],
            "ai_severity": f.get("severity"),
            "ai_is_false_positive": bool(f.get("is_false_positive", False)),
            "ai_root_cause_id": rc_id,
            "ai_dedup_of": f.get("dedup_of"),
            "ai_confidence": f.get("confidence"),
        })

    db.apply_triage(triaged)

    # Met à jour les compteurs des root_causes
    if rc_counts:
        with db.get_conn() as conn:
            with conn.cursor() as cur:
                for rc_id, count in rc_counts.items():
                    cur.execute("UPDATE root_causes SET finding_count = %s WHERE id = %s",
                                (count, rc_id))

    db.log_run("triage", scan_id, scan.get("target"), llm.provider, llm.model,
               resp.input_tokens, resp.output_tokens, resp.cost_usd, resp.duration_ms, "success")

    real = sum(1 for t in triaged if not t["ai_is_false_positive"] and t["ai_dedup_of"] is None)
    return {
        "scan_id": scan_id,
        "findings_count": len(findings),
        "real_issues_count": real,
        "false_positives_count": fp_count,
        "duplicates_count": dup_count,
        "root_causes_count": len(ref_to_id),
        "cost_usd": resp.cost_usd,
        "duration_ms": resp.duration_ms,
    }
