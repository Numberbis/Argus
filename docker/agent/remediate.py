from __future__ import annotations
import logging

from config import Config
from llm import LLMClient
from prompts.remediate import SYSTEM_PROMPT, build_user_prompt
import db

log = logging.getLogger(__name__)


def run_remediate(cfg: Config, llm: LLMClient, finding_id: int) -> dict:
    finding = db.fetch_finding(finding_id)
    if not finding:
        raise ValueError(f"finding_id {finding_id} introuvable")

    user_prompt = build_user_prompt(finding)
    resp = llm.call(SYSTEM_PROMPT, user_prompt)

    db.set_remediation(finding_id, resp.content)
    db.log_run("remediate", finding.get("scan_id"), finding.get("target"), llm.provider,
               llm.model, resp.input_tokens, resp.output_tokens, resp.cost_usd,
               resp.duration_ms, "success")

    return {
        "finding_id": finding_id,
        "remediation": resp.content,
        "cost_usd": resp.cost_usd,
    }
