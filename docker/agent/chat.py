from __future__ import annotations
import logging

from config import Config
from llm import LLMClient
from prompts.chat import SYSTEM_PROMPT, build_user_prompt, SUMMARY_SYSTEM_PROMPT, build_summary_prompt
import db

log = logging.getLogger(__name__)


def run_chat(cfg: Config, llm: LLMClient, question: str, context_target: str | None) -> dict:
    # Étape 1 : NL → SQL (ou réponse directe si non-SQL)
    user_prompt = build_user_prompt(question, context_target)
    resp1 = llm.call(SYSTEM_PROMPT, user_prompt, json_mode=True)

    try:
        plan = resp1.parse_json()
    except Exception as e:
        log.exception("Réponse chat non-JSON")
        db.log_run("chat", None, context_target, llm.provider, llm.model,
                   resp1.input_tokens, resp1.output_tokens, resp1.cost_usd,
                   resp1.duration_ms, "failed", error=str(e))
        raise

    sql = plan.get("sql")
    total_cost = resp1.cost_usd

    if not sql:
        # Réponse directe sans SQL
        db.log_run("chat", None, context_target, llm.provider, llm.model,
                   resp1.input_tokens, resp1.output_tokens, resp1.cost_usd,
                   resp1.duration_ms, "success")
        return {
            "answer": plan.get("answer", "(réponse vide)"),
            "sql": None, "rows": [], "cost_usd": total_cost,
        }

    # Étape 2 : exécution SQL avec garde-fous
    try:
        rows = db.safe_select(sql, cfg.sql_row_limit)
    except Exception as e:
        log.warning("SQL refusé/échoué : %s — %s", sql, e)
        return {
            "answer": f"Désolé, la requête générée n'a pas pu être exécutée : {e}",
            "sql": sql, "rows": [], "cost_usd": total_cost,
        }

    # Étape 3 : reformulation NL des résultats
    summary_prompt = build_summary_prompt(question, sql, rows)
    resp2 = llm.call(SUMMARY_SYSTEM_PROMPT, summary_prompt)
    total_cost += resp2.cost_usd

    db.log_run("chat", None, context_target, llm.provider, llm.model,
               resp1.input_tokens + resp2.input_tokens,
               resp1.output_tokens + resp2.output_tokens,
               total_cost, resp1.duration_ms + resp2.duration_ms, "success")

    return {
        "answer": resp2.content,
        "sql": sql,
        "rows": rows,
        "cost_usd": total_cost,
    }
