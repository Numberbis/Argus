"""Argus AI Agent — service FastAPI pour le triage, la remédiation et le chat."""
from __future__ import annotations
import logging
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

from config import Config
from llm import LLMClient
from budget import check_budget, BudgetExceededError
import db
import triage as triage_mod
import remediate as remediate_mod
import chat as chat_mod
from models import (
    TriageRequest, TriageResponse,
    RemediateRequest, RemediateResponse,
    ChatRequest, ChatResponse,
    BudgetResponse,
)


logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("argus.agent")

cfg = Config.from_env()
llm = LLMClient(
    provider=cfg.provider,
    model=cfg.litellm_model,
    api_key=cfg.api_key,
    api_base=cfg.api_base,
    supports_cache=cfg.supports_cache,
)

app = FastAPI(
    title="Argus AI Agent",
    version="0.1.0",
    description="Triage, remédiation et chat sur les données de sécurité Argus",
)

# Métriques Prometheus
TRIAGE_TOTAL = Counter("argus_triage_total", "Triages effectués", ["status"])
TRIAGE_DURATION = Histogram("argus_triage_duration_seconds", "Durée triage")
REMEDIATE_TOTAL = Counter("argus_remediate_total", "Remédiations générées", ["status"])
CHAT_TOTAL = Counter("argus_chat_total", "Requêtes chat", ["status"])
LLM_COST = Counter("argus_llm_cost_usd", "Coût cumulé en USD", ["run_type"])


@app.get("/health")
def health():
    return {"status": "ok", "provider": cfg.provider, "model": cfg.model}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/budget", response_model=BudgetResponse)
def budget():
    spend = db.today_spend_usd()
    return BudgetResponse(
        spend_today_usd=spend,
        daily_cap_usd=cfg.daily_budget_usd,
        remaining_usd=max(0.0, cfg.daily_budget_usd - spend),
        provider=cfg.provider,
        model=cfg.model,
    )


@app.post("/triage", response_model=TriageResponse)
def triage_endpoint(req: TriageRequest):
    try:
        check_budget(cfg.daily_budget_usd)
    except BudgetExceededError as e:
        TRIAGE_TOTAL.labels(status="budget_exceeded").inc()
        raise HTTPException(status_code=429, detail=str(e))

    try:
        with TRIAGE_DURATION.time():
            result = triage_mod.run_triage(cfg, llm, req.scan_id)
        TRIAGE_TOTAL.labels(status="success").inc()
        LLM_COST.labels(run_type="triage").inc(result["cost_usd"])
        return TriageResponse(**result)
    except ValueError as e:
        TRIAGE_TOTAL.labels(status="not_found").inc()
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        log.exception("Triage failed for scan_id=%s", req.scan_id)
        TRIAGE_TOTAL.labels(status="error").inc()
        raise HTTPException(status_code=500, detail=f"Triage failed: {e}")


@app.post("/remediate", response_model=RemediateResponse)
def remediate_endpoint(req: RemediateRequest):
    try:
        check_budget(cfg.daily_budget_usd)
    except BudgetExceededError as e:
        REMEDIATE_TOTAL.labels(status="budget_exceeded").inc()
        raise HTTPException(status_code=429, detail=str(e))

    try:
        result = remediate_mod.run_remediate(cfg, llm, req.finding_id)
        REMEDIATE_TOTAL.labels(status="success").inc()
        LLM_COST.labels(run_type="remediate").inc(result["cost_usd"])
        return RemediateResponse(**result)
    except ValueError as e:
        REMEDIATE_TOTAL.labels(status="not_found").inc()
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        log.exception("Remediate failed for finding_id=%s", req.finding_id)
        REMEDIATE_TOTAL.labels(status="error").inc()
        raise HTTPException(status_code=500, detail=f"Remediate failed: {e}")


@app.post("/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest):
    try:
        check_budget(cfg.daily_budget_usd)
    except BudgetExceededError as e:
        CHAT_TOTAL.labels(status="budget_exceeded").inc()
        raise HTTPException(status_code=429, detail=str(e))

    try:
        result = chat_mod.run_chat(cfg, llm, req.question, req.context_target)
        CHAT_TOTAL.labels(status="success").inc()
        LLM_COST.labels(run_type="chat").inc(result["cost_usd"])
        return ChatResponse(**result)
    except Exception as e:
        log.exception("Chat failed")
        CHAT_TOTAL.labels(status="error").inc()
        raise HTTPException(status_code=500, detail=f"Chat failed: {e}")
