from __future__ import annotations
import logging

from db import today_spend_usd

log = logging.getLogger(__name__)


class BudgetExceededError(Exception):
    pass


def check_budget(daily_cap_usd: float) -> float:
    """Lève BudgetExceededError si le cap journalier est atteint. Renvoie le spend actuel sinon."""
    spend = today_spend_usd()
    if spend >= daily_cap_usd:
        log.warning("Budget journalier atteint : %.4f >= %.4f USD", spend, daily_cap_usd)
        raise BudgetExceededError(
            f"Budget journalier atteint ({spend:.4f}/{daily_cap_usd:.2f} USD). "
            f"Augmentez LLM_DAILY_BUDGET_USD ou attendez minuit UTC."
        )
    return spend
