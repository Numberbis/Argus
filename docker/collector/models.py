from __future__ import annotations
from typing import Optional
from pydantic import BaseModel


class Finding(BaseModel):
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    description: Optional[str] = None
    url: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_ids: list[str] = []
    remediation: Optional[str] = None


class ScanResult(BaseModel):
    started_at: str
    target_url: Optional[str] = None   # URL de la cible scannée (ex: https://buildweb.fr)
    findings: list[Finding]
    raw_output: dict | list = {}
