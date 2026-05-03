#!/usr/bin/env python3
"""Triage IA de tous les scans complétés non encore triagés.

Utile en bulk après une migration ou pour rattraper un retard de file d'attente.

Usage :
    python3 scripts/triage-all.py [--limit 50] [--target site-name]
"""
from __future__ import annotations
import argparse
import os
import sys

import psycopg2
import psycopg2.extras

try:
    import httpx
except ImportError:
    print("Erreur : httpx non installé. Lancez : pip install httpx", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=50, help="Nombre max de scans à traiter")
    p.add_argument("--target", type=str, default=None, help="Limiter à un site")
    p.add_argument("--db-url", default=os.environ.get("DB_URL"))
    p.add_argument("--agent-url", default=os.environ.get("AGENT_URL", "http://localhost:8090"))
    args = p.parse_args()

    if not args.db_url:
        # défaut sensé en mode docker compose local
        args.db_url = "postgresql://audit:audit@localhost:5432/audit_db"

    conn = psycopg2.connect(args.db_url)
    sql = """SELECT s.id FROM scans s
             WHERE s.status = 'completed'
               AND NOT EXISTS (
                   SELECT 1 FROM findings f
                   WHERE f.scan_id = s.id AND f.ai_triaged_at IS NOT NULL
               )
               AND EXISTS (SELECT 1 FROM findings f WHERE f.scan_id = s.id)"""
    params: list = []
    if args.target:
        sql += " AND s.target = %s"
        params.append(args.target)
    sql += " ORDER BY s.started_at DESC LIMIT %s"
    params.append(args.limit)

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        scans = [dict(r) for r in cur.fetchall()]
    conn.close()

    if not scans:
        print("Aucun scan à triager.")
        return 0

    print(f"Triage de {len(scans)} scans via {args.agent_url}...")
    total_cost = 0.0
    succeeded = 0
    with httpx.Client(timeout=180) as client:
        for s in scans:
            try:
                r = client.post(f"{args.agent_url}/triage", json={"scan_id": s["id"]})
                if r.status_code == 429:
                    print(f"  Scan {s['id']}: budget atteint, arrêt.")
                    break
                r.raise_for_status()
                d = r.json()
                total_cost += d.get("cost_usd", 0.0)
                succeeded += 1
                print(f"  Scan {s['id']}: {d['findings_count']} → {d['real_issues_count']} "
                      f"real ({d['false_positives_count']} FP, {d['duplicates_count']} dup) "
                      f"${d['cost_usd']:.4f}")
            except Exception as e:
                print(f"  Scan {s['id']}: ERREUR {e}", file=sys.stderr)

    print(f"\nTerminé : {succeeded}/{len(scans)} succès, coût total ${total_cost:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
