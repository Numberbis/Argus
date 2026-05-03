#!/usr/bin/env python3
"""
Recherche de sites web d'entreprises dans une zone géographique donnée
et mise à jour automatique de config/websites.yml.

Sources (par ordre de priorité) :
  1. Google Places API   — nécessite GOOGLE_MAPS_API_KEY dans .env ou variable d'env
  2. Overpass API (OSM)  — gratuit, aucune clé requise (fallback automatique)

Usage :
    python scripts/scrape-websites.py --query "restaurant" --location "13ème arrondissement, Paris" --limit 10
    python scripts/scrape-websites.py --query "boulangerie" --location "Lyon 2ème" --limit 5 --group boulangeries
    python scripts/scrape-websites.py --query "restaurant" --location "Paris 13" --dry-run
    python scripts/scrape-websites.py --list-groups
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote_plus, urlparse

import requests
import yaml

# ─────────────────────────────────────────────────────────────────────────────
# Chemins
# ─────────────────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parents[1]
CONFIG_PATH = BASE_DIR / "config" / "websites.yml"
ENV_FILE    = BASE_DIR / ".env"

# ─────────────────────────────────────────────────────────────────────────────
# Chargement de la clé API depuis .env si présente
# ─────────────────────────────────────────────────────────────────────────────

def load_env() -> None:
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def get_google_api_key() -> str | None:
    return os.environ.get("GOOGLE_MAPS_API_KEY") or os.environ.get("GOOGLE_PLACES_API_KEY")


# ─────────────────────────────────────────────────────────────────────────────
# Source 1 : Google Places Text Search API
# ─────────────────────────────────────────────────────────────────────────────

def search_google_places(query: str, location: str, limit: int, api_key: str) -> list[dict]:
    """Retourne une liste de {name, url, address} via Google Places Text Search."""
    results = []
    text_query = f"{query} {location}"
    endpoint = "https://maps.googleapis.com/maps/api/place/textsearch/json"

    page_token = None
    while len(results) < limit:
        params: dict = {"query": text_query, "key": api_key, "language": "fr"}
        if page_token:
            params["pagetoken"] = page_token

        try:
            resp = requests.get(endpoint, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            print(f"  [Google Places] Erreur réseau : {exc}", file=sys.stderr)
            break

        if data.get("status") not in ("OK", "ZERO_RESULTS"):
            print(f"  [Google Places] Statut inattendu : {data.get('status')} — {data.get('error_message','')}", file=sys.stderr)
            break

        place_ids = [p["place_id"] for p in data.get("results", [])]
        for place_id in place_ids:
            if len(results) >= limit:
                break
            detail = _google_place_detail(place_id, api_key)
            if detail:
                results.append(detail)

        page_token = data.get("next_page_token")
        if not page_token:
            break
        time.sleep(2)   # Google exige un délai avant d'utiliser le next_page_token

    return results[:limit]


def _google_place_detail(place_id: str, api_key: str) -> dict | None:
    endpoint = "https://maps.googleapis.com/maps/api/place/details/json"
    params = {
        "place_id": place_id,
        "fields": "name,website,formatted_address",
        "key": api_key,
        "language": "fr",
    }
    try:
        resp = requests.get(endpoint, params=params, timeout=10)
        resp.raise_for_status()
        result = resp.json().get("result", {})
    except requests.RequestException:
        return None

    website = result.get("website", "").strip()
    if not website:
        return None

    return {
        "name": result.get("name", ""),
        "url": _normalize_url(website),
        "address": result.get("formatted_address", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Source 2 : Overpass API (OpenStreetMap) — fallback gratuit
# ─────────────────────────────────────────────────────────────────────────────

# Correspondance type de recherche → tags OSM
OSM_TYPE_MAP: dict[str, list[str]] = {
    "restaurant":     ['amenity=restaurant', 'amenity=fast_food'],
    "boulangerie":    ['shop=bakery'],
    "café":           ['amenity=cafe'],
    "bar":            ['amenity=bar'],
    "hôtel":          ['tourism=hotel'],
    "médecin":        ['amenity=doctors'],
    "pharmacie":      ['amenity=pharmacy'],
    "coiffeur":       ['shop=hairdresser'],
    "fleuriste":      ['shop=florist'],
    "librairie":      ['shop=books'],
    "épicerie":       ['shop=convenience'],
    "supermarché":    ['shop=supermarket'],
    "sport":          ['leisure=sports_centre', 'shop=sports'],
    "musée":          ['tourism=museum'],
    "école":          ['amenity=school'],
}

def search_overpass(query: str, location: str, limit: int) -> list[dict]:
    """Retourne des POI avec website via Overpass API (OSM)."""
    bbox = _geocode_location(location)
    if not bbox:
        print(f"  [Overpass] Impossible de géocoder '{location}'", file=sys.stderr)
        return []

    # Détermination des tags OSM à chercher
    query_lower = query.lower()
    osm_tags: list[str] = []
    for keyword, tags in OSM_TYPE_MAP.items():
        if keyword in query_lower:
            osm_tags = tags
            break
    if not osm_tags:
        # Recherche générique par nom
        osm_tags = [f'name~"{query}",i']

    south, west, north, east = bbox
    overpass_url = "https://overpass-api.de/api/interpreter"

    # Construction de la requête Overpass QL
    tag_filters = "\n  ".join(
        f'node[{tag}]["website"]({south},{west},{north},{east});'
        f'\n  way[{tag}]["website"]({south},{west},{north},{east});'
        for tag in osm_tags
    )
    overpass_query = f"""
[out:json][timeout:25];
(
  {tag_filters}
);
out body {limit * 3};
"""

    try:
        resp = requests.post(overpass_url, data={"data": overpass_query}, timeout=30)
        resp.raise_for_status()
        elements = resp.json().get("elements", [])
    except requests.RequestException as exc:
        print(f"  [Overpass] Erreur réseau : {exc}", file=sys.stderr)
        return []

    results = []
    seen_urls: set[str] = set()
    for el in elements:
        tags_el = el.get("tags", {})
        website = tags_el.get("website", "").strip()
        name    = tags_el.get("name", "").strip()
        if not website or not name:
            continue
        url = _normalize_url(website)
        if url in seen_urls:
            continue
        seen_urls.add(url)
        results.append({"name": name, "url": url, "address": _osm_address(tags_el)})
        if len(results) >= limit:
            break

    return results


def _geocode_location(location: str) -> tuple[float, float, float, float] | None:
    """Retourne (south, west, north, east) via Nominatim."""
    nominatim_url = "https://nominatim.openstreetmap.org/search"
    params = {"q": location, "format": "json", "limit": 1}
    headers = {"User-Agent": "audit-scraper/1.0 (security-audit-tool)"}
    try:
        resp = requests.get(nominatim_url, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        return None

    if not data:
        return None

    bb = data[0].get("boundingbox")
    if not bb or len(bb) < 4:
        return None

    south, north, west, east = float(bb[0]), float(bb[1]), float(bb[2]), float(bb[3])
    return south, west, north, east


def _osm_address(tags: dict) -> str:
    parts = [
        tags.get("addr:housenumber", ""),
        tags.get("addr:street", ""),
        tags.get("addr:postcode", ""),
        tags.get("addr:city", ""),
    ]
    return " ".join(p for p in parts if p)


# ─────────────────────────────────────────────────────────────────────────────
# Utilitaires URL
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """S'assure que l'URL commence par https:// ou http://."""
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _slug(name: str) -> str:
    """Convertit un nom en slug utilisable comme clé YAML."""
    slug = name.lower()
    slug = re.sub(r"[àáâä]", "a", slug)
    slug = re.sub(r"[èéêë]", "e", slug)
    slug = re.sub(r"[îï]", "i", slug)
    slug = re.sub(r"[ôö]", "o", slug)
    slug = re.sub(r"[ùûü]", "u", slug)
    slug = re.sub(r"[ç]", "c", slug)
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


# ─────────────────────────────────────────────────────────────────────────────
# Lecture / écriture config/websites.yml
# ─────────────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def existing_urls(config: dict) -> set[str]:
    return {s["url"].rstrip("/") for s in config.get("websites", [])}


def existing_groups(config: dict) -> set[str]:
    return {s.get("group", "") for s in config.get("websites", []) if s.get("group")}


def append_sites(config: dict, new_sites: list[dict], group: str) -> tuple[dict, int]:
    """Ajoute les nouveaux sites dans la config, ignore les doublons d'URL."""
    already = existing_urls(config)
    added = 0
    for site in new_sites:
        if site["url"].rstrip("/") in already:
            print(f"  ⏭  Doublon ignoré : {site['url']}")
            continue
        entry = {
            "name":         site["name"],
            "url":          site["url"],
            "group":        group,
            "scan_profile": "light",
        }
        config.setdefault("websites", []).append(entry)
        already.add(site["url"].rstrip("/"))
        added += 1
    return config, added


def save_config(config: dict) -> None:
    """Réécrit config/websites.yml en préservant l'en-tête de commentaire."""
    header = (
        "---\n"
        "# Source de vérité unique pour les sites à auditer.\n"
        "# Ajouter un site ici puis relancer : ansible-playbook playbooks/update-targets.yml\n"
        "#\n"
        "# Groupes disponibles : agence | restaurants | vignobles | media | divers\n"
        "# Filtrer par groupe  : python scripts/audit-now.py --group restaurants\n"
        "\n"
    )
    body = yaml.dump(
        config,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        indent=2,
    )
    CONFIG_PATH.write_text(header + body, encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# Affichage
# ─────────────────────────────────────────────────────────────────────────────

def print_results(found: list[dict], source: str) -> None:
    print(f"\n  Source : {source}  ({len(found)} résultat(s))\n")
    for i, site in enumerate(found, 1):
        addr = f"  {site['address']}" if site.get("address") else ""
        print(f"  {i:2}. {site['name']}")
        print(f"      {site['url']}{addr}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    load_env()

    parser = argparse.ArgumentParser(
        description="Recherche des sites web d'entreprises dans une zone et met à jour config/websites.yml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Exemples :
  python scripts/scrape-websites.py --query "restaurant" --location "13ème arrondissement, Paris" --limit 10
  python scripts/scrape-websites.py --query "boulangerie" --location "Lyon 2ème" --group boulangeries
  python scripts/scrape-websites.py --query "restaurant" --location "Paris 13" --dry-run
  python scripts/scrape-websites.py --list-groups

Variables d'environnement :
  GOOGLE_MAPS_API_KEY  — clé Google Places API (optionnelle, active la source Google)
""",
    )
    parser.add_argument("--query",    metavar="TYPE",
                        help="Type d'établissement (ex: restaurant, boulangerie, hôtel)")
    parser.add_argument("--location", metavar="LIEU",
                        help="Zone géographique (ex: '13ème arrondissement, Paris', 'Lyon 2ème')")
    parser.add_argument("--limit",    metavar="N", type=int, default=10,
                        help="Nombre maximum de sites à récupérer (défaut: 10)")
    parser.add_argument("--group",    metavar="GROUPE", default=None,
                        help="Groupe à assigner dans websites.yml (défaut: dérivé de --query)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Afficher les résultats sans modifier websites.yml")
    parser.add_argument("--list-groups", action="store_true",
                        help="Lister les groupes existants dans config/websites.yml")
    parser.add_argument("--source",   choices=["google", "osm", "auto"], default="auto",
                        help="Forcer une source de données (défaut: auto — Google si clé dispo, sinon OSM)")
    args = parser.parse_args()

    # ── list-groups ──────────────────────────────────────────────────────────
    if args.list_groups:
        config = load_config()
        groups = existing_groups(config)
        print("\nGroupes existants dans config/websites.yml :")
        for g in sorted(groups):
            count = sum(1 for s in config["websites"] if s.get("group") == g)
            print(f"  {g:<20} ({count} site(s))")
        print()
        return

    # ── validation args ──────────────────────────────────────────────────────
    if not args.query or not args.location:
        parser.error("--query et --location sont obligatoires (sauf --list-groups)")

    group = args.group or _slug(args.query)

    print(f"\n▶ Recherche : « {args.query} » dans « {args.location} » (max {args.limit})")

    # ── sélection source ─────────────────────────────────────────────────────
    api_key = get_google_api_key()
    found: list[dict] = []
    source_used = ""

    use_google = args.source == "google" or (args.source == "auto" and api_key)
    use_osm    = args.source == "osm"    or (args.source == "auto" and not api_key)

    if use_google:
        if not api_key:
            print("  Clé GOOGLE_MAPS_API_KEY manquante — basculement sur Overpass/OSM", file=sys.stderr)
            use_osm = True
            use_google = False
        else:
            print("  Utilisation de Google Places API...")
            found = search_google_places(args.query, args.location, args.limit, api_key)
            source_used = "Google Places API"
            if not found:
                print("  Aucun résultat Google — basculement sur Overpass/OSM")
                use_osm = True

    if use_osm and not found:
        print("  Utilisation de Overpass API (OpenStreetMap)...")
        found = search_overpass(args.query, args.location, args.limit)
        source_used = "Overpass API (OpenStreetMap)"

    if not found:
        print("  Aucun résultat trouvé. Essayez de reformuler --query ou --location.")
        sys.exit(0)

    print_results(found, source_used)

    # ── dry-run ───────────────────────────────────────────────────────────────
    if args.dry_run:
        print("  Mode --dry-run : aucune modification de websites.yml")
        return

    # ── mise à jour config ────────────────────────────────────────────────────
    config = load_config()
    config, added = append_sites(config, found, group)

    if added == 0:
        print("  Aucun nouveau site ajouté (tous déjà présents).")
        return

    save_config(config)
    print(f"  {added} site(s) ajouté(s) dans config/websites.yml (groupe : {group})")
    print(f"  Pour auditer ce groupe : python scripts/audit-now.py --group {group}\n")


if __name__ == "__main__":
    main()
