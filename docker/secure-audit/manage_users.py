#!/usr/bin/env python3
"""
Gestion des utilisateurs — Secure Audit (By Build Web)

Usage :
  # Ajouter un admin (accès illimité)
  python manage_users.py add admin --password MonMotDePasse

  # Ajouter un utilisateur restreint à un ou plusieurs sites
  python manage_users.py add chez-meilan --password MonMotDePasse --url https://chez-meilan.fr
  python manage_users.py add client-xyz  --password MonMotDePasse --url https://site1.fr --url https://site2.fr

  # Lister tous les utilisateurs
  python manage_users.py list

  # Supprimer un utilisateur
  python manage_users.py delete chez-meilan

  # Réinitialiser le mot de passe
  python manage_users.py passwd chez-meilan --password NouveauMotDePasse

Le fichier users.json est créé dans le répertoire courant par défaut.
En production (Docker), spécifier le chemin via --file ou USERS_FILE :
  python manage_users.py --file /app/data/users.json add ...
  USERS_FILE=/app/data/users.json python manage_users.py add ...
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

DEFAULT_USERS_FILE = os.environ.get("USERS_FILE", "data/users.json")


def load_users(path: Path) -> dict:
    if path.exists():
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_users(path: Path, users: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    print(f"✓ Fichier mis à jour : {path}")


# ── Commandes ─────────────────────────────────────────────────────────────────

def cmd_add(args, path: Path) -> None:
    users = load_users(path)

    if args.username in users:
        answer = input(f"L'utilisateur '{args.username}' existe déjà. Écraser ? [o/N] ")
        if answer.lower() not in ("o", "oui", "y", "yes"):
            print("Annulé.")
            sys.exit(0)

    allowed_urls = args.url if args.url else None  # None = accès illimité

    users[args.username] = {
        "password_hash": generate_password_hash(args.password),
        "allowed_urls":  allowed_urls,
        "description":   args.description or "",
    }

    save_users(path, users)

    if allowed_urls:
        print(f"✓ Utilisateur '{args.username}' créé — restreint à : {', '.join(allowed_urls)}")
    else:
        print(f"✓ Utilisateur '{args.username}' créé — accès illimité")


def cmd_list(args, path: Path) -> None:
    users = load_users(path)

    if not users:
        print("Aucun utilisateur dans le fichier.")
        return

    print(f"\n{'Utilisateur':<20} {'Restriction URL':<40} {'Description'}")
    print("─" * 80)
    for username, data in users.items():
        urls = ", ".join(data.get("allowed_urls") or []) or "— (accès illimité)"
        desc = data.get("description") or ""
        print(f"{username:<20} {urls:<40} {desc}")
    print()


def cmd_delete(args, path: Path) -> None:
    users = load_users(path)

    if args.username not in users:
        print(f"Erreur : utilisateur '{args.username}' introuvable.", file=sys.stderr)
        sys.exit(1)

    del users[args.username]
    save_users(path, users)
    print(f"✓ Utilisateur '{args.username}' supprimé.")


def cmd_passwd(args, path: Path) -> None:
    users = load_users(path)

    if args.username not in users:
        print(f"Erreur : utilisateur '{args.username}' introuvable.", file=sys.stderr)
        sys.exit(1)

    users[args.username]["password_hash"] = generate_password_hash(args.password)
    save_users(path, users)
    print(f"✓ Mot de passe de '{args.username}' mis à jour.")


# ── Point d'entrée ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gestion des utilisateurs Secure Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--file", default=DEFAULT_USERS_FILE,
        help=f"Chemin vers users.json (défaut : {DEFAULT_USERS_FILE})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # add
    p_add = sub.add_parser("add", help="Créer ou remplacer un utilisateur")
    p_add.add_argument("username", help="Nom d'utilisateur")
    p_add.add_argument("--password", required=True, help="Mot de passe")
    p_add.add_argument(
        "--url", action="append", metavar="URL",
        help="URL autorisée (répéter pour plusieurs). Sans cette option : accès illimité.",
    )
    p_add.add_argument("--description", default="", help="Description (optionnelle)")

    # list
    sub.add_parser("list", help="Lister les utilisateurs")

    # delete
    p_del = sub.add_parser("delete", help="Supprimer un utilisateur")
    p_del.add_argument("username", help="Nom d'utilisateur à supprimer")

    # passwd
    p_pw = sub.add_parser("passwd", help="Changer le mot de passe")
    p_pw.add_argument("username", help="Nom d'utilisateur")
    p_pw.add_argument("--password", required=True, help="Nouveau mot de passe")

    args = parser.parse_args()
    path = Path(args.file)

    dispatch = {
        "add":    cmd_add,
        "list":   cmd_list,
        "delete": cmd_delete,
        "passwd": cmd_passwd,
    }
    dispatch[args.command](args, path)


if __name__ == "__main__":
    main()
