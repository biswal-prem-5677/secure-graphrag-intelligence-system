"""
CLI utilities for Secure GraphRAG Knowledge Intelligence System.
Usage:
    python -m app.cli create-admin [--username admin]
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
import uuid

from app.db.database import init_db
from app.models.user import User, UserRole, user_store
from app.security.auth import hash_password


def create_admin(username: str = "admin", password: str | None = None) -> None:
    """Create the initial admin account safely without hardcoded defaults."""
    init_db()
    if user_store.user_exists(username):
        print(f"Error: User '{username}' already exists.", file=sys.stderr)
        sys.exit(1)

    pw = password or os.environ.get("ADMIN_PASSWORD") or os.environ.get("DEFAULT_ADMIN_PASSWORD")
    generated = False
    if not pw:
        if sys.stdin.isatty():
            pw = getpass.getpass(f"Enter password for admin '{username}' (leave blank to auto-generate): ").strip()
        if not pw:
            pw = secrets.token_urlsafe(18)
            generated = True

    if len(pw) < 12:
        print("Error: Admin password must be at least 12 characters.", file=sys.stderr)
        sys.exit(1)

    user_store.add_user(
        User(
            id=str(uuid.uuid4()),
            username=username,
            role=UserRole.admin,
            hashed_password=hash_password(pw),
            disabled=False,
        )
    )
    print(f"Admin user '{username}' created successfully.")
    if generated:
        print(f"Generated one-time password: {pw}")
        print("Store this password securely; it will not be displayed again.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure GraphRAG Admin CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    admin_parser = subparsers.add_parser("create-admin", help="Create an administrator account")
    admin_parser.add_argument("--username", default="admin", help="Admin username (default: admin)")

    args = parser.parse_args()
    if args.command == "create-admin":
        create_admin(username=args.username)


if __name__ == "__main__":
    main()
