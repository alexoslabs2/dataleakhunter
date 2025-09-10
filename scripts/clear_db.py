#!/usr/bin/env python3
"""
LeakHunter DB cleaner.

Usage examples:
  # Soft-reset common collections (events/cursors/scheduler), keep indexes
  python scripts/clear_db.py --mode soft --yes

  # Drop common collections entirely
  python scripts/clear_db.py --mode drop --yes

  # Only clear specific collections
  python scripts/clear_db.py --mode soft --collections events cursors --yes

  # Nuke entire database (DANGEROUS)
  python scripts/clear_db.py --mode nuke --yes --force
"""

import os
import sys
import argparse
from typing import List
from pymongo import MongoClient

DEFAULT_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017")
DEFAULT_DB = os.getenv("MONGO_DB", "leakhunter")

# Collections we use in LeakHunter (will skip if not present)
DEFAULT_TARGETS = [
    "events",
    "cursors",
    "scheduler",
    # Optional/occasional:
    "exports_state",
    "alerts",
    "tickets",
]

SYSTEM_DBS = {"admin", "local", "config"}

def confirm(prompt: str) -> bool:
    ans = input(f"{prompt} [y/N]: ").strip().lower()
    return ans in {"y", "yes"}

def list_existing(db, names: List[str]) -> List[str]:
    existing = set(db.list_collection_names())
    return [c for c in names if c in existing]

def main():
    parser = argparse.ArgumentParser(description="LeakHunter MongoDB cleaner")
    parser.add_argument("--uri", default=DEFAULT_URI, help=f"Mongo URI (default: {DEFAULT_URI})")
    parser.add_argument("--db", default=DEFAULT_DB, help=f"Database name (default: {DEFAULT_DB})")
    parser.add_argument("--mode", choices=["soft", "drop", "nuke"], required=True,
                        help="soft=delete docs, drop=drop collections, nuke=drop database")
    parser.add_argument("--collections", nargs="*", help="Limit to these collections (default: LeakHunter defaults)")
    parser.add_argument("--all", action="store_true", help="Affect ALL non-system collections in the DB")
    parser.add_argument("--yes", action="store_true", help="Do not prompt for confirmation")
    parser.add_argument("--force", action="store_true", help="Required with --mode nuke")
    args = parser.parse_args()

    client = MongoClient(args.uri)
    db = client[args.db]

    if args.mode == "nuke":
        if args.db in SYSTEM_DBS:
            print(f"Refusing to drop system database '{args.db}'. Choose a different DB.", file=sys.stderr)
            sys.exit(2)
        if not args.force:
            print("Refusing to nuke without --force.", file=sys.stderr)
            sys.exit(2)
        if not args.yes and not confirm(f"Really DROP DATABASE '{args.db}' at {args.uri}?"):
            print("Aborted.")
            sys.exit(0)
        client.drop_database(args.db)
        print(f"[OK] Dropped database '{args.db}'.")
        return

    # Determine target collections
    if args.all:
        targets = [c for c in db.list_collection_names() if not c.startswith("system.")]
    elif args.collections:
        targets = args.collections
    else:
        targets = DEFAULT_TARGETS

    targets = list_existing(db, targets)
    if not targets:
        print("[Info] No matching collections to operate on.")
        return

    # Preview counts
    print(f"Target DB: {args.db} @ {args.uri}")
    print(f"Mode: {args.mode}")
    print("Collections:")
    for c in targets:
        try:
            cnt = db[c].estimated_document_count()
        except Exception:
            cnt = "?"
        print(f"  - {c} (docs: {cnt})")

    if not args.yes and not confirm("Proceed with the operation"):
        print("Aborted.")
        return

    # Execute
    for c in targets:
        coll = db[c]
        if args.mode == "soft":
            res = coll.delete_many({})
            print(f"[soft] {c}: deleted {res.deleted_count} docs")
        elif args.mode == "drop":
            db.drop_collection(c)
            print(f"[drop] {c}: dropped")

    print("[DONE]")

if __name__ == "__main__":
    main()
