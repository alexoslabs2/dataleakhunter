from __future__ import annotations

import re
import time
from datetime import datetime, timezone

import requests
from pymongo import MongoClient

from ..config import settings
from ..utils import load_patterns
from ..normalize import make_event
from ..workflow import jira_create, glpi_create, servicenow_create
from ..integrations.webhooks import try_deliver_to_all
from ..alerts import slack_alerts
from ..alerts import slack_webhook

# Mongo setup
mdb = MongoClient(settings.mongo_uri)[settings.mongo_db]
events = mdb.events
cursors = mdb.cursors

events.create_index("fingerprint", unique=True)
events.create_index([("found_at", 1)])
# No _id index creation; it's built-in.
# cursors.create_index("value")  # optional

PATTERNS = {k: re.compile(v, re.MULTILINE) for k, v in load_patterns().items()}

TRELLO_KEY = getattr(settings, "trello_key", None)
TRELLO_TOKEN = getattr(settings, "trello_token", None)
TRELLO_API = "https://api.trello.com/1"

def scan() -> int:
    """Scan Trello boards/cards for sensitive data."""
    if not (TRELLO_KEY and TRELLO_TOKEN):
        print("[Trello] Missing API key/token.")
        return 0

    count = 0
    auth = {"key": TRELLO_KEY, "token": TRELLO_TOKEN}

    # Boards
    r = requests.get(f"{TRELLO_API}/members/me/boards", params=auth, timeout=20)
    if r.status_code != 200:
        print(f"[Trello] list boards error: Trello GET {r.url} failed: {r.status_code} {r.text[:200]}")
        return 0
    boards = r.json() or []

    for b in boards:
        bid = b.get("id")
        bname = b.get("name") or bid

        # Lists on board
        rl = requests.get(f"{TRELLO_API}/boards/{bid}/lists", params=auth, timeout=20)
        if rl.status_code != 200:
            print(f"[Trello] list lists error: {rl.status_code} {rl.text[:200]}")
            continue
        lists = rl.json() or []

        for lst in lists:
            lid = lst.get("id")
            lname = lst.get("name") or lid

            # Cards in list
            rc = requests.get(f"{TRELLO_API}/lists/{lid}/cards", params={**auth, "fields": "name,desc,url,dateLastActivity,idMembers"}, timeout=20)
            if rc.status_code != 200:
                print(f"[Trello] list cards error: {rc.status_code} {rc.text[:200]}")
                continue
            cards = rc.json() or []

            for card in cards:
                cname = card.get("name") or card.get("id")
                cdesc = card.get("desc") or ""
                text = f"{cname}\n{cdesc}"
                dets = []
                for label, rx in PATTERNS.items():
                    mo = rx.search(text)
                    if mo:
                        dets.append({"label": label, "match": mo.group(0)})

                if dets:
                    when = card.get("dateLastActivity")
                    try:
                        found_at = datetime.fromisoformat(when.replace("Z", "+00:00")) if when else datetime.now(tz=timezone.utc)
                    except Exception:
                        found_at = datetime.now(tz=timezone.utc)

                    container = {
                        "type": "card",
                        "id": card.get("id"),
                        "name": f"{bname} / {lname} / {cname}",
                        "url": card.get("url"),
                    }
                    ev = make_event(
                        "trello",
                        container,
                        text,
                        dets,
                        {"author_name": "", "author_id": "", "pointer": card.get("id")},
                    )
                    ev["found_at"] = found_at

                    res = events.update_one({"fingerprint": ev["fingerprint"]}, {"$setOnInsert": ev}, upsert=True)
                    if res.upserted_id:
                        count += 1
                        try:
                            jira_create.create_ticket_for_event(ev, mdb)
                            glpi_create.create_ticket_for_event(ev, mdb)
                            servicenow_create.create_ticket_for_event(ev, mdb)
                            slack_alerts.send_event_alert(ev)
                            slack_webhook.send_event_alert(ev)
                        except Exception as e:
                            print("[Trello] ticket create error:", e)
                        try:
                            try_deliver_to_all(ev)
                        except Exception as e:
                            print("[Integrations] webhook dispatch error:", e)

            time.sleep(0.2)

    return count
