from __future__ import annotations

import re
import time
import socket
from datetime import datetime, timezone
from urllib.error import URLError

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from pymongo import MongoClient

from ..config import settings
from ..utils import load_patterns
from ..normalize import make_event
from ..workflow import jira_create, glpi_create, servicenow_create
from ..integrations.webhooks import try_deliver_to_all
from ..alerts import slack_alerts
from ..alerts import slack_webhook

# Slack client (optional if token not set)
client = WebClient(token=getattr(settings, "slack_bot_token", None), timeout=30) if getattr(settings, "slack_bot_token", None) else None

# Mongo setup
mdb = MongoClient(settings.mongo_uri)[settings.mongo_db]
events = mdb.events
cursors = mdb.cursors

events.create_index("fingerprint", unique=True)
events.create_index([("found_at", 1)])
# DO NOT create an index on _id with unique=True; it already exists by default.
# If you want faster lookups by cursor value, you may also create:
# cursors.create_index("value")


# Compile patterns once
PATTERNS = {k: re.compile(v, re.MULTILINE) for k, v in load_patterns().items()}

def _get_cursor(key: str):
    doc = cursors.find_one({"_id": key})
    return doc.get("value") if doc else None

def _set_cursor(key: str, val: str):
    cursors.update_one({"_id": key}, {"$set": {"value": val}}, upsert=True)

def _retry(call, retries: int = 3, base_delay: float = 0.6):
    last = None
    for i in range(retries):
        try:
            return call()
        except (SlackApiError, URLError, socket.gaierror, TimeoutError) as e:
            last = e
            if i == retries - 1:
                raise
            time.sleep(base_delay * (2 ** i))
    if last:
        raise last

def scan() -> int:
    """Enumerate Slack conversations and detect leaks. Returns count of new events inserted."""
    if not client:
        return 0

    count = 0
    oldest = _get_cursor("slack_oldest") or "0"

    try:
        convs = _retry(lambda: client.conversations_list(
            types="public_channel,private_channel,im,mpim",
            limit=200
        ))
        channels = convs.get("channels", [])
    except (SlackApiError, URLError, socket.gaierror, TimeoutError) as e:
        print(f"[Slack] conversations_list failed: {e}")
        return 0

    for ch in channels:
        cid = ch["id"]
        cname = ch.get("name") or ch.get("user") or cid
        cursor = None

        while True:
            try:
                resp = _retry(lambda: client.conversations_history(
                    channel=cid, limit=200, cursor=cursor, oldest=oldest
                ))
            except (SlackApiError, URLError, socket.gaierror, TimeoutError) as e:
                print(f"[Slack] conversations_history failed for {cid}: {e}")
                break

            for m in resp.get("messages", []):
                ts = m.get("ts", "")
                text = m.get("text", "") or ""
                dets = []
                for label, rx in PATTERNS.items():
                    mo = rx.search(text)
                    if mo:
                        dets.append({"label": label, "match": mo.group(0)})

                if dets:
                    container = {
                        "type": "channel",
                        "id": cid,
                        "name": cname,
                        "url": f"https://slack.com/app_redirect?channel={cid}&message_ts={ts}",
                    }
                    user_id = m.get("user") or m.get("bot_id")
                    ev = make_event(
                        "slack",
                        container,
                        text,
                        dets,
                        {
                            "message_ts": ts,
                            "pointer": ts,
                            "author_id": user_id,
                            "author_name": str(user_id),
                        },
                    )
                    res = events.update_one(
                        {"fingerprint": ev["fingerprint"]},
                        {"$setOnInsert": ev},
                        upsert=True,
                    )
                    if res.upserted_id:
                        count += 1
                        # Auto-ticket creation (best effort)
                        try:
                            jira_create.create_ticket_for_event(ev, mdb)
                            glpi_create.create_ticket_for_event(ev, mdb)
                            servicenow_create.create_ticket_for_event(ev, mdb)
                            slack_alerts.send_event_alert(ev)
                            slack_webhook.send_event_alert(ev)
                        except Exception as e:
                            print("[Slack] ticket create error:", e)
                        # Integrations API — push to registered webhooks
                        try:
                            try_deliver_to_all(ev)
                        except Exception as e:
                            print("[Integrations] webhook dispatch error:", e)

            cursor = resp.get("response_metadata", {}).get("next_cursor")
            if not cursor:
                break
            time.sleep(0.3)  # be nice to the API

    _set_cursor("slack_oldest", str(time.time()))
    return count