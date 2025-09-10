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
# No custom _id index needed on cursors.
# cursors.create_index("value")  # optional

PATTERNS = {k: re.compile(v, re.MULTILINE) for k, v in load_patterns().items()}

JIRA_SERVER = getattr(settings, "jira_server", None)
JIRA_USERNAME = getattr(settings, "jira_username", None)
JIRA_API_TOKEN = getattr(settings, "jira_api_token", None)

def _get_cursor(key: str):
    doc = cursors.find_one({"_id": key})
    return doc.get("value") if doc else None

def _set_cursor(key: str, val: str):
    cursors.update_one({"_id": key}, {"$set": {"value": val}}, upsert=True)

def scan() -> int:
    """Scan Jira issues for sensitive data."""
    if not (JIRA_SERVER and JIRA_USERNAME and JIRA_API_TOKEN):
        return 0

    auth = (JIRA_USERNAME, JIRA_API_TOKEN)
    headers = {"Accept": "application/json"}
    count = 0

    updated_cursor = _get_cursor("jira_updated")  # ISO string
    jql = "ORDER BY updated DESC"
    if updated_cursor:
        jql = f"updated >= '{updated_cursor}' ORDER BY updated DESC"

    start_at = 0
    page_size = 50

    while True:
        url = f"{JIRA_SERVER}/rest/api/2/search"
        params = {"jql": jql, "startAt": start_at, "maxResults": page_size, "fields": "summary,description,updated"}
        r = requests.get(url, headers=headers, auth=auth, params=params, timeout=20)
        if r.status_code != 200:
            print(f"[Jira] API error {r.status_code}: {r.text[:200]}")
            break

        data = r.json()
        issues = data.get("issues", [])
        if not issues:
            break

        for issue in issues:
            key = issue.get("key")
            fields = issue.get("fields") or {}
            updated = fields.get("updated")
            try:
                updated_dt = datetime.fromisoformat(updated.replace("Z", "+00:00")) if updated else datetime.now(tz=timezone.utc)
            except Exception:
                updated_dt = datetime.now(tz=timezone.utc)

            combined = f"{fields.get('summary','')}\n{fields.get('description','') or ''}"
            dets = []
            for label, rx in PATTERNS.items():
                mo = rx.search(combined or "")
                if mo:
                    dets.append({"label": label, "match": mo.group(0)})

            if dets:
                container = {
                    "type": "issue",
                    "id": key,
                    "name": key,
                    "url": f"{JIRA_SERVER}/browse/{key}",
                }
                ev = make_event(
                    "jira",
                    container,
                    combined or "",
                    dets,
                    {"author_name": "", "author_id": "", "pointer": key, "updated": updated},
                )
                # Ensure found_at reflects issue updated time
                ev["found_at"] = updated_dt
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
                        print("[JiraConnector] ticket create error:", e)
                    try:
                        try_deliver_to_all(ev)
                    except Exception as e:
                        print("[Integrations] webhook dispatch error:", e)

        start_at += page_size
        if start_at >= data.get("total", 0):
            break
        time.sleep(0.3)

    # Advance cursor conservatively to now (or last seen updated)
    _set_cursor("jira_updated", datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"))
    return count
