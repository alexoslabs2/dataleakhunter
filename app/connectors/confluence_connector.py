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

CONFLUENCE_SERVER = getattr(settings, "confluence_server", None)
JIRA_USERNAME = getattr(settings, "jira_username", None)  # reused creds
JIRA_API_TOKEN = getattr(settings, "jira_api_token", None)

def _get_cursor(key: str):
    doc = cursors.find_one({"_id": key})
    return doc.get("value") if doc else None

def _set_cursor(key: str, val: str):
    cursors.update_one({"_id": key}, {"$set": {"value": val}}, upsert=True)

def scan() -> int:
    """Scan Confluence pages for sensitive data."""
    if not (CONFLUENCE_SERVER and JIRA_USERNAME and JIRA_API_TOKEN):
        return 0

    auth = (JIRA_USERNAME, JIRA_API_TOKEN)
    headers = {"Accept": "application/json"}
    count = 0

    since_iso = _get_cursor("conf_modified")  # ISO string
    cql = "type=page ORDER BY lastmodified DESC"
    if since_iso:
        cql = f"type=page and lastmodified >= {since_iso} ORDER BY lastmodified DESC"

    start = 0
    limit = 50

    while True:
        search_url = f"{CONFLUENCE_SERVER}/rest/api/content/search"
        params = {"cql": cql, "limit": limit, "start": start}
        r = requests.get(search_url, headers=headers, auth=auth, params=params, timeout=20)
        if r.status_code != 200:
            print(f"[Confluence] API error {r.status_code}: {r.text[:200]}")
            break

        data = r.json()
        pages = data.get("results", []) or []
        if not pages:
            break

        for page in pages:
            page_id = page.get("id")
            title = page.get("title", "")
            body_url = f"{CONFLUENCE_SERVER}/rest/api/content/{page_id}"
            body_params = {"expand": "body.storage,version,space,history"}
            br = requests.get(body_url, headers=headers, auth=auth, params=body_params, timeout=20)
            if br.status_code != 200:
                print(f"[Confluence] Body fetch failed {page_id}: {br.status_code}")
                continue
            bjson = br.json()
            storage = ((bjson.get("body") or {}).get("storage") or {}).get("value") or ""
            lastmod = ((bjson.get("version") or {}).get("when")) or page.get("lastmodified")
            try:
                last_dt = datetime.fromisoformat(str(lastmod).replace("Z", "+00:00"))
            except Exception:
                last_dt = datetime.now(tz=timezone.utc)

            dets = []
            for label, rx in PATTERNS.items():
                mo = rx.search(storage)
                if mo:
                    dets.append({"label": label, "match": mo.group(0)})

            if dets:
                container = {
                    "type": "page",
                    "id": page_id,
                    "name": title,
                    "url": f"{CONFLUENCE_SERVER}/pages/viewpage.action?pageId={page_id}",
                }
                ev = make_event(
                    "confluence",
                    container,
                    storage,
                    dets,
                    {"author_name": "", "author_id": "", "pointer": page_id},
                )
                ev["found_at"] = last_dt
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
                        print("[Confluence] ticket create error:", e)
                    try:
                        try_deliver_to_all(ev)
                    except Exception as e:
                        print("[Integrations] webhook dispatch error:", e)

        start = data.get("start", 0) + data.get("limit", limit)
        if start >= data.get("size", 0) and not data.get("_links", {}).get("next"):
            break
        time.sleep(0.3)

    _set_cursor("conf_modified", datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"))
    return count

