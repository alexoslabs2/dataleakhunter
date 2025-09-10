from __future__ import annotations

import os, time, json
from typing import Optional, Dict, Any
from datetime import datetime, timezone

import requests
from pymongo import MongoClient
from app.config import settings

# ---- Config (env) ----
# SLACK_WEBHOOK_ENABLED=true|false
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
# SLACK_WEBHOOK_ROUTING='{"rule:Credit Card":"https://hooks...A","platform:trello":"https://hooks...B","severity:high":"https://hooks...C"}'
ENABLED = os.getenv("SLACK_WEBHOOK_ENABLED", "true").lower() in ("1", "true", "yes")
DEFAULT_URL = (os.getenv("SLACK_WEBHOOK_URL") or "").strip()
ROUTING_RAW = os.getenv("SLACK_WEBHOOK_ROUTING") or ""
try:
    ROUTING: Dict[str, str] = json.loads(ROUTING_RAW) if ROUTING_RAW.strip() else {}
except Exception:
    ROUTING = {}

# Mongo (used for dedupe: mark event alerted)
_mclient = MongoClient(settings.mongo_uri)
_mdb = _mclient[settings.mongo_db]
_events = _mdb.events
_events.create_index("fingerprint", unique=True)
_events.create_index([("status.slack_webhook_at", 1)])

def _choose_url(event: Dict[str, Any], override: Optional[str] = None) -> Optional[str]:
    if override:
        return override.strip()
    dets = event.get("detections") or []
    primary = (dets[0] if dets else {}) or {}
    rule = primary.get("label") or ""
    plat = (event.get("platform") or "").lower()
    sev = (event.get("severity") or "").lower()
    for key in (f"rule:{rule}", f"platform:{plat}", f"severity:{sev}"):
        if key in ROUTING and ROUTING[key]:
            return ROUTING[key].strip()
    return DEFAULT_URL or None

def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _truncate(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"

def _build_blocks(event: Dict[str, Any]) -> list[Dict[str, Any]]:
    dets = event.get("detections") or []
    primary = (dets[0] if dets else {}) or {}
    rule = primary.get("label") or "Sensitive Data"
    severity = event.get("severity", "Medium")
    plat = event.get("platform", "-")
    cont = event.get("container") or {}
    cname = cont.get("name") or cont.get("id") or "-"
    src_url = cont.get("url") or "-"
    ts = event.get("found_at")
    when = ts if isinstance(ts, str) else (ts or datetime.utcnow().replace(tzinfo=timezone.utc)).isoformat()
    fp = event.get("fingerprint") or "-"
    snippet = _truncate(event.get("snippet_redacted") or "", 850)
    author = (event.get("source_meta") or {}).get("author_name") or (event.get("source_meta") or {}).get("author_id") or "-"

    dash = settings.dashboard_base_url or "http://localhost:8501"
    dash_link = f"{dash}?fingerprint={fp}"

    header = f":rotating_light: {severity} — {rule}"
    sub = f"*{plat}* / `{_esc(cname)}`"

    return [
        {"type": "header", "text": {"type": "plain_text", "text": header[:150]}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{sub}\n*When:* `{when}`   *Who:* `{_esc(author)}`"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Snippet (redacted)*\n```{_esc(snippet)}```"}},
        {
            "type": "actions",
            "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": "View in Dashboard"}, "url": dash_link},
                {"type": "button", "text": {"type": "plain_text", "text": "View Source"}, "url": src_url},
            ],
        },
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"`fingerprint:` `{fp}`"}]},
    ]

def _post_with_retry(url: str, payload: dict) -> bool:
    """Send to webhook with simple backoff for 429/5xx."""
    tries = 0
    while True:
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                return True
            if r.status_code == 429:
                retry = int(r.headers.get("Retry-After", "1"))
                time.sleep(retry + 1)
                tries += 1
                if tries <= 3:
                    continue
            # 5xx retry a couple times
            if 500 <= r.status_code < 600 and tries < 3:
                time.sleep(1.5 * (tries + 1))
                tries += 1
                continue
            print(f"[SlackWebhook] post failed {r.status_code}: {r.text[:300]}")
            return False
        except requests.RequestException as e:
            tries += 1
            if tries > 3:
                print(f"[SlackWebhook] network error: {e}")
                return False
            time.sleep(1.5 * tries)

def send_event_alert(event: Dict[str, Any], mdb=None, webhook_url: Optional[str] = None, dedupe: bool = True) -> Optional[dict]:
    """
    Send a Slack alert via Incoming Webhook.
    - webhook_url: override destination webhook URL (useful for tests/routes).
    - dedupe: skip if we've already sent via webhook for this event.
    """
    if not ENABLED:
        return None

    # Dedupe by event status
    if dedupe:
        doc = _events.find_one({"fingerprint": event.get("fingerprint")}, {"status.slack_webhook_at": 1})
        if doc and (doc.get("status") or {}).get("slack_webhook_at"):
            return None

    url = _choose_url(event, override=webhook_url)
    if not url:
        print("[SlackWebhook] No webhook URL configured. Set SLACK_WEBHOOK_URL or SLACK_WEBHOOK_ROUTING.")
        return None

    blocks = _build_blocks(event)
    text_fallback = f"[LeakHunter] {event.get('severity','Medium')} — {(event.get('detections') or [{}])[0].get('label','Sensitive Data')}"
    payload = {"text": text_fallback, "blocks": blocks}

    ok = _post_with_retry(url, payload)
    if not ok:
        return None

    # Mark alerted
    try:
        _events.update_one(
            {"fingerprint": event.get("fingerprint")},
            {"$set": {"status.slack_webhook_at": datetime.now(tz=timezone.utc), "status.last_sync_at": datetime.now(tz=timezone.utc)}},
        )
    except Exception:
        pass

    return {"ok": True}
