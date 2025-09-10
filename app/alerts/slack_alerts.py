from __future__ import annotations

import os, time, json, html
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from pymongo import MongoClient
from app.config import settings

# ---- Config (env) ----
# SLACK_ALERT_ENABLED=true|false
# SLACK_ALERT_TOKEN=  (defaults to SLACK_BOT_TOKEN)
# SLACK_ALERT_CHANNEL=#security-alerts or CXXXXXXXX
# SLACK_ALERT_ROUTING='{"rule:Credit Card":"#pci-alerts","platform:slack":"#slack-leaks","severity:high":"#urgent"}'
ENABLED = os.getenv("SLACK_ALERT_ENABLED", "true").lower() in ("1", "true", "yes")
TOKEN = os.getenv("SLACK_ALERT_TOKEN") or settings.slack_bot_token
DEFAULT_CH = os.getenv("SLACK_ALERT_CHANNEL")
ROUTING_RAW = os.getenv("SLACK_ALERT_ROUTING") or ""
try:
    ROUTING = json.loads(ROUTING_RAW) if ROUTING_RAW.strip() else {}
except Exception:
    ROUTING = {}

client: Optional[WebClient] = WebClient(token=TOKEN, timeout=30) if TOKEN else None
_channel_cache: Dict[str, str] = {}

# Mongo (used to flag alerted events)
_mclient = MongoClient(settings.mongo_uri)
_mdb = _mclient[settings.mongo_db]
_events = _mdb.events
_events.create_index("fingerprint", unique=True)
_events.create_index([("status.slack.ts", 1)])

def _resolve_channel(ch_ref: Optional[str]) -> Optional[str]:
    """Return a Slack channel ID for '#name' or already-an-ID."""
    if not ch_ref or not client:
        return None
    if ch_ref.startswith("C") or ch_ref.startswith("G"):
        return ch_ref
    name = ch_ref.lstrip("#").strip()
    if not name:
        return None
    if name in _channel_cache:
        return _channel_cache[name]
    cursor = None
    while True:
        resp = client.conversations_list(types="public_channel,private_channel", limit=200, cursor=cursor)
        for ch in resp.get("channels", []):
            if ch.get("name") == name:
                _channel_cache[name] = ch["id"]
                return ch["id"]
        cursor = (resp.get("response_metadata") or {}).get("next_cursor")
        if not cursor:
            break
    return None

def _channel_for_event(event: Dict[str, Any]) -> Optional[str]:
    """Routing precedence: rule → platform → severity → default channel."""
    dets = event.get("detections") or []
    primary = (dets[0] if dets else {}) or {}
    rule = primary.get("label") or ""
    plat = (event.get("platform") or "").lower()
    sev = (event.get("severity") or "").lower()

    for key in (f"rule:{rule}", f"platform:{plat}", f"severity:{sev}"):
        if key in ROUTING:
            cid = _resolve_channel(ROUTING[key])
            if cid:
                return cid
    return _resolve_channel(DEFAULT_CH)

def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _truncate(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"

def _post_with_retry(**kwargs) -> Dict[str, Any]:
    """Post with simple 429 backoff."""
    assert client is not None
    tries = 0
    while True:
        try:
            return client.chat_postMessage(**kwargs)
        except SlackApiError as e:
            if e.response is not None and e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", "1"))
                time.sleep(retry_after + 1)
                tries += 1
                if tries <= 3:
                    continue
            # Log and bubble up
            print(f"[SlackAlert] post error {getattr(e.response,'status_code',None)}: {getattr(e.response,'data',e)}")
            raise

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
    snippet = _truncate(event.get("snippet_redacted") or "", 900)
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

def send_event_alert(event: Dict[str, Any], mdb=None, channel: Optional[str] = None, dedupe: bool = True) -> Optional[Dict[str, Any]]:
    """
    Send a Slack alert for a detection event.
    - channel: override target (ID or #name). If None, uses routing/defaults.
    - dedupe: if True, skip if status.slack.ts already exists.
    Returns Slack response dict on success, None on no-op/failure.
    """
    if not ENABLED or not client:
        return None

    # Dedupe by event status
    if dedupe:
        doc = _events.find_one({"fingerprint": event.get("fingerprint")}, {"status.slack.ts": 1})
        if doc and ((doc.get("status") or {}).get("slack") or {}).get("ts"):
            return None

    target = _resolve_channel(channel) if channel else _channel_for_event(event)
    if not target:
        print("[SlackAlert] No target channel configured/resolved. Set SLACK_ALERT_CHANNEL or SLACK_ALERT_ROUTING.")
        return None

    blocks = _build_blocks(event)
    text_fallback = f"[LeakHunter] {event.get('severity','Medium')} — {(event.get('detections') or [{}])[0].get('label','Sensitive Data')}"

    try:
        resp = _post_with_retry(channel=target, text=text_fallback, blocks=blocks)
    except Exception:
        return None

    # Save message metadata to event
    try:
        _events.update_one(
            {"fingerprint": event.get("fingerprint")},
            {"$set": {"status.slack": {"channel": target, "ts": resp.get('ts')}, "status.last_sync_at": datetime.now(tz=timezone.utc)}},
        )
    except Exception:
        pass

    return {"ok": True, "channel": target, "ts": resp.get("ts")}
