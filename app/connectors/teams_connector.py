import os, json, re, hashlib, html
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import urllib.request, urllib.parse
import urllib.parse as up

from pymongo import MongoClient, ASCENDING
from app.config import settings

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# --- DB ---
_client = MongoClient(settings.mongo_uri)
_mdb = _client[settings.mongo_db]
_events = _mdb.events
_cursors = _mdb.cursors
# ensure fingerprint uniqueness for dedupe
try:
    _events.create_index([("fingerprint", ASCENDING)], name="fingerprint_1", unique=True, background=True)
except Exception:
    pass

# --- Patterns loader ---
def _load_patterns() -> Dict[str, re.Pattern]:
    path = os.getenv("PATTERNS_FILE", "/app/patterns.json")
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    compiled = {}
    for label, rx in raw.items():
        flags = re.IGNORECASE | re.MULTILINE
        try:
            compiled[label] = re.compile(rx, flags)
        except re.error as e:
            print(f"[Teams] bad regex for '{label}': {e}")
    return compiled

PATTERNS = _load_patterns()

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _cursor_key(team_id: str, channel_id: str) -> str:
    return f"teams:channel:{team_id}:{channel_id}"

def _get_token() -> str:
    tenant = os.getenv("MS_TENANT_ID") or getattr(settings, "teams_tenant_id", None)
    client_id = os.getenv("MS_CLIENT_ID") or getattr(settings, "teams_client_id", None)
    secret = os.getenv("MS_CLIENT_SECRET") or getattr(settings, "teams_client_secret", None)
    if not (tenant and client_id and secret):
        raise RuntimeError("Missing MS_TENANT_ID/MS_CLIENT_ID/MS_CLIENT_SECRET")
    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode("utf-8")
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = json.loads(r.read().decode("utf-8"))
        return body["access_token"]

def _graph_get(url: str, headers: dict) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))

def _strip_html(s: str) -> str:
    # quick & safe HTML → text
    s = html.unescape(s or "")
    # remove tags
    s = re.sub(r"<(script|style)[\s\S]*?</\1>", " ", s, flags=re.IGNORECASE)
    s = re.sub(r"<[^>]+>", " ", s)
    # collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _is_team_provisioned(team_id: str, headers: dict) -> bool:
    try:
        _graph_get(f"{GRAPH_BASE}/teams/{team_id}", headers)
        return True
    except Exception as e:
        try:
            body = e.read().decode("utf-8")  # type: ignore[attr-defined]
            data = json.loads(body)
            msg = (data.get("error") or {}).get("message", "")
            code = (data.get("error") or {}).get("code", "")
            if code in ("NotFound", "Unknown") and "No threadId found" in msg:
                return False
        except Exception:
            pass
        return False

def _list_provisioned_teams(headers: dict) -> list[dict]:
    params = {
        "$select": "id,displayName,resourceProvisioningOptions",
        "$filter": "resourceProvisioningOptions/Any(x:x eq 'Team')",
    }
    url = _url(GRAPH_BASE, "/groups", params)
    data = _graph_get(url, headers)
    teams = []
    for g in data.get("value", []):
        gid = g.get("id")
        if gid and _is_team_provisioned(gid, headers):
            teams.append({"id": gid, "displayName": g.get("displayName", gid)})
    return teams


def _list_channels(team_id: str, headers: dict) -> List[dict]:
    # Avoid $top (some tenants disallow); page if needed
    url = f"{GRAPH_BASE}/teams/{team_id}/channels"
    try:
        data = _graph_get(url, headers)
        return data.get("value", [])
    except Exception as e:
        try:
            body = e.read().decode("utf-8")  # type: ignore[attr-defined]
            ed = json.loads(body)
            msg = (ed.get("error") or {}).get("message", "")
            code = (ed.get("error") or {}).get("code", "")
            if code in ("NotFound", "Unknown") and "No threadId found" in msg:
                print(f"[Teams] skip non-provisioned team={team_id}")
                return []
        except Exception:
            pass
        raise

def _list_messages(team_id: str, channel_id: str, headers: dict, limit: int = 100) -> List[dict]:
    # Fetch recent messages (limit). You can add delta later when stable in your tenant.
    url = f"{GRAPH_BASE}/teams/{team_id}/channels/{channel_id}/messages?$top={max(1, min(limit, 200))}"
    try:
        data = _graph_get(url, headers)
        return data.get("value", [])
    except Exception:
        # Some tenants reject $top; retry without it
        data = _graph_get(f"{GRAPH_BASE}/teams/{team_id}/channels/{channel_id}/messages", headers)
        return data.get("value", [])

def _fingerprint(d: dict) -> str:
    key = "|".join([
        "teams",
        d.get("type", "") or "",
        d.get("rule", "") or "",
        d.get("container_id", "") or "",
        d.get("record_id", "") or "",
        _strip_html(d.get("snippet_redacted", "") or "")[:200],
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def _redact(text: str, matches: List[re.Match]) -> str:
    # Simple redaction: replace matched spans with ****
    if not matches:
        return text[:500]
    out = text
    # replace from end to start to keep indices stable
    spans = sorted([m.span(0) for m in matches], key=lambda x: x[0], reverse=True)
    for a, b in spans[:10]:
        out = out[:a] + "****" + out[b:]
    return out[:500]

def _store_event(ev: dict) -> bool:
    ev["fingerprint"] = _fingerprint(ev)
    ev["created_at"] = _now_iso()
    try:
        _events.update_one({"fingerprint": ev["fingerprint"]}, {"$setOnInsert": ev}, upsert=True)
        return True
    except Exception as e:
        # Duplicate (already stored) or other error
        # If duplicate, modifiedCount==0 and upsertedId is None; consider not new
        return False

def _detect_and_store(text: str, meta: dict) -> int:
    new = 0
    for label, rx in PATTERNS.items():
        matches = list(rx.finditer(text))
        if not matches:
            continue
        ev = {
            "platform": "Teams",
            "source": "teams",
            "type": label,
            "severity": meta.get("severity", "Medium"),
            "found_at": _now_iso(),
            "author_id": meta.get("author_id"),
            "author_name": meta.get("author_name"),
            "container": meta.get("container"),            # e.g., "team/channel"
            "container_id": meta.get("container_id"),      # f"{team_id}/{channel_id}"
            "container_name": meta.get("container_name"),  # f"{team_name}/{channel_name}"
            "record_id": meta.get("record_id"),            # message id
            "url": meta.get("url"),
            "snippet_redacted": _redact(text, matches),
            "raw_sample": text[:500],  # optional
        }
        if _store_event(ev):
            new += 1
    return new

def scan(full: bool = False, limit_per_channel: int = 100) -> int:
    """
    Scan provisioned Teams channels for sensitive data.
    Returns number of NEW events inserted (deduped by fingerprint).
    """
    try:
        token = _get_token()
    except Exception as e:
        print(f"[Teams] token error: {e}")
        return 0

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    try:
        teams = _list_provisioned_teams(headers)
    except Exception as e:
        print(f"[Teams] list teams error: {e}")
        return 0

    total_scanned = 0
    total_new = 0

    for t in teams:
        team_id = t["id"]
        team_name = t.get("displayName", team_id)
        try:
            channels = _list_channels(team_id, headers)
        except Exception as e:
            print(f"[Teams] list_channels error team={team_id}: {e}")
            continue

        for ch in channels:
            ch_id = ch.get("id")
            ch_name = ch.get("displayName", ch_id)
            if not ch_id:
                continue

            # cursor (simple; we fetch recent N and rely on fingerprint dedupe)
            k = _cursor_key(team_id, ch_id)
            # Optional: could store last seen message id/time; here we always fetch recent N
            try:
                msgs = _list_messages(team_id, ch_id, headers, limit=limit_per_channel)
            except Exception as e:
                print(f"[Teams] list_messages error team={team_id} channel={ch_id}: {e}")
                continue

            for m in msgs:
                body = (m.get("body") or {})
                ctype = body.get("contentType", "text")
                content = body.get("content", "") or ""
                text = _strip_html(content) if ctype.lower() == "html" else content

                frm = m.get("from") or {}
                user = frm.get("user") or {}
                author_name = user.get("displayName") or frm.get("application", {}).get("displayName") or "unknown"
                author_id = user.get("id") or ""

                msg_id = m.get("id", "")
                url = f"https://teams.microsoft.com/l/message/{ch_id}/{msg_id}" if (ch_id and msg_id) else ""

                meta = {
                    "author_id": author_id,
                    "author_name": author_name,
                    "container": "team/channel",
                    "container_id": f"{team_id}/{ch_id}",
                    "container_name": f"{team_name}/{ch_name}",
                    "record_id": msg_id,
                    "url": url,
                    # You can tune severity per rule; default medium here
                    "severity": "Medium",
                }

                total_new += _detect_and_store(text, meta)
                total_scanned += 1

            # Save a lightweight cursor timestamp to indicate progress
            try:
                _cursors.update_one(
                    {"k": k},
                    {"$set": {"k": k, "ts": _now_iso()}},
                    upsert=True
                )
            except Exception:
                pass

    print(f"[Teams] scanned={total_scanned} new={total_new}")
    return total_new

def _url(base: str, path: str, params: dict | None = None) -> str:
    """
    Build a Graph URL with proper percent-encoding for query params
    (spaces, quotes, slashes in OData $filter, etc.).
    """
    if not params:
        return f"{base}{path}"
    query = up.urlencode(params, quote_via=up.quote, safe="")  # encode spaces as %20, quotes as %27
    return f"{base}{path}?{query}"

def _graph_get(url: str, headers: dict) -> dict:
    if " " in url:
        url = url.replace(" ", "%20")
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))