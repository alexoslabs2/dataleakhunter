from __future__ import annotations

from typing import Dict, Any, List, Iterable, Optional
from datetime import datetime, timezone
import os, json, time, requests
from pathlib import Path

from pymongo import MongoClient

from app.config import settings
from app.exporters.siem_clients import (
    SplunkHECClient,
    ElasticBulkClient,
    GenericHTTPClient,
)

# --- Mongo state collection (no _id index creation; it's built-in) ---
_mdb = MongoClient(settings.mongo_uri)[settings.mongo_db]
_state = _mdb.export_state
# Optionally: _state.create_index([("updated_at", 1)])

PLATFORMS = {"Slack", "Confluence", "Jira", "Trello", "Teams"}

# ---------- cursor helpers ----------
def _get_cursor(dest: str) -> Optional[str]:
    doc = _state.find_one({"_id": f"cursor:{dest}"})
    return (doc or {}).get("value")

def _set_cursor(dest: str, cur: str):
    _state.update_one(
        {"_id": f"cursor:{dest}"},
        {"$set": {"value": cur, "updated_at": datetime.now(tz=timezone.utc)}},
        upsert=True,
    )

# ---------- integrations API paging ----------
def _fetch_page(cursor: Optional[str], limit: int = 500) -> Dict[str, Any]:
    base = (getattr(settings, "integrations_base_url", None)
            or getattr(settings, "api_base_url", "http://localhost:8000")).rstrip("/")
    url = f"{base}/integrations/events"
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    headers: Dict[str, str] = {}
    api_keys = getattr(settings, "integrations_api_keys", "") or ""
    if api_keys.strip():
        headers["X-API-Key"] = api_keys.split(",")[0].strip()
    r = requests.get(url, params=params, headers=headers, timeout=25)
    if r.status_code != 200:
        raise RuntimeError(f"Integrations API error {r.status_code}: {r.text[:300]}")
    return r.json()

def _ecs_stream(paged_events: List[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    # /integrations/events already returns ECS/CIM-aligned dicts
    for ev in paged_events:
        yield ev

# ---------- sinks / clients ----------
class _FileSink:
    """Simple NDJSON file sink for local testing/export."""
    def __init__(self, out_dir: str):
        self.out_dir = out_dir or "/exports"
        Path(self.out_dir).mkdir(parents=True, exist_ok=True)

    def send(self, ecs_events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        now = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        p = Path(self.out_dir) / f"leakhunter_{now}.ndjson"
        n = 0
        with p.open("w", encoding="utf-8") as fh:
            for ev in ecs_events:
                fh.write(json.dumps(ev, separators=(",", ":")) + "\n")
                n += 1
        return {"ok": n, "failed": 0, "dest": "file", "path": str(p)}

def _make_client(mode: str):
    m = (mode or "").lower()
    if m == "splunk":
        return SplunkHECClient(
            url=settings.splunk_hec_url,
            token=settings.splunk_hec_token,
            index=settings.splunk_hec_index or None,
            sourcetype=settings.splunk_hec_sourcetype or "leakhunter:ecs",
            source=settings.splunk_hec_source or "leakhunter",
            host=settings.splunk_hec_host or None,
            verify=bool(settings.splunk_hec_verify),
        )
    if m == "elastic":
        return ElasticBulkClient(
            url=settings.elastic_url,
            index=settings.elastic_index or "leakhunter-findings",
            api_key=settings.elastic_api_key or None,
            basic_user=settings.elastic_basic_user or None,
            basic_pass=settings.elastic_basic_pass or None,
        )
    if m == "generic":
        hdr = {}
        hj = getattr(settings, "generic_headers_json", "") or ""
        if hj:
            try:
                hdr = json.loads(hj)
            except Exception as e:
                print("[Exporter] invalid GENERIC_HEADERS_JSON; ignoring:", e)
        return GenericHTTPClient(
            url=settings.generic_url,
            headers=hdr,
            ndjson=bool(getattr(settings, "generic_ndjson", False)),
        )
    if m == "file":
        # Support legacy knobs too
        outdir = getattr(settings, "siem_export_dir", "/exports") or "/exports"
        return _FileSink(outdir)
    raise RuntimeError(f"Unknown EXPORT_MODE '{mode}' (expected splunk|elastic|generic|file)")

# ---------- public entry ----------
def run_export(mode: str | None = None, page_limit: int = 500) -> Dict[str, Any]:
    """
    Pull pages from /integrations/events and forward to chosen sink.
    Cursor is persisted per-mode in Mongo (export_state collection).
    """
    # prefer explicit arg, else settings.export_mode, else legacy siem_export_mode
    mode = (mode or getattr(settings, "export_mode", None) or getattr(settings, "siem_export_mode", "file")).lower()
    client = _make_client(mode)

    cur = _get_cursor(mode)
    total_ok = 0
    total_fail = 0
    pages = 0

    while True:
        data = _fetch_page(cur, limit=page_limit)
        evs = data.get("events", []) or []
        next_cur = data.get("next_cursor")
        if not evs:
            break

        res = client.send(_ecs_stream(evs))
        try:
            total_ok += int(res.get("ok") or 0)
            total_fail += int(res.get("failed") or 0)
        except Exception:
            pass
        pages += 1

        if next_cur:
            cur = next_cur
            _set_cursor(mode, cur)
        else:
            break

        time.sleep(0.2)

    return {"ok": True, "mode": mode, "sent": total_ok, "failed": total_fail, "pages": pages, "cursor": cur}

def _iter_events_since(db, since_iso: str, limit: int = 1000):
    q = {"@ts": {"$gt": since_iso}} if since_iso else {}
    # se usar campo platform, pode restringir aqui:
    # q["platform"] = {"$in": list(PLATFORMS)}
    return db["events"].find(q).sort("found_at", 1).limit(limit)