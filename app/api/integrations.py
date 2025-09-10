
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any, Generator
import json, time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from pymongo import MongoClient

from app.config import settings
from app.integrations.schemas import to_ecs
from app.integrations.webhooks import register_webhook, delete_webhook, list_webhooks, try_deliver_to_all

router = APIRouter(prefix="/integrations", tags=["integrations"])

def require_api_key(req: Request):
    allowed = {k.strip() for k in (settings.integrations_api_keys or "").split(",") if k.strip()}
    if not allowed:
        return
    key = req.headers.get("X-API-Key")
    if not key:
        auth = req.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            key = auth.split(" ", 1)[1].strip()
    if not key or key not in allowed:
        raise HTTPException(401, "invalid or missing API key")

mdb = MongoClient(settings.mongo_uri)[settings.mongo_db]
events = mdb.events

class EventQuery(BaseModel):
    platform: Optional[str] = None
    severity: Optional[str] = None
    label: Optional[str] = None
    since: Optional[str] = None
    until: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    cursor: Optional[str] = None

def _build_mongo_query(q: EventQuery) -> Dict[str, Any]:
    query: Dict[str, Any] = {}
    if q.platform:
        query["platform"] = q.platform.lower()
    if q.severity:
        query["severity"] = {"$regex": f"^{q.severity}$", "$options": "i"}
    if q.label:
        query["detections.label"] = q.label
    time_cond = {}
    if q.since:
        try:
            time_cond["$gte"] = datetime.fromisoformat(q.since.replace("Z", "+00:00"))
        except Exception:
            pass
    if q.until:
        try:
            time_cond["$lte"] = datetime.fromisoformat(q.until.replace("Z", "+00:00"))
        except Exception:
            pass
    if time_cond:
        query["found_at"] = time_cond
    if q.cursor:
        try:
            dt = datetime.fromisoformat(q.cursor.replace("Z", "+00:00"))
            query["found_at"] = {**time_cond, "$lt": dt}
        except Exception:
            pass
    return query

def _next_cursor(doc: Dict[str, Any]) -> Optional[str]:
    dt = doc.get("found_at")
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    return None

@router.get("/events", dependencies=[Depends(require_api_key)])
def list_events(
    platform: Optional[str] = None,
    severity: Optional[str] = None,
    label: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    cursor: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
):
    q = EventQuery(platform=platform, severity=severity, label=label, since=since, until=until, cursor=cursor, limit=limit)
    mongo_q = _build_mongo_query(q)
    docs = list(events.find(mongo_q).sort("found_at", -1).limit(limit))
    ecs = [to_ecs(d) for d in docs]
    next_cur = _next_cursor(docs[-1]) if docs else None
    return {"ok": True, "count": len(ecs), "next_cursor": next_cur, "events": ecs}

@router.get("/events/{fingerprint}", dependencies=[Depends(require_api_key)])
def get_event(fingerprint: str):
    doc = events.find_one({"fingerprint": fingerprint})
    if not doc:
        raise HTTPException(404, "not found")
    return {"ok": True, "event": to_ecs(doc)}

@router.get("/events/stream", dependencies=[Depends(require_api_key)])
def stream_events(platform: Optional[str] = None, severity: Optional[str] = None, label: Optional[str] = None, since: Optional[str] = None):
    base_since = datetime.fromisoformat(since.replace("Z", "+00:00")) if since else datetime.now(tz=timezone.utc)
    def gen() -> Generator[bytes, None, None]:
        last_seen = base_since
        while True:
            q = {"found_at": {"$gt": last_seen}}
            if platform:
                q["platform"] = platform.lower()
            if severity:
                q["severity"] = {"$regex": f"^{severity}$", "$options": "i"}
            if label:
                q["detections.label"] = label
            batch = list(events.find(q).sort("found_at", 1).limit(100))
            for d in batch:
                ts = d.get("found_at")
                if isinstance(ts, datetime):
                    last_seen = ts
                data = json.dumps(to_ecs(d))
                yield f"event: leakhunter.finding\nid: {d.get('fingerprint')}\ndata: {data}\n\n".encode("utf-8")
            time.sleep(1.0)
    return StreamingResponse(gen(), media_type="text/event-stream")

class WebhookIn(BaseModel):
    url: str
    secret: Optional[str] = None
    filters: Optional[Dict[str, Any]] = None

@router.post("/webhooks", dependencies=[Depends(require_api_key)])
def create_webhook(w: WebhookIn):
    wid = register_webhook(w.url, w.secret, w.filters or {})
    return {"ok": True, "id": str(wid)}

@router.get("/webhooks", dependencies=[Depends(require_api_key)])
def get_webhooks():
    return {"ok": True, "webhooks": list_webhooks()}

@router.delete("/webhooks/{webhook_id}", dependencies=[Depends(require_api_key)])
def remove_webhook(webhook_id: str):
    ok = delete_webhook(webhook_id)
    if not ok:
        raise HTTPException(404, "not found")
    return {"ok": True}

@router.post("/webhooks/deliver/{fingerprint}", dependencies=[Depends(require_api_key)])
def deliver_once(fingerprint: str):
    doc = events.find_one({"fingerprint": fingerprint})
    if not doc:
        raise HTTPException(404, "not found")
    sent = try_deliver_to_all(doc)
    return {"ok": True, "deliveries": sent}
