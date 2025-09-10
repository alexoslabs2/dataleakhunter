
from __future__ import annotations
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import requests, json, hmac, hashlib
from bson import ObjectId
from pymongo import MongoClient
from app.config import settings
from app.integrations.schemas import to_ecs

_mdb = MongoClient(settings.mongo_uri)[settings.mongo_db]
_webhooks = _mdb.integrations_webhooks
_deliveries = _mdb.integrations_deliveries
_webhooks.create_index([("enabled", 1)])
_webhooks.create_index([("created_at", 1)])
_deliveries.create_index([("event_fingerprint", 1)])
_deliveries.create_index([("webhook_id", 1), ("status", 1), ("created_at", 1)])

def register_webhook(url: str, secret: Optional[str], filters: Dict[str, Any]):
    doc = {"url": url.strip(), "secret": (secret or "").strip(), "filters": filters or {}, "enabled": True, "created_at": datetime.now(tz=timezone.utc)}
    return _webhooks.insert_one(doc).inserted_id

def delete_webhook(webhook_id: str) -> bool:
    try: oid = ObjectId(webhook_id)
    except Exception: return False
    return _webhooks.delete_one({"_id": oid}).deleted_count > 0

def list_webhooks() -> List[Dict[str, Any]]:
    return [{"id": str(w["_id"]), "url": w["url"], "enabled": bool(w.get("enabled", True)), "filters": w.get("filters") or {}} for w in _webhooks.find({}).sort("created_at",-1)]

def match_filters(event: Dict[str, Any], filters: Dict[str, Any]) -> bool:
    if not filters: return True
    plat = (event.get("platform") or "").lower()
    sev = (event.get("severity") or "").lower()
    labels = [d.get("label") for d in (event.get("detections") or []) if d.get("label")]
    if "platform" in filters and (filters["platform"] or "").lower() != plat: return False
    if "severity" in filters and (filters["severity"] or "").lower() != sev: return False
    if "labels" in filters:
        want = set([str(x) for x in (filters["labels"] or [])])
        if not (want & set(labels)): return False
    return True

def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

def _deliver_one(event: Dict[str, Any], w: Dict[str, Any]) -> Dict[str, Any]:
    body = json.dumps(to_ecs(event)).encode("utf-8")
    headers = {"Content-Type":"application/json","X-LeakHunter-Event":"finding","X-LeakHunter-Fingerprint":str(event.get("fingerprint"))}
    if w.get("secret"): headers["X-LeakHunter-Signature"] = _sign(w["secret"], body)
    try:
        r = requests.post(w["url"], data=body, headers=headers, timeout=10)
        ok = 200 <= r.status_code < 300
        _deliveries.insert_one({"webhook_id": w["_id"], "url": w["url"], "event_fingerprint": event.get("fingerprint"), "status": "sent" if ok else "failed", "http_status": r.status_code, "response": r.text[:500], "created_at": datetime.now(tz=timezone.utc)})
        return {"ok": ok, "status": r.status_code}
    except Exception as e:
        _deliveries.insert_one({"webhook_id": w["_id"], "url": w["url"], "event_fingerprint": event.get("fingerprint"), "status": "error", "error": str(e)[:300], "created_at": datetime.now(tz=timezone.utc)})
        return {"ok": False, "error": str(e)}

def try_deliver_to_all(event: Dict[str, Any]):
    out = []
    for w in _webhooks.find({"enabled": True}):
        if match_filters(event, w.get("filters") or {}):
            out.append(_deliver_one(event, w))
    return out
