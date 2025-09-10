
from __future__ import annotations
from typing import Dict, Any, List
from datetime import datetime, timezone

def _iso(dt):
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    return dt

def to_ecs(ev: Dict[str, Any]) -> Dict[str, Any]:
    dets: List[Dict[str, Any]] = ev.get("detections") or []
    primary = (dets[0] if dets else {}) or {}
    cont = ev.get("container") or {}
    meta = ev.get("source_meta") or {}
    return {
        "timestamp": _iso(ev.get("found_at")),
        "event": {
            "id": ev.get("fingerprint"),
            "kind": "alert",
            "category": ["intrusion_detection", "data_leak"],
            "type": ["info"],
            "severity": {"low": 2, "medium": 5, "high": 8}.get((ev.get("severity") or "medium").lower(), 5),
            "created": _iso(ev.get("found_at")),
            "dataset": "leakhunter.findings",
            "reason": primary.get("label") or "Sensitive Data",
        },
        "rule": {"name": primary.get("label") or "Sensitive Data", "id": primary.get("id") or None},
        "observer": {"vendor": "LeakHunter", "type": "DLP"},
        "tags": list({primary.get("label") or "sensitive", ev.get("platform") or ""} - {""}),
        "source": {"service": {"name": ev.get("platform")}, "user": {"name": meta.get("author_name") or meta.get("author_id")}, "url": cont.get("url")},
        "container": {"id": cont.get("id"), "name": cont.get("name"), "type": cont.get("type")},
        "leakhunter": {"platform": ev.get("platform"), "severity": ev.get("severity"), "detections": dets, "snippet_redacted": ev.get("snippet_redacted"), "meta": meta},
    }
