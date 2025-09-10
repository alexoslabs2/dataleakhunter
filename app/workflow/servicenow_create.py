
from __future__ import annotations
import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.config import settings

def _severity_rank(s: str) -> int:
    if not s: return 0
    return {"low":1, "medium":2, "high":3}.get(s.lower(), 2)

def _eligible(event: Dict[str, Any]) -> bool:
    if not settings.snow_create_on_detect:
        return False
    needed = [settings.snow_instance_url, settings.snow_username, settings.snow_password]
    if not all(needed):
        return False
    return _severity_rank(event.get("severity","Medium")) >= _severity_rank(settings.snow_min_severity)

def _urgency_from_severity(sev: str) -> str:
    return {"high":"1", "medium":"2", "low":"3"}.get((sev or "medium").lower(), "2")

def create_ticket_for_event(event: Dict[str, Any], mdb) -> Optional[str]:
    if not _eligible(event):
        return None
    if event.get("status",{}).get("snow_sys_id"):
        return event["status"]["snow_sys_id"]

    dets = event.get("detections", []) or []
    primary = (dets[0] if dets else {}) or {}
    type_ = primary.get("label", "Sensitive Data")
    platform = event.get("platform","-")
    container = event.get("container") or {}
    container_name = container.get("name") or container.get("id") or "-"
    url = container.get("url") or "-"
    sev = event.get("severity","Medium")
    urgency = _urgency_from_severity(sev)
    snippet = (event.get("snippet_redacted") or "")[:800]
    fp = event.get("fingerprint")
    dash = settings.dashboard_base_url or "http://localhost:8501"
    dash_link = f"{dash}?fingerprint={fp}"
    summary = f"[DLH] {type_} in {platform}/{container_name}"

    payload = {
        "short_description": summary,
        "description": f"Sensitive data detected on {platform}/{container_name}\nURL: {url}\nSeverity: {sev}\nFingerprint: {fp}\n\nSnippet (redacted):\n{snippet}\n\nDashboard: {dash_link}",
        "category": "security",
        "subcategory": "data_leak",
        "urgency": urgency,
    }
    if settings.snow_assignment_group:
        payload["assignment_group"] = settings.snow_assignment_group
    if settings.snow_cmdb_ci:
        payload["cmdb_ci"] = settings.snow_cmdb_ci

    url_api = f"{settings.snow_instance_url.rstrip('/')}/api/now/table/{settings.snow_table}"
    r = requests.post(url_api, auth=(settings.snow_username, settings.snow_password), json=payload, timeout=30)
    if r.status_code not in (200,201):
        try:
            txt = r.text[:400]
        except Exception:
            txt = str(r.status_code)
        print(f"[ServiceNow] create failed {r.status_code}: {txt}")
        return None
    res = r.json().get("result") or {}
    sys_id = res.get("sys_id")
    if sys_id:
        mdb.events.update_one({"fingerprint": event["fingerprint"]},
                              {"$set": {"status.snow_sys_id": sys_id, "status.last_sync_at": datetime.now(tz=timezone.utc)}})
    return sys_id
