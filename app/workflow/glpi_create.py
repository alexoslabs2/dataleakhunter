from __future__ import annotations
import requests
from app.config import settings

import os
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.config import settings

def _severity_rank(s: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get((s or "medium").lower(), 2)


def _norm_url(u: Optional[str]) -> Optional[str]:
    if not u:
        return None
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u.rstrip("/")


def _eligible(event: Dict[str, Any]) -> bool:
    """Decide if we should create a GLPI ticket for this event."""
    if not settings.glpi_create_on_detect:
        return False

    base = _norm_url(settings.glpi_url)
    if not base or not settings.glpi_app_token or not settings.glpi_user_token:
        return False

    # Avoid accidental localhost inside containers unless explicitly permitted
    host = urlparse(base).hostname or ""
    if host in ("localhost", "127.0.0.1") and os.getenv("GLPI_ALLOW_LOCALHOST", "0") != "1":
        print("[GLPI] Skipping: GLPI_URL points to localhost; set GLPI_ALLOW_LOCALHOST=1 to permit.")
        return False

    return _severity_rank(event.get("severity", "Medium")) >= _severity_rank(settings.glpi_min_severity)


def _start_session(base: str) -> Optional[str]:
    """Open a GLPI API session and return the session token."""
    url = f"{base}/apirest.php/initSession"
    headers = {"App-Token": settings.glpi_app_token, "Content-Type": "application/json"}
    try:
        r = requests.post(url, json={"user_token": settings.glpi_user_token}, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"[GLPI] initSession network error: {e}")
        return None

    if r.status_code != 200:
        print(f"[GLPI] initSession failed {r.status_code}: {r.text[:500]}")
        return None

    try:
        return (r.json() or {}).get("session_token")
    except Exception:
        print(f"[GLPI] initSession: invalid JSON: {r.text[:500]}")
        return None


def _end_session(base: str, session_token: str) -> None:
    """Close a GLPI API session; best-effort."""
    try:
        url = f"{base}/apirest.php/killSession"
        headers = {"App-Token": settings.glpi_app_token, "Session-Token": session_token}
        requests.post(url, headers=headers, timeout=5)
    except Exception:
        pass


def _prio_from_severity(sev: str) -> int:
    # GLPI priorities are typically 1..5; map Low/Medium/High
    return {"low": 2, "medium": 3, "high": 5}.get((sev or "medium").lower(), 3)


def create_ticket_for_event(event: Dict[str, Any], mdb) -> Optional[int]:
    """
    Create a GLPI Ticket for a detection event.
    Returns ticket ID on success, None otherwise.
    """
    if not _eligible(event):
        return None

    # Idempotency: if we already have a GLPI ID, return it
    if event.get("status", {}).get("glpi_id"):
        return event["status"]["glpi_id"]

    base = _norm_url(settings.glpi_url)
    session = _start_session(base)
    if not session:
        return None

    try:
        dets = event.get("detections", []) or []
        primary = (dets[0] if dets else {}) or {}
        type_ = primary.get("label", "Sensitive Data")

        platform = event.get("platform", "-")
        container = event.get("container") or {}
        container_name = container.get("name") or container.get("id") or "-"
        url_src = container.get("url") or "-"

        sev = event.get("severity", "Medium")
        prio = _prio_from_severity(sev)

        snippet = (event.get("snippet_redacted") or "")[:800]
        fp = event.get("fingerprint")
        dash = settings.dashboard_base_url or "http://localhost:8501"
        dash_link = f"{dash}?fingerprint={fp}"

        summary = f"[DLH] {type_} in {platform}/{container_name}"
        content = (
            "Found sensitive data.\n\n"
            f"Platform: {platform}\n"
            f"Container: {container_name}\n"
            f"URL: {url_src}\n"
            f"Severity: {sev}\n"
            f"Fingerprint: {fp}\n\n"
            "Snippet (redacted):\n"
            f"{snippet}\n\n"
            f"Dashboard: {dash_link}\n"
        )

        payload = {"name": summary, "content": content, "priority": prio}
        if settings.glpi_entity_id:
            try:
                payload["entities_id"] = int(settings.glpi_entity_id)
            except Exception:
                pass

        # ---- Correct GLPI format: wrap object in {"input": [ ... ]} ----
        hdr = {
            "App-Token": settings.glpi_app_token,
            "Session-Token": session,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = {"input": [payload]}
        r = requests.post(f"{base}/apirest.php/Ticket", json=body, headers=hdr, timeout=30)
        if r.status_code not in (200, 201):
            print(f"[GLPI] create failed {r.status_code}: {r.text[:500]}")
            return None

        # Parse ticket id from common GLPI response shapes
        tid: Optional[int] = None
        try:
            data = r.json() or {}
            if isinstance(data, dict):
                tid = data.get("id")
                if not tid:
                    for key in ("added", "items", "result", "data"):
                        v = data.get(key)
                        if isinstance(v, list) and v:
                            first = v[0]
                            if isinstance(first, dict) and first.get("id"):
                                tid = first.get("id")
                                break
        except Exception:
            pass

        if not tid:
            print(f"[GLPI] create succeeded but could not parse ticket id. Raw: {r.text[:500]}")
            return None

        # Persist linkage
        mdb.events.update_one(
            {"fingerprint": event["fingerprint"]},
            {"$set": {"status.glpi_id": tid, "status.last_sync_at": datetime.now(tz=timezone.utc)}},
        )
        return tid

    finally:
        _end_session(base, session)
