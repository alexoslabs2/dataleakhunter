
from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, Any
import os, json, requests
from pymongo.collection import Collection
from app.config import settings

#AUTH_SCHEME = (settings.siem_http_auth_scheme or "bearer").lower()
#DEBUG = settings.siem_http_debug
# Prefer legacy SIEM_HTTP_* if present, else fall back to Generic exporter fields
HTTP_URL = getattr(settings, "siem_http_url", "") or getattr(settings, "generic_url", "")
AUTH_SCHEME = (getattr(settings, "siem_http_auth_scheme", None) or "bearer").lower()
TOKEN = getattr(settings, "siem_http_token", "")  # legacy token
HDR_JSON = getattr(settings, "siem_http_headers_json", "") or getattr(settings, "generic_headers_json", "")
VERIFY = bool(getattr(settings, "siem_http_verify", True))

headers = {"Content-Type": "application/json"}
if HDR_JSON:
    try:
        headers.update(json.loads(HDR_JSON))
    except Exception as e:
        print("[Exporter] ignoring invalid headers JSON:", e)

# Build Authorization only if not already provided in HDR_JSON
if TOKEN and "authorization" not in {k.lower(): v for k, v in headers.items()}:
    if AUTH_SCHEME == "bearer":
        headers["Authorization"] = f"Bearer {TOKEN}"
    elif AUTH_SCHEME == "apikey":
        headers["X-API-Key"] = TOKEN
    else:
        headers["Authorization"] = TOKEN  # raw token

# Now use HTTP_URL, headers, VERIFY in your POST calls.

def _iso_to_epoch(ts: str) -> int:
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return int(datetime.fromisoformat(ts).timestamp())
    except Exception:
        return int(datetime.utcnow().timestamp())

def _to_ecs(event: Dict[str, Any]) -> Dict[str, Any]:
    dets = event.get("detections", []) or []
    primary = (dets[0] if dets else {}) or {}
    label = primary.get("label")
    sample = primary.get("match")
    container = event.get("container", {}) or {}
    platform = event.get("platform")
    severity = event.get("severity", "Medium")
    ts = event.get("found_at") or datetime.utcnow().replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z","+00:00"))
        except Exception:
            ts = datetime.utcnow().replace(tzinfo=timezone.utc)
    ecs = {
        "@timestamp": ts.isoformat().replace("+00:00", "Z"),
        "event": {
            "kind": "alert",
            "category": ["threat", "credential"],
            "type": ["info"],
            "severity": 7 if str(severity).lower()=="high" else 5,
            "id": event.get("fingerprint"),
            "module": "leakhunter",
            "dataset": "leakhunter.detect",
            "risk_score": 50 if str(severity).lower()=="high" else 25,
        },
        "rule": {"name": label or "Sensitive Data Leak", "uuid": event.get("fingerprint")},
        "observer": {"vendor": "LeakHunter", "type": "DLP"},
        "source": {"service": {"name": platform}, "url": container.get("url")},
        "leak": {
            "source": {
                "platform": platform,
                "container": container.get("name"),
                "container_id": container.get("id"),
                "container_type": container.get("type"),
            },
            "data": {
                "labels": [d.get("label") for d in dets],
                "sample": sample,
                "snippet_redacted": event.get("snippet_redacted"),
            },
        },
        "labels": [platform, severity] + [d.get("label") for d in dets],
        "leakhunter": {"fingerprint": event.get("fingerprint")},
    }
    def _clean(d):
        if isinstance(d, dict):
            return {k:_clean(v) for k,v in d.items() if v is not None}
        if isinstance(d, list):
            return [ _clean(v) for v in d if v is not None]
        return d
    return _clean(ecs)

def _wrap_for_splunk(rec: Dict[str, Any]) -> Dict[str, Any]:
    epoch = _iso_to_epoch(rec.get("@timestamp", datetime.utcnow().isoformat()))
    return {
        "time": epoch,
        "host": settings.splunk_host or "leakhunter",
        "source": settings.splunk_source or "leakhunter",
        "sourcetype": settings.splunk_sourcetype or "_json",
        "index": settings.splunk_index,
        "event": rec,
    }

def export_events(coll: Collection, since_dt: datetime) -> Dict[str, Any]:
    cur = coll.find({"found_at": {"$gte": since_dt}}).sort("found_at", 1)
    ecs_records = [_to_ecs(e) for e in cur]
    mode = (settings.siem_export_mode or "file").lower()

    if mode == "http" and settings.siem_http_url:
        ok = 0; fail = 0
        for rec in ecs_records:
            headers = {}
            token = settings.siem_http_token
            if token:
                headers["Authorization"] = f"Splunk {token}" if AUTH_SCHEME == "splunk" else f"Bearer {token}"
            payload = _wrap_for_splunk(rec) if AUTH_SCHEME == "splunk" else rec
            try:
                r = requests.post(settings.siem_http_url, json=payload, headers=headers, timeout=15)
                if 200 <= r.status_code < 300:
                    ok += 1
                else:
                    fail += 1
                    if DEBUG:
                        print(f"[SIEM] HTTP {r.status_code} body={r.text[:500]}")
            except Exception as e:
                fail += 1
                if DEBUG:
                    print(f"[SIEM] POST error: {e}")
        return {"mode": "http", "exported": ok, "failed": fail}

    outdir = settings.siem_export_dir or "/exports"
    os.makedirs(outdir, exist_ok=True)
    fname = f"leakhunter_export_{since_dt.strftime('%Y%m%dT%H%M%S')}.ndjson"
    path = os.path.join(outdir, fname)
    with open(path, "w", encoding="utf-8") as f:
        for rec in ecs_records:
            f.write(json.dumps(rec) + "\n")
    return {"mode": "file", "path": path, "exported": len(ecs_records)}

def event_to_ecs(e: Dict[str, Any]) -> Dict[str, Any]:
    # timestamp
    ts = e.get("found_at") or e.get("@timestamp") or datetime.utcnow().isoformat() + "Z"
    platform = e.get("platform") or "unknown"
    leak_type = e.get("type") or e.get("rule") or "Sensitive Data"
    sev = (e.get("severity") or "low").lower()
    sev_map = {"low": 1, "medium": 4, "high": 7, "critical": 10}  # ECS event.severity 1..10
    sev_num = sev_map.get(sev, 1)

    # basic ECS
    ecs = {
        "@timestamp": ts,
        "event": {
            "kind": "alert",
            "category": ["threat"],
            "type": ["info"],
            "severity": sev_num,
            "module": "leakhunter",
            "dataset": "leakhunter.findings",
        },
        "rule": {"name": leak_type},
        "tags": ["leakhunter", platform.lower()],
        "message": e.get("snippet_redacted") or e.get("snippet") or "",
        "observer": {"vendor": "LeakHunter", "product": "LeakHunter", "type": "dlp"},
        "source": {
            "service": {"name": platform},
            "url": e.get("url"),
        },
        "user": {
            "id": (e.get("author") or {}).get("id") or e.get("author_id"),
            "name": (e.get("author") or {}).get("name") or e.get("author_name"),
        },
        "related": {
            "hash": [e.get("fingerprint")] if e.get("fingerprint") else [],
            "user": [ (e.get("author") or {}).get("name") or e.get("author_name") ] if (e.get("author") or e.get("author_name")) else [],
        },
        "leakhunter": {
            "platform": platform,
            "container": e.get("container_name") or e.get("container_id"),
            "container_id": e.get("container_id"),
            "team_id": (e.get("source_meta") or {}).get("team_id"),
            "channel_id": (e.get("source_meta") or {}).get("channel_id"),
        },
    }
    return ecs