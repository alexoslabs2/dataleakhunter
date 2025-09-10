
from datetime import datetime, timezone
from typing import List, Dict, Any
from .utils import sha256, redact

def make_event(platform: str,
               container: dict,
               text: str,
               detections: List[Dict[str, str]],
               source_meta: Dict[str, Any]) -> dict:
    matches = sorted({d.get("match","") for d in detections if d.get("match")})
    pointer = str(source_meta.get("pointer", ""))
    fp_basis = f"{platform}|{container.get('id')}|{pointer}|{','.join(matches)}"
    fingerprint = sha256(fp_basis)
    snippet = text[:4000]
    snippet_redacted = redact(snippet, matches)
    severity = "High" if any(d.get("label","").lower().startswith(("password","private","api","credit")) for d in detections) else "Medium"
    ts = datetime.utcnow().replace(tzinfo=timezone.utc)
    return {
        "fingerprint": fingerprint,
        "platform": platform,
        "container": container,
        "found_at": ts,
        "severity": severity,
        "detections": detections,
        "snippet_redacted": snippet_redacted,
        "status": {"state": "new", "jira_key": None, "glpi_id": None, "snow_sys_id": None, "last_sync_at": None},
        "source_meta": source_meta,
    }
