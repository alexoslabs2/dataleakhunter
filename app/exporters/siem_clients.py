from __future__ import annotations
from typing import Iterable, Dict, Any, Optional, List
from datetime import datetime, timezone
import base64, json, time
import requests

def _epoch(ts: str | datetime | None) -> float:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.timestamp()
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            pass
    return time.time()

class SplunkHECClient:
    def __init__(self, url: str, token: str, index: Optional[str] = None,
                 sourcetype: Optional[str] = "leakhunter:ecs",
                 source: Optional[str] = "leakhunter", host: Optional[str] = None,
                 verify: bool = True, timeout: int = 15):
        self.url = url.rstrip("/") + "/services/collector/event"
        self.hdr = {"Authorization": f"Splunk {token}"}
        self.index = index
        self.sourcetype = sourcetype
        self.source = source
        self.host = host
        self.verify = verify
        self.timeout = timeout

    def send(self, ecs_events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        # HEC accepts one JSON per request or batched NDJSON (one JSON per line).
        # We'll send in chunks of ~500 events (safe default).
        ok = 0; fail = 0
        batch: List[str] = []
        def flush():
            nonlocal ok, fail, batch
            if not batch: return
            data = ("\n".join(batch)).encode("utf-8")
            r = requests.post(self.url, data=data, headers=self.hdr,
                              verify=self.verify, timeout=self.timeout)
            if r.status_code == 200:
                ok += len(batch)
            else:
                fail += len(batch)
                print(f"[SplunkHEC] HTTP {r.status_code}: {r.text[:300]}")
            batch = []
        for ev in ecs_events:
            payload = {
                "time": _epoch(ev.get("timestamp")),
                "event": ev,
            }
            if self.index: payload["index"] = self.index
            if self.sourcetype: payload["sourcetype"] = self.sourcetype
            if self.source: payload["source"] = self.source
            if self.host: payload["host"] = self.host
            batch.append(json.dumps(payload, separators=(",", ":")))
            if len(batch) >= 500:
                flush()
        flush()
        return {"ok": ok, "failed": fail, "dest": "splunk"}

class ElasticBulkClient:
    def __init__(self, url: str, index: str,
                 api_key: Optional[str] = None,
                 basic_user: Optional[str] = None,
                 basic_pass: Optional[str] = None,
                 verify: bool = True, timeout: int = 15):
        self.url = url.rstrip("/") + "/_bulk"
        self.index = index
        self.verify = verify
        self.timeout = timeout
        hdr = {"Content-Type": "application/x-ndjson"}
        if api_key:
            hdr["Authorization"] = "ApiKey " + api_key
        elif basic_user is not None and basic_pass is not None:
            tok = base64.b64encode(f"{basic_user}:{basic_pass}".encode()).decode()
            hdr["Authorization"] = "Basic " + tok
        self.hdr = hdr

    def send(self, ecs_events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        ok = 0; fail = 0
        lines: List[str] = []
        def flush():
            nonlocal ok, fail, lines
            if not lines: return
            body = ("\n".join(lines) + "\n").encode("utf-8")
            r = requests.post(self.url, data=body, headers=self.hdr,
                              verify=self.verify, timeout=self.timeout)
            if r.status_code >= 200 and r.status_code < 300 and not (r.json().get("errors")):
                ok += len(lines)//2
            else:
                fail += len(lines)//2
                try:
                    print(f"[ElasticBulk] HTTP {r.status_code}, errors={r.json().get('errors')}")
                except Exception:
                    print(f"[ElasticBulk] HTTP {r.status_code}: {r.text[:300]}")
            lines = []
        for ev in ecs_events:
            # Ensure @timestamp for Kibana
            if "@timestamp" not in ev:
                ev["@timestamp"] = ev.get("timestamp")
            lines.append(json.dumps({"index": {"_index": self.index}}, separators=(",", ":")))
            lines.append(json.dumps(ev, separators=(",", ":")))
            if len(lines) >= 1000:  # 500 docs
                flush()
        flush()
        return {"ok": ok, "failed": fail, "dest": "elastic"}

class GenericHTTPClient:
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None,
                 verify: bool = True, timeout: int = 15, ndjson: bool = False):
        self.url = url
        self.hdr = {"Content-Type": "application/json"}
        if headers: self.hdr.update(headers)
        self.verify = verify
        self.timeout = timeout
        self.ndjson = ndjson

    def send(self, ecs_events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        if self.ndjson:
            data = "\n".join(json.dumps(e, separators=(",", ":")) for e in ecs_events).encode("utf-8")
            r = requests.post(self.url, data=data, headers=self.hdr,
                              verify=self.verify, timeout=self.timeout)
            ok = 0 if r.status_code >= 300 else "unknown"
            return {"ok": ok, "failed": 0 if r.status_code < 300 else "all", "status": r.status_code, "dest": "generic-ndjson"}
        # default: one POST containing array
        arr = list(ecs_events)
        r = requests.post(self.url, json=arr, headers=self.hdr,
                          verify=self.verify, timeout=self.timeout)
        return {"ok": 0 if r.status_code >= 300 else len(arr), "failed": 0 if r.status_code < 300 else len(arr),
                "status": r.status_code, "dest": "generic-json"}
