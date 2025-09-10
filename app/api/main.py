from fastapi import FastAPI, HTTPException, Query
import os
import threading
import time
import hmac

from app.connectors import slack_connector, jira_connector, confluence_connector, trello_connector, teams_connector
from app.scheduler import scheduler, load_jobs_from_db, ensure_default_schedule, run_scan
from pymongo import MongoClient
from pydantic import BaseModel
from typing import Optional
from app.config import settings
from datetime import datetime, timedelta
from app.exporter import export_events
from app.workflow import jira_create, glpi_create, servicenow_create
from app.api import integrations
from app.jobs.exporter_job import run_export, _get_cursor
from fastapi import Header

# --- DB setup ---
client = MongoClient(settings.mongo_uri)
mdb = client[settings.mongo_db]
sched_coll = mdb.scheduler

# --- App ---
app = FastAPI()
app.include_router(integrations.router)  # keep your existing integrations router

# --- Helpers ---
def _cursor(prefix: str) -> Optional[str]:
    """
    Best-effort lookup of the most recent cursor timestamp/delta for a connector.
    Looks in the 'cursors' collection by key prefix (e.g., 'slack', 'teams').
    """
    try:
        doc = mdb.cursors.find_one({"k": {"$regex": f"^{prefix}"}}, sort=[("_id", -1)])
        if not doc:
            return None
        # Prefer a human-ish timestamp if present, else the delta link as evidence
        return doc.get("ts") or doc.get("delta")
    except Exception:
        return None

# --- Lifecycle ---
@app.on_event("startup")
def _startup():
    ensure_default_schedule()
    load_jobs_from_db()
    try:
        scheduler.start()
    except Exception:
        pass

@app.on_event("shutdown")
def _shutdown():
    try:
        scheduler.shutdown(wait=False)
    except Exception:
        pass

# --- Health ---
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/healthz")
def healthz():
    return {"ok": True}

# --- Triggers ---
@app.post("/trigger/{connector}")
def trigger(connector: str, full: bool = Query(False)):
    if connector == "slack":
        new = slack_connector.scan()
    elif connector == "jira":
        new = jira_connector.scan()
    elif connector == "confluence":
        new = confluence_connector.scan()
    elif connector == "trello":
        new = trello_connector.scan(full=full)
    elif connector == "teams":
        new = teams_connector.scan()
    else:
        return {"error": "unknown connector"}
    return {"ok": True, "new": int(new) if isinstance(new, int) else new}

@app.post("/trigger/teams")
def trigger_teams():
    return teams_connector.scan()

# --- Scheduler API ---
class ScheduleModel(BaseModel):
    connector: str = "all"
    frequency: str
    time: str = "02:00"
    timezone: str = "UTC"
    day_of_week: Optional[str] = None
    day_of_month: Optional[int] = None
    enabled: bool = True

@app.get("/schedule")
def get_schedule():
    return [{
        "_id": str(doc.get("_id")),
        "connector": doc.get("connector", "all"),
        "frequency": doc.get("frequency", "daily"),
        "time": doc.get("time", "02:00"),
        "timezone": doc.get("timezone", "UTC"),
        "day_of_week": doc.get("day_of_week"),
        "day_of_month": doc.get("day_of_month"),
        "enabled": doc.get("enabled", True),
    } for doc in sched_coll.find().sort("_id", 1)]

@app.post("/schedule")
def create_schedule(cfg: ScheduleModel):
    doc = cfg.model_dump()
    ins = sched_coll.insert_one(doc)
    load_jobs_from_db()
    return {"ok": True, "id": str(ins.inserted_id)}

@app.put("/schedule/{id}")
def update_schedule(id: str, cfg: ScheduleModel):
    from bson import ObjectId
    doc = cfg.model_dump()
    sched_coll.update_one({"_id": ObjectId(id)}, {"$set": doc})
    load_jobs_from_db()
    return {"ok": True, "id": id}

@app.delete("/schedule/{id}")
def delete_schedule(id: str):
    from bson import ObjectId
    sched_coll.delete_one({"_id": ObjectId(id)})
    load_jobs_from_db()
    return {"ok": True, "id": id}

@app.post("/schedule/reload")
def schedule_reload():
    load_jobs_from_db()
    return {"ok": True}

@app.post("/schedule/run-now")
def schedule_run_now(connector: str = "all"):
    # run_scan expects a list[str] or None. Normalize here.
    sources = None if connector == "all" else [connector]
    res = run_scan(sources)
    return {"ok": True, "result": res}

# --- Export API ---
@app.post("/export/run")
def export_run(since_days: int = Query(7, ge=0, le=365)):
    since = datetime.utcnow() - timedelta(days=since_days)
    res = export_events(mdb.events, since)
    return {"ok": True, **res, "since": since.isoformat()}

@app.get("/exports/cursor")
def exports_cursor(mode: str = Query(default="splunk")):
    return {"mode": mode, "cursor": _get_cursor(mode)}

@app.post("/exports/run")
def exports_run(mode: str = Query(default="splunk"), limit: int = Query(default=500, ge=1, le=1000)):
    return run_export(mode=mode, page_limit=limit)
