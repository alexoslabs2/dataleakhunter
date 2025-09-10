
from __future__ import annotations
from typing import Dict, Any
from zoneinfo import ZoneInfo
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from pymongo import MongoClient
from .config import settings
from .connectors import slack_connector, jira_connector, confluence_connector, trello_connector, teams_connector

client = MongoClient(settings.mongo_uri)
db = client[settings.mongo_db]
coll = db.scheduler

scheduler = BackgroundScheduler(timezone=ZoneInfo('UTC'))

def run_scan(connector: str = "all"):
    def safe_call(fn):
        try:
            return fn()
        except Exception as e:
            print(f"[Scheduler] Connector error: {e}")
            return 0

    if connector == "slack":
        return safe_call(slack_connector.scan)
    if connector == "jira":
        return safe_call(jira_connector.scan)
    if connector == "confluence":
        return safe_call(confluence_connector.scan)
    if connector == "trello":
        return safe_call(trello_connector.scan)
    if connector == "teams":
        return safe_call(teams_connector.scan)
    return {
        "slack": safe_call(slack_connector.scan),
        "jira": safe_call(jira_connector.scan),
        "confluence": safe_call(confluence_connector.scan),
        "trello": safe_call(trello_connector.scan),
        "teams": safe_call(teams_connector.scan)
    }

def _job_id(cfg: Dict[str, Any]) -> str:
    return f"{cfg.get('connector','all')}-{cfg['frequency']}-{str(cfg.get('_id','new'))}"

def load_jobs_from_db():
    for j in scheduler.get_jobs():
        scheduler.remove_job(j.id)
    for cfg in coll.find({"enabled": True}):
        tz = ZoneInfo(cfg.get("timezone", "UTC"))
        freq = cfg.get("frequency", "daily")
        connector = cfg.get("connector", "all")
        hm = (cfg.get("time") or "02:00").split(":")
        hour = int(hm[0]); minute = int(hm[1]) if len(hm) > 1 else 0
        if freq == "daily":
            trig = CronTrigger(hour=hour, minute=minute, timezone=tz)
        elif freq == "weekly":
            dow = cfg.get("day_of_week", "mon")
            trig = CronTrigger(day_of_week=dow, hour=hour, minute=minute, timezone=tz)
        elif freq == "monthly":
            dom = int(cfg.get("day_of_month", 1))
            trig = CronTrigger(day=dom, hour=hour, minute=minute, timezone=tz)
        else:
            continue
        scheduler.add_job(run_scan, trig, args=[connector], id=_job_id(cfg), replace_existing=True)

def ensure_default_schedule():
    if coll.count_documents({}) == 0:
        coll.insert_one({
            "connector": "all",
            "frequency": "daily",
            "time": "02:00",
            "timezone": "UTC",
            "enabled": True
        })
