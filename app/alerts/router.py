from __future__ import annotations
from typing import Dict, Any

from app.config import settings
from app.alerts.slack_webhook import send_slack_webhook  # if you use webhook
from app.alerts.teams_webhook import send_teams_webhook

_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
def _rank(s: str | None) -> int: return _SEV_RANK.get((s or "low").lower(), 1)

def notify_all(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Route alerts by severity thresholds configured in settings."""
    out: Dict[str, Any] = {}

    sev = (finding.get("severity") or "Low").lower()

    # Slack (webhook) – optional if you also have bot alerts
    if getattr(settings, "slack_webhook_enabled", False) and settings.slack_webhook_url:
        if _rank(sev) >= _rank(getattr(settings, "slack_alert_min_severity", "Low")):
            out["slack_webhook"] = send_slack_webhook(finding)

    # Teams (webhook)
    if getattr(settings, "teams_webhook_enabled", False) and settings.teams_webhook_url:
        if _rank(sev) >= _rank(getattr(settings, "teams_alert_min_severity", "Low")):
            out["teams_webhook"] = send_teams_webhook(finding)

    return out
