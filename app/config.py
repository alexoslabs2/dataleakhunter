from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


# Try Pydantic v2 (pydantic-settings); fallback to v1; fallback to env shim
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict  # v2
    _MODE = "pydantic-v2"
except Exception:
    try:
        from pydantic import BaseSettings  # v1
        SettingsConfigDict = None  # type: ignore
        _MODE = "pydantic-v1"
    except Exception:
        BaseSettings = object  # type: ignore
        SettingsConfigDict = None  # type: ignore
        _MODE = "env-shim"

class _SettingsBase(BaseSettings):  # type: ignore
    # --- Core DB / URLs ---
    mongo_uri: str = "mongodb://mongo:27017"
    mongo_db: str = "dataleakhunter"

    # Base URLs (both kept to “keep the existing”)
    api_base_url: str = "http://localhost:8000"
    integrations_base_url: str = "http://localhost:8000"

    # /integrations API auth (comma-separated API keys; empty disables auth)
    integrations_api_keys: str = ""

    # --- Connectors ---
    slack_bot_token: str = ""
    jira_server: str = ""
    jira_username: str = ""
    jira_api_token: str = ""
    confluence_server: str = ""
    trello_key: str = ""
    trello_token: str = ""

    # --- Ticket creation policy (legacy names preserved) ---
    jira_default_project: str = ""
    jira_issue_type: str = "Task"
    jira_create_on_detect: bool = False
    jira_min_severity: str = "Low"

    glpi_url: str = ""
    glpi_app_token: str = ""
    glpi_user_token: str = ""
    glpi_entity_id: int = ""
    glpi_create_on_detect: bool = False
    glpi_min_severity: str = "High"

    # --- Slack alerts & webhooks ---
    slack_alert_enabled: bool = False
    slack_alert_token: str = ""
    slack_alert_channel: str = ""
    slack_alert_routing: str = ""
    slack_webhook_enabled: bool = False
    slack_webhook_url: str = ""
    slack_webhook_routing: str = ""

    # --- Export / SIEM (new + legacy names) ---
    export_mode: str = "splunk"         # splunk | elastic | generic | file
    siem_export_mode: str = "file"
    siem_export_dir: str = "/exports"

    # LEGACY HTTP SIEM fields (missing in your crash)
    siem_http_url: str = ""             # e.g., https://example/ingest
    siem_http_auth_scheme: str = "bearer"  # bearer | apikey | token
    siem_http_token: str = ""           # token value
    siem_http_headers_json: str = ""    # extra headers as JSON
    siem_http_verify: bool = True
   
    admin_token: str | None = None 
   
# Concrete settings per mode
if _MODE == "pydantic-v2":
    class Settings(_SettingsBase):  # type: ignore
        model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")  # type: ignore
    settings = Settings()
elif _MODE == "pydantic-v1":
    class Settings(_SettingsBase):  # type: ignore
        class Config:
            env_file = ".env"
            case_sensitive = False
            extra = "ignore"
    settings = Settings()
else:
    # Env-only shim (no pydantic). Tolerant to missing vars.
    import os
    def _getbool(name: str, default: bool) -> bool:
        v = os.getenv(name)
        return default if v is None else str(v).strip().lower() in ("1","true","yes","y","on")
    class Settings:  # pragma: no cover
        def __init__(self):
            g=os.getenv
            self.mongo_uri=g("MONGO_URI","mongodb://mongo:27017"); self.mongo_db=g("MONGO_DB","leakhunter")
            self.api_base_url=g("API_BASE_URL","http://localhost:8000")
            self.integrations_base_url=g("INTEGRATIONS_BASE_URL",self.api_base_url)
            self.integrations_api_keys=g("INTEGRATIONS_API_KEYS","")
            self.slack_bot_token=g("SLACK_BOT_TOKEN","")
            self.jira_server=g("JIRA_SERVER",""); self.jira_username=g("JIRA_USERNAME",""); self.jira_api_token=g("JIRA_API_TOKEN","")
            self.confluence_server=g("CONFLUENCE_SERVER",""); self.trello_key=g("TRELLO_KEY",""); self.trello_token=g("TRELLO_TOKEN","")
            self.jira_default_project=g("JIRA_DEFAULT_PROJECT",""); self.jira_issue_type=g("JIRA_ISSUE_TYPE","Task")
            self.jira_create_on_detect=_getbool("JIRA_CREATE_ON_DETECT",False); self.jira_min_severity=g("JIRA_MIN_SEVERITY","Low")
            self.glpi_url=g("GLPI_URL",""); self.glpi_app_token=g("GLPI_APP_TOKEN",""); self.glpi_user_token=g("GLPI_USER_TOKEN","")
            self.glpi_create_on_detect=_getbool("GLPI_CREATE_ON_DETECT",False); self.glpi_min_severity=g("GLPI_MIN_SEVERITY","High")
            self.slack_alert_enabled=_getbool("SLACK_ALERT_ENABLED",False); self.slack_alert_token=g("SLACK_ALERT_TOKEN","")
            self.slack_alert_channel=g("SLACK_ALERT_CHANNEL",""); self.slack_alert_routing=g("SLACK_ALERT_ROUTING","")
            self.slack_webhook_enabled=_getbool("SLACK_WEBHOOK_ENABLED",False); self.slack_webhook_url=g("SLACK_WEBHOOK_URL",""); self.slack_webhook_routing=g("SLACK_WEBHOOK_ROUTING","")
            self.export_mode=g("EXPORT_MODE","splunk"); self.siem_export_mode=g("SIEM_EXPORT_MODE","file"); self.siem_export_dir=g("SIEM_EXPORT_DIR","/exports")

            # Microsoft Graph (app-only)
            self.ms_tenant_id=g("MS_TENANT_ID","")
            self.ms_client_id=g("MS_CLIENT_ID","")
            self.ms_client_secret=g("MS_CLIENT_SECRET","")
            self.teams_include_chats=_getbool("TEAMS_INCLUDE_CHATS",False)
            self.teams_page_size=g("TEAMS_PAGE_SIZE","50")
            self.teams_max_pages=g("TEAMS_MAX_PAGES","10")
            self.teams_full_on_empty=_getbool("TEAMS_FULL_ON_EMPTY",True)
            self.teams_backfill_limit=g("TEAMS_BACKFILL_LIMIT","200")

            # Legacy HTTP SIEM
            self.siem_http_url=g("SIEM_HTTP_URL",""); self.siem_http_auth_scheme=g("SIEM_HTTP_AUTH_SCHEME","bearer")
            self.siem_http_token=g("SIEM_HTTP_TOKEN",""); self.siem_http_headers_json=g("SIEM_HTTP_HEADERS_JSON",""); self.siem_http_verify=_getbool("SIEM_HTTP_VERIFY",True)
            
    settings = Settings()
