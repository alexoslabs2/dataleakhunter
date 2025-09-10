
from __future__ import annotations
import io, json, re, requests
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.config import settings
from app.utils import sha256

#Atlassian Document Format Error Patch 
SESSION = requests.Session()
SESSION.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
AUTH = (settings.jira_username or "", settings.jira_api_token or "")

JIRA_BASE = (settings.jira_server or "").rstrip("/")
PROJECT_KEY = settings.jira_default_project or "SEC"
ISSUE_TYPE = settings.jira_issue_type or "Task"
#End Patch

ISSUE_URL = f"{settings.jira_server}/rest/api/2/issue"
ATTACH_URL_TPL = f"{settings.jira_server}/rest/api/2/issue/{{key}}/attachments"
AUTH = (settings.jira_username, settings.jira_api_token)

def _severity_rank(s: str) -> int:
    if not s: return 0
    return {"low":1, "medium":2, "high":3}.get(s.lower(), 2)

def _eligible(event: Dict[str, Any]) -> bool:
    if not settings.jira_create_on_detect:
        return False
    needed = [settings.jira_server, settings.jira_username, settings.jira_api_token, settings.jira_default_project]
    if not all(needed):
        return False
    return _severity_rank(event.get("severity","Medium")) >= _severity_rank(settings.jira_min_severity)

def _routing_for(label: str) -> Dict[str, Any]:
    try:
        if settings.jira_routing_map:
            data = json.loads(settings.jira_routing_map)
            for k,v in (data or {}).items():
                if label.lower().startswith(str(k).lower()):
                    return v or {}
    except Exception:
        pass
    return {}

def _jira_labelify(s: str) -> str:
    s = (s or "").lower().strip()
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^a-z0-9_.-]", "-", s)
    s = re.sub(r"-{2,}", "-", s)
    return s.strip("-")[:80]

def _compose_summary_and_description(event: Dict[str, Any]) -> tuple[str, str, list[str]]:
    dets = event.get("detections", []) or []
    primary = (dets[0] if dets else {}) or {}
    type_ = primary.get("label", "Sensitive Data")
    platform = event.get("platform","-")
    container = event.get("container") or {}
    container_name = container.get("name") or container.get("id") or "-"
    url = container.get("url") or "-"
    found_at = event.get("found_at")
    when = found_at if isinstance(found_at, str) else (found_at or datetime.utcnow()).replace(tzinfo=timezone.utc).isoformat()
    author_name = (event.get("source_meta") or {}).get("author_name") or "-"
    author_id = (event.get("source_meta") or {}).get("author_id") or "-"
    severity = event.get("severity","Medium")
    snippet = (event.get("snippet_redacted","") or "")[:800]
    fp = event.get("fingerprint") or "-"
    dash = settings.dashboard_base_url or "http://localhost:8501"
    dash_link = f"{dash}?fingerprint={fp}"
    summary = f"[DLH] Sensitive data found: {type_} in {platform}/{container_name}"
    description = f"""**When**: `{when}`
**Where**: `{platform} → {container_name} ({url})`
**Who**: `{author_name} ({author_id})`
**What**: `{type_}` (severity `{severity}`)
**Snippet (redacted)**:
```
{snippet}
```

**Recommended Action**: remove/rotate secret, restrict access, update credentials.

**Labels**: `data-leakage`, `{type_}`, `{platform}`
**Fingerprint**: `{fp}`
**Dashboard**: {dash_link}
"""
    raw_labels = ["data-leakage", f"rule-{type_}", platform]
    labels = [_jira_labelify(x) for x in raw_labels if x]
    labels = list(dict.fromkeys([l for l in labels if l]))
    return summary, description, labels

def _create_issue(summary: str, description: str, labels: list[str], project_key: str, assignee: Optional[str]=None) -> Optional[str]:
    fields = {
        "project": {"key": project_key},
        "summary": summary,
        "issuetype": {"name": settings.jira_issue_type},
        "description": description,
        "labels": labels,
    }
    if assignee:
        if assignee.startswith("acc_"):
            fields["assignee"] = {"accountId": assignee.replace("acc_","",1)}
        else:
            fields["assignee"] = {"name": assignee}
    r = requests.post(ISSUE_URL, json={"fields": fields}, auth=AUTH, timeout=30)
    if r.status_code not in (200,201):
        print(f"[JiraCreate] create failed {r.status_code} resp={r.text[:400]}")
        return None
    return (r.json() or {}).get("key")

def _attach_evidence(issue_key: str, event: Dict[str, Any]) -> None:
    url = ATTACH_URL_TPL.format(key=issue_key)
    snippet = (event.get("snippet_redacted") or "")[:1000]
    digest = sha256(snippet)
    content = f"fingerprint={event.get('fingerprint')}\nsha256(snippet_redacted)={digest}\nplatform={event.get('platform')}\ncontainer={(event.get('container') or {}).get('name')}\n"
    import io as _io
    buf = _io.BytesIO(content.encode("utf-8"))
    files = {"file": ("evidence.txt", buf, "text/plain")}
    headers = {"X-Atlassian-Token": "no-check"}
    r = requests.post(url, files=files, headers=headers, auth=AUTH, timeout=30)
    if r.status_code not in (200,201):
        print(f"[JiraCreate] attach failed {r.status_code}: {r.text[:200]}")

def create_ticket_for_event(event: Dict[str, Any], mdb) -> Optional[str]:
    if not _eligible(event):
        return None
    if event.get("status",{}).get("jira_key"):
        return event["status"]["jira_key"]
    dets = event.get("detections", []) or []
    primary = (dets[0] if dets else {}) or {}
    route = _routing_for(primary.get("label",""))
    project = route.get("project") or settings.jira_default_project
    assignee = route.get("assignee")
    summary, description, labels = _compose_summary_and_description(event)
    key = _create_issue(summary, description, labels, project, assignee)
    if key:
        mdb.events.update_one({"fingerprint": event["fingerprint"]}, {"$set": {"status.jira_key": key, "status.last_sync_at": datetime.now(tz=timezone.utc)}})
        try: _attach_evidence(key, event)
        except Exception as e: print("[JiraCreate] evidence attach error:", e)
    return key


# Atlassian Document Format Error Patch Start
# -------------------------
# Helpers
# -------------------------

def _sanitize_label(label: str) -> str:
    """
    Jira labels: sem espaços; letras, números, '-', '_', '.'
    """
    s = label.strip().lower()
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"[^a-z0-9._-]", "", s)
    return s[:255] or "label"

def _labels_from_finding(platform: str, rule: str) -> List[str]:
    base = ["data-leakage"]
    if platform:
        base.append(_sanitize_label(platform))
    if rule:
        base.append(_sanitize_label(rule))
    # remover duplicatas mantendo ordem
    seen = set()
    out = []
    for x in base:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

def _text_to_adf(text: str) -> Dict[str, Any]:
    """
    Converte texto/markdown simples em ADF bem-formado.
    - Quebras de linha -> hardBreak
    - Blocos em branco -> novos parágrafos
    Obs.: simples e robusto para evitar 400 ADF.
    """
    text = (text or "").strip("\n")
    if not text:
        # documento vazio válido
        return {"version": 1, "type": "doc", "content": [{"type": "paragraph", "content": []}]}

    paragraphs = [p for p in re.split(r"\n\s*\n", text) if p is not None]
    content: List[Dict[str, Any]] = []
    for p in paragraphs:
        lines = p.split("\n")
        node_content: List[Dict[str, Any]] = []
        for i, line in enumerate(lines):
            line = line.rstrip("\r")
            if line:
                node_content.append({"type": "text", "text": line})
            else:
                node_content.append({"type": "text", "text": ""})
            if i < len(lines) - 1:
                node_content.append({"type": "hardBreak"})
        content.append({"type": "paragraph", "content": node_content})

    return {"version": 1, "type": "doc", "content": content}

def _render_description_md(
    found_at: str,
    platform: str,
    container_name: str,
    url: str,
    author_name: str,
    author_id: str,
    leak_type: str,
    severity: str,
    snippet_redacted: str,
    dashboard_url: Optional[str] = None,
) -> str:
    """
    Usa o seu template em Markdown "leve". Depois convertemos para ADF.
    """
    lines = [
        f"- **When**: `{found_at}`",
        f"- **Where**: `{platform}` → `{container_name}` ({url})",
        f"- **Who**: `{author_name}` (`{author_id}`)",
        f"- **What**: `{leak_type}` (severity `{severity}`)",
        f"- **Snippet (redacted)**:",
        "```",
        (snippet_redacted or "")[:1500],
        "```",
        "- **Recommended Action**: remove/rotate secret, restrict access, update credentials.",
        f"- **Labels**: `data-leakage`, `{leak_type}`, `{platform}`",
    ]
    if dashboard_url:
        lines.append(f"- **Dashboard Item**: {dashboard_url}")
    return "\n".join(lines)

def _build_issue_payload(
    summary: str,
    description_adf: Dict[str, Any],
    labels: List[str],
    project_key: str = PROJECT_KEY,
    issue_type: str = ISSUE_TYPE,
) -> Dict[str, Any]:
    # Campos mínimos para create
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary[:255],
            "issuetype": {"name": issue_type},
            "description": description_adf,
            "labels": labels[:50],  # limite razoável
        }
    }
    return payload

def _post_issue(payload: Dict[str, Any]) -> requests.Response:
    """
    Jira Cloud: /rest/api/3/issue (ADF)
    Jira Server/DC: /rest/api/2/issue (texto simples também aceita)
    Faz fallback automático se /3 falhar por 404/415.
    """
    url_v3 = f"{JIRA_BASE}/rest/api/3/issue"
    resp = SESSION.post(url_v3, data=json.dumps(payload), auth=AUTH, timeout=30)
    if resp.status_code in (404, 415):
        url_v2 = f"{JIRA_BASE}/rest/api/2/issue"
        resp = SESSION.post(url_v2, data=json.dumps(payload), auth=AUTH, timeout=30)
    return resp

# -------------------------
# API principal
# -------------------------

def create_ticket_from_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """
    f: dicionário do achado (platform, container_name, url, author, type, severity, snippet, found_at, dashboard_link)
    Retorna: {ok: bool, key?: str, id?: str, error?: str, status: int}
    """
    if not (JIRA_BASE and settings.jira_username and settings.jira_api_token):
        return {"ok": False, "status": 0, "error": "Jira not configured"}

    platform = f.get("platform", "")
    container_name = f.get("container_name", f.get("container", ""))
    url = f.get("url", "")
    author_name = (f.get("author") or {}).get("name", "") or f.get("author_name", "")
    author_id = (f.get("author") or {}).get("id", "") or f.get("author_id", "")
    leak_type = f.get("type", f.get("rule", "Sensitive Data"))
    severity = f.get("severity", "Low")
    snippet_redacted = f.get("snippet_redacted") or f.get("snippet") or ""
    found_at = f.get("found_at", "")
    dashboard_url = f.get("dashboard_url")

    summary = f"[DLH] Sensitive data found: {leak_type} in {platform}/{container_name}"

    # Monta descrição (markdown simples) e converte para ADF
    md = _render_description_md(
        found_at=found_at,
        platform=platform,
        container_name=container_name,
        url=url,
        author_name=author_name,
        author_id=author_id,
        leak_type=leak_type,
        severity=severity,
        snippet_redacted=snippet_redacted,
        dashboard_url=dashboard_url,
    )
    description_adf = _text_to_adf(md)

    labels = _labels_from_finding(platform, leak_type)

    payload = _build_issue_payload(
        summary=summary,
        description_adf=description_adf,
        labels=labels,
        project_key=PROJECT_KEY,
        issue_type=ISSUE_TYPE,
    )

    try:
        resp = _post_issue(payload)
    except requests.RequestException as e:
        return {"ok": False, "status": 0, "error": f"JiraCreate exception: {e!r}"}

    if resp.status_code >= 400:
        return {"ok": False, "status": resp.status_code, "error": resp.text}

    try:
        data = resp.json()
    except Exception:
        data = {"raw": resp.text}

    return {"ok": True, "status": resp.status_code, "key": data.get("key"), "id": data.get("id"), "data": data}
#END