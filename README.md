<p align="center">
  <img src="assets/dlh-logo.png" alt="DataLeakHunter logo" width="260">
</p>

<p align="center">
https://dataleakhunter.com
</p>

# DataLeakHunter aka DLH

DataLeakHunter(DLH) is a modular system to detect and track sensitive data leaks across Slack, Confluence, Jira, and Trello. It exports ECS/CIM-aligned JSON to SIEM, and can open tickets automatically in Jira and GLPI.

## Quickstart

```bash
cp .env.example .env
# fill in tokens
docker compose up -d --build
```

API → http://localhost:8000 •

## Tokens / Credentials — How to Create & Verify

- **Jira token**: https://id.atlassian.com/manage-profile/security/api-tokens
  ```bash
  curl -s -u "you@company.com:xxxxx" "$JIRA_SERVER/rest/api/3/myself" | jq .
  ```
- **Confluence**: same Atlassian token/email.
  ```bash
  curl -s -u "you@company.com:xxxxx" "$CONFLUENCE_SERVER/rest/api/space?limit=1" | jq .
  ```
- **Trello key/token**: https://trello.com/app-key
  ```bash
  curl "https://api.trello.com/1/members/me/boards?fields=id,name,shortUrl&filter=open&key=$TRELLO_KEY&token=$TRELLO_TOKEN"
  ```
- **Slack bot**: add read scopes; verify
  ```bash
  curl -s -H "Authorization: Bearer $SLACK_BOT_TOKEN" "https://slack.com/api/conversations.list?types=public_channel,private_channel,im,mpim" | jq .
  ```
- **GLPI**: enable REST; App-Token/User Token
  ```bash
  curl -s -X POST "$GLPI_URL/apirest.php/initSession"     -H "App-Token: $GLPI_APP_TOKEN" -H "Content-Type: application/json"     -d '{"user_token":"'"$GLPI_USER_TOKEN"'"}'
  ```
- **ServiceNow**:
  ```bash
  curl -s -u "$SNOW_USERNAME:$SNOW_PASSWORD"     -H "Content-Type: application/json"     -d '{"short_description":"LeakHunter test","description":"hello"}'     "$SNOW_INSTANCE_URL/api/now/table/incident"
  ```


---

## API Integrations

DataLeakHunter exposes a simple **REST API** to integrate findings with other systems (SIEMs, dashboards, orchestration tools, etc).

### Authentication
All integration endpoints require an API key via header:

```http
GET /integrations/events
Host: localhost:8000
X-API-Key: <your-key>

INTEGRATIONS_API_KEYS=supersecret123,anotherkey

GET /integrations/events?limit=10&since=2025-08-01T00:00:00Z

{
  "ok": true,
  "events": [
    {
      "id": "66cba3...",
      "platform": "slack",
      "container": "general",
      "rule": "Credit Card",
      "severity": "High",
      "snippet": "4111 **** **** 1111",
      "url": "https://slack.com/...",
      "found_at": "2025-08-26T14:00:00Z",
      "author": {
        "id": "U12345",
        "name": "alice"
      }
    }
  ]
}

POST /integrations/events
Content-Type: application/json
X-API-Key: <your-key>

{
  "platform": "github",
  "container": "repo-secrets",
  "rule": "Password",
  "severity": "Critical",
  "snippet": "hunter2",
  "url": "https://github.com/org/repo",
  "author": { "id": "user1", "name": "bob" }
}

GET /integrations/health

Example Usage

Splunk/Elastic dashboards → Poll GET /integrations/events regularly.

Custom SIEM/ETL → Push detections into LeakHunter using POST /integrations/events.

SOAR tools (Cortex XSOAR, TheHive, Shuffle, etc.) → Create workflows that fetch new findings and auto-create playbooks.## 🔌 API Integrations

LeakHunter exposes a simple **REST API** to integrate findings with other systems (SIEMs, dashboards, orchestration tools, etc).

### Authentication
All integration endpoints require an API key via header:

```http
GET /integrations/events
Host: localhost:8000
X-API-Key: <your-key>
```

Keys are defined in `.env` (comma-separated if multiple):

```env
INTEGRATIONS_API_KEYS=supersecret123,anotherkey
```

### Endpoints

#### List Findings
```http
GET /integrations/events?limit=10&since=2025-08-01T00:00:00Z
```

**Response (ECS/CIM aligned JSON):**
```json
{
  "ok": true,
  "events": [
    {
      "id": "66cba3...",
      "platform": "slack",
      "container": "general",
      "rule": "Credit Card",
      "severity": "High",
      "snippet": "4111 **** **** 1111",
      "url": "https://slack.com/...",
      "found_at": "2025-08-26T14:00:00Z",
      "author": {
        "id": "U12345",
        "name": "alice"
      }
    }
  ]
}
```

#### Submit Findings (for external connectors)
```http
POST /integrations/events
Content-Type: application/json
X-API-Key: <your-key>

{
  "platform": "github",
  "container": "repo-secrets",
  "rule": "Password",
  "severity": "Critical",
  "snippet": "hunter2",
  "url": "https://github.com/org/repo",
  "author": { "id": "user1", "name": "bob" }
}
```

#### Health
```http
GET /integrations/health
```

---

### Example Usage

- **Splunk/Elastic dashboards** → Poll `GET /integrations/events` regularly.
- **Custom SIEM/ETL** → Push detections into LeakHunter using `POST /integrations/events`.
- **SOAR tools (Cortex XSOAR, TheHive, Shuffle, etc.)** → Create workflows that fetch new findings and auto-create playbooks.

---

With this API, DataLeakHunter can serve as both:
- A **detection hub** (Slack/Jira/Confluence/Trello → LeakHunter → your SIEM)
- A **broker** for external sources (GitHub, GitLab, Bitbucket, etc.) to feed findings into the same normalized pipeline.


## Sanity checks

```bash
curl -X POST "http://localhost:8000/trigger/slack"
curl -X POST "http://localhost:8000/trigger/confluence"
curl -X POST "http://localhost:8000/trigger/jira"
curl -X POST "http://localhost:8000/trigger/trello?full=true"
curl -X POST "http://localhost:8000/schedule/run-now?connector=all"
curl -X POST "http://localhost:8000/export/run?since_days=7"
```
