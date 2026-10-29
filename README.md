# wazuh-mcp — MCP server for Wazuh SIEM triage (indexer + manager API)

![python](https://img.shields.io/badge/python-3.11%2B-blue)
![mcp](https://img.shields.io/badge/MCP-1.x-6E56CF)
![wazuh](https://img.shields.io/badge/Wazuh-4.x-005571)
![transport](https://img.shields.io/badge/transport-stdio-informational)
![tls](https://img.shields.io/badge/TLS-self--signed--ok-yellow)
![status](https://img.shields.io/badge/status-personal%20homelab-brightgreen)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 60-Second Overview

**Wazuh** is an open-source SIEM/XDR platform. It ships an OSSEC-fork agent that
tails logs, runs rootkit/FIM checks, and streams events to a manager; the
manager normalises against ~3,000 built-in rules and writes alerts into an
OpenSearch index (`wazuh-alerts-*`). A dashboard sits on top. In a typical
homelab it watches Linux hosts, Proxmox, pfSense/OPNsense, containers,
Windows endpoints — everything that can forward syslog or run the agent.

**MCP** (Model Context Protocol, Anthropic 2024) is a stdio/JSON-RPC
contract that lets an LLM call typed server tools. Instead of pasting curl
output into Claude, Claude *calls* `wazuh_alerts(hours=1, min_level=10)` and
reasons over the structured result.

**What this enables** — natural-language SIEM triage from Claude Desktop /
Claude Code:

> "show failed logins in the last hour across all agents"
> → `wazuh_search("rule.groups:authentication_failed", hours=1)`

> "why is the proxmox agent disconnected?"
> → `wazuh_agents(status="disconnected")` + `wazuh_alerts(agent_name="proxmox", hours=24)`

> "what IP is attacking us right now?"
> → `wazuh_top_rules(hours=1)` → pivot via `wazuh_search("data.srcip:X.X.X.X")`

No dashboard tab-switching, no Lucene memorisation, no Kibana round-trips.
The LLM composes queries from the question.

---

## For Interviewers

### Problem Statement

SIEM query UX is slow for the person who actually has to triage alerts at
2am. The default Wazuh workflow:

1. Open browser → log into dashboard → wait for OpenSearch to warm up.
2. Pick the "Security events" view, remember the Lucene field names
   (`rule.groups`, `agent.name`, `data.srcip`, `rule.level`), filter.
3. Context-switch to the "Agents" view to check status.
4. Scroll through 50-row tables, copy a timestamp, pivot to a new filter.

Every step is a tab, a click, a wait. Analyst mental state is the scarce
resource; the dashboard spends it liberally.

An LLM over MCP flips this. The analyst types the question in English, the
model picks the right tool, builds the DSL, pages the result, and summarises.
Pivots are free (another tool call, same conversation). The dashboard
becomes a verification surface, not the primary one.

### Skills Demonstrated

| Area                        | Where it shows up                                                       |
| --------------------------- | ----------------------------------------------------------------------- |
| MCP protocol                | `FastMCP("wazuh")` + `@mcp.tool()` decorators, stdio transport          |
| Wazuh indexer (OpenSearch)  | `_indexer_search()` posts hand-rolled DSL to `/wazuh-alerts-*/_search`  |
| Wazuh manager REST API      | `_api_get()` with Bearer token against `/agents`, `/rules`              |
| Authentication flow         | `_api_token()` POST to `/security/user/authenticate`, 850s TTL cache   |
| Query building              | bool/must composition, Lucene `query_string`, terms aggregations        |
| Result summarisation        | `_hits_to_alerts()` reshape to flat dicts, 400-char `full_log` cap      |
| Pydantic-ish schemas        | tool signatures (`hours: int = 24`) auto-exposed as MCP input schema    |
| Secure defaults             | TLS verify off by default for self-signed; env-only creds, no disk read |

### Architecture (ASCII)

```
                 +--------------------+
    user prompt  |   Claude Desktop   |
    "failed      |   / Claude Code    |
    logins last  +----------+---------+
    hour"                   |
                            | stdio (JSON-RPC, MCP)
                            v
                 +--------------------+
                 |    server.py       |      requirements.txt:
                 |    FastMCP("wazuh")|        mcp[cli] >=1.0
                 |                    |        requests  >=2.32
                 |  @mcp.tool x8      |        urllib3   >=2.0
                 +----+--------+------+
                      |        |
         HTTPS +Basic |        | HTTPS Bearer (cached token, 850s)
                      v        v
       +----------------+   +----------------+
       |  Wazuh         |   |  Wazuh         |
       |  Indexer       |   |  Manager API   |
       |  (OpenSearch)  |   |  :55000        |
       |  :9200         |   |                |
       |                |   |  /agents       |
       |  wazuh-alerts-*|   |  /rules        |
       +-------+--------+   |  /security/... |
               ^            +--------+-------+
               |                     ^
               |  filebeat           | agent-mgmt
               |                     |
       +-------+---------------------+------+
       |          Wazuh Manager (ossec)     |
       +-----------------+------------------+
                         ^
                         | 1514/udp + 1515/tcp
             +-----------+------------+
             |  Wazuh agents (Linux,  |
             |  Proxmox, Windows,     |
             |  containers, syslog)   |
             +------------------------+
```

### Design Decisions

**Why both indexer *and* manager API?**
Alerts live in the OpenSearch index — hitting the manager's `/security/events`
endpoint for every query would round-trip through the manager, which paginates
poorly and caps at 500 results. The indexer gives us aggregations
(`terms`, `date_histogram`) the manager API doesn't expose. Agent *state*,
however, isn't indexed as alerts — a disconnected agent emits silence, not an
event. For "which agents are down right now?" the manager's `/agents`
endpoint is the only truthful source. Two sources, one tool surface.

**How are auth tokens refreshed?**
Wazuh manager tokens live ~900s. `_api_token()` caches in-process with an
850s TTL (30s safety margin) and re-authenticates transparently on expiry.
Indexer auth is HTTP Basic every call — stateless, no cache needed. The
token cache is a module-level dict; a long-running MCP process pays the
auth cost once per 14 minutes, not once per query.

**Pagination / truncation strategy for large result sets.**
LLM context is the real budget, not network. Three layers:

1. `limit` capped at `min(limit, 500)` inside each tool — never return more
   than one OpenSearch page.
2. `_hits_to_alerts()` reshapes each hit to 8 fields; drops the 90% of the
   `_source` nobody asks about (fileset, decoder metadata, geoip blobs).
3. `full_log` truncated to 400 chars. A multi-MB log line is a token
   bonfire; the LLM gets the first 400 chars and can call the tool again
   with a narrower filter if it needs more.

If the model needs page 2, it asks a sharper question. Pagination becomes
*refinement*, not scroll.

**Why read-only?**
No `agent restart`, no rule edits, no index deletes. A prompt-injected log
line should never be able to disable monitoring. Every tool is a `GET` or a
search; the manager API endpoints that *do* mutate state (`PUT /agents/...`,
`DELETE /rules/...`) are not wired in. This is a deliberate ceiling.
`ponytail:` lift it only when there's a specific operator ritual that
benefits from being in-chat.

### Metrics

| Metric                            | Value                             |
| --------------------------------- | --------------------------------- |
| MCP tools exposed                 | 8                                 |
| Lines of code (`server.py`)       | ~280                              |
| Runtime dependencies              | 3 (`mcp`, `requests`, `urllib3`)  |
| Hardcoded hostnames / IPs         | 0 (all env-driven)                |
| Destructive endpoints wired       | 0 (read-only MCP)                 |
| Auth sources                      | 2 (indexer Basic, manager Bearer) |
| Token cache TTL                   | 850s (manager tokens valid 900s)  |
| Max rows per tool call            | 500                               |
| `full_log` truncation             | 400 chars                         |
| Default TLS verify                | off (self-signed homelab fit)     |

---

## Quick Start

### 1. Install

```bash
cd ~/projects/wazuh-mcp
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Python 3.11+. The `mcp[cli]` package pulls in `anyio`, `pydantic`, and the
JSON-RPC stdio transport.

### 2. Point at your Wazuh

You need, at minimum, indexer URL + credentials. Manager API creds are
optional (only `wazuh_agents` and `wazuh_rule` need them).

```bash
export WAZUH_INDEXER_URL=https://wazuh.example.com:9200
export WAZUH_INDEXER_USER=admin
export WAZUH_INDEXER_PASS='…'
export WAZUH_API_URL=https://wazuh.example.com:55000
export WAZUH_API_USER=wazuh-wui
export WAZUH_API_PASS='…'
# optional
export WAZUH_VERIFY_TLS=0           # 1 to enforce; 0 for the stock self-signed install
```

Quick smoke test (hits `_cluster/health` + mints a token):

```bash
venv/bin/python -c "from server import wazuh_health; import json; print(json.dumps(wazuh_health(), indent=2))"
```

### 3. Register with Claude Desktop / Claude Code

Claude Code (recommended — scopes creds per user, not per repo):

```bash
claude mcp add --scope user \
  -e WAZUH_INDEXER_URL=https://wazuh.example.com:9200 \
  -e WAZUH_INDEXER_USER=admin \
  -e WAZUH_INDEXER_PASS='…' \
  -e WAZUH_API_URL=https://wazuh.example.com:55000 \
  -e WAZUH_API_USER=wazuh-wui \
  -e WAZUH_API_PASS='…' \
  wazuh -- /home/you/projects/wazuh-mcp/venv/bin/python /home/you/projects/wazuh-mcp/server.py
```

Claude Desktop (`~/.config/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/home/you/projects/wazuh-mcp/venv/bin/python",
      "args": ["/home/you/projects/wazuh-mcp/server.py"],
      "env": {
        "WAZUH_INDEXER_URL": "https://wazuh.example.com:9200",
        "WAZUH_INDEXER_USER": "admin",
        "WAZUH_INDEXER_PASS": "…",
        "WAZUH_API_URL":     "https://wazuh.example.com:55000",
        "WAZUH_API_USER":    "wazuh-wui",
        "WAZUH_API_PASS":    "…",
        "WAZUH_VERIFY_TLS":  "0"
      }
    }
  }
}
```

### 4. First query

Open a fresh Claude session and ask:

> *"Is my Wazuh healthy? Then show me the top 5 firing rules in the last hour."*

Claude will call `wazuh_health` then `wazuh_top_rules(hours=1, size=5)`.

---

## Tool Reference

All eight tools are read-only. Return types are JSON-serialisable dicts/lists.

| Tool               | Backend          | Purpose                                                      |
| ------------------ | ---------------- | ------------------------------------------------------------ |
| `wazuh_health`     | both             | Indexer + API reachability + cluster status                  |
| `wazuh_alerts`     | indexer          | Recent alerts, structured filters (rule_id, level, agent)    |
| `wazuh_top_rules`  | indexer agg      | Top firing rule IDs over N hours, with descriptions          |
| `wazuh_top_agents` | indexer agg      | Agents with most alerts over N hours                         |
| `wazuh_search`     | indexer          | Lucene `query_string` — the escape hatch for arbitrary DSL   |
| `wazuh_agents`     | manager `/agents`| Registered agent list, optional `status` filter              |
| `wazuh_rule`       | manager `/rules` | Full rule definition by ID                                   |
| `wazuh_fim`        | indexer          | File-integrity-monitoring (syscheck) events, agent-scoped    |

### `wazuh_health() -> dict`

Confirms indexer + API reachable. Returns:

```json
{
  "indexer_url": "https://wazuh.example.com:9200",
  "api_url":     "https://wazuh.example.com:55000",
  "verify_tls":  false,
  "indexer":     {"status_code": 200, "cluster_status": "green"},
  "api":         "token_ok"
}
```

### `wazuh_alerts(hours=24, rule_id="", min_level=0, agent_name="", limit=50) -> list[dict]`

AND-combined filters. Omit any to broaden. Returns alerts shaped as:

```json
{
  "ts":          "2026-10-28T22:13:04.112Z",
  "rule_id":     "5760",
  "level":       10,
  "description": "sshd: authentication failed.",
  "groups":      ["authentication_failed", "pci_dss_10.2.4", "gpg13_7.1"],
  "agent":       {"id": "003", "name": "proxmox", "ip": "10.0.0.5"},
  "location":    "/var/log/auth.log",
  "full_log":    "Oct 28 22:13:04 proxmox sshd[12402]: Failed password for root …"
}
```

### `wazuh_top_rules(hours=24, size=20) -> list[dict]`

OpenSearch `terms` aggregation on `rule.id` with sub-aggregation for the
description. Returns `[{rule_id, count, description}, ...]`.

### `wazuh_top_agents(hours=24, size=20) -> list[dict]`

`terms` on `agent.name`. Returns `[{agent, count}, ...]`.

### `wazuh_search(query_string, hours=24, limit=50) -> list[dict]`

Lucene `query_string` passed straight through. The flex tool for anything
not covered by the structured ones. Examples:

- `rule.groups:authentication_failed`
- `data.srcip:1.2.3.4 AND rule.level:>=10`
- `agent.name:proxmox AND rule.description:*ssh*`
- `data.vulnerability.cve:CVE-2024-* AND rule.level:>=12`

### `wazuh_agents(status="", limit=100) -> list[dict]`

Manager API `/agents`. `status` ∈ `active | disconnected | never_connected | pending` (empty = all).

### `wazuh_rule(rule_id) -> dict`

Manager API `/rules?rule_ids=…`. Returns the rule's full definition —
XML-decoded fields, groups, level, pci/gdpr/hipaa mappings.

### `wazuh_fim(agent_name="", hours=24, limit=50) -> list[dict]`

Thin wrapper over `wazuh_search` scoped to `rule.groups:syscheck`. Useful
answer to "what changed on this host overnight?"

---

## Examples

### 1. Triage failed logins in the last 24h

> **you:** any brute-force activity in the last day?

Claude's tool trace:

```
wazuh_top_rules(hours=24, size=5)
→ [{"rule_id": "5760", "count": 412, "description": "sshd: authentication failed."},
   {"rule_id": "5712", "count": 87,  "description": "sshd: brute force trying to get access."},
   ...]

wazuh_alerts(rule_id="5712", hours=24, limit=10)
→ [{ts: "…", agent: {name: "proxmox", ip: "10.0.0.5"}, full_log: "… Failed password for root from 203.0.113.42 …"}, ...]
```

Claude summarises: *"412 failed-auth events in 24h, concentrated on `proxmox`
(SSH exposed). 87 of those crossed the brute-force threshold. Top attacker
IP: 203.0.113.42. Suggest fail2ban / move SSH off :22."*

### 2. Find disconnected agents

> **you:** which agents are down?

```
wazuh_agents(status="disconnected")
→ [{id: "007", name: "db01", lastKeepAlive: "2026-10-26T14:02:11Z", ...},
   {id: "011", name: "nas",  lastKeepAlive: "2026-10-27T08:17:03Z", ...}]

wazuh_alerts(agent_name="db01", hours=72, limit=20)
→ [... last alert 2026-10-26T13:58, nothing after ...]
```

Claude: *"`db01` went silent 2d ago at 14:02 UTC — last alert was a
scheduled rotation 4 minutes prior. Agent likely died with the log rotation,
not an attack. `nas` is only 18h down, probably the reboot you did yesterday."*

### 3. Pivot on an IP to see every alert it triggered

> **you:** show me everything 203.0.113.42 has done

```
wazuh_search("data.srcip:203.0.113.42", hours=168, limit=100)
→ [... 94 hits across 3 agents, rule.groups includes authentication_failed,
     web_scan, invalid_login ...]

wazuh_search("data.srcip:203.0.113.42 AND rule.level:>=10", hours=168, limit=20)
→ [... 23 high-severity hits, pattern: SSH brute → web dirbust → giveup ...]
```

Claude: *"203.0.113.42 hit 3 agents over 7d — SSH brute on `proxmox`, dirbust
on `web01`, nothing on `mail01`. 23 events ≥ level 10. Classic opportunistic
scanner. Already blocked on `proxmox` after rule 5712 fired. Consider a
network-level block in your edge firewall."*

---

## Technical Reference

### Install

```bash
git clone <repo> wazuh-mcp
cd wazuh-mcp
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Only 3 runtime deps: `mcp[cli]`, `requests`, `urllib3`. No ORMs, no async
frameworks, no CLI libraries — the MCP SDK handles the stdio contract and
`requests` handles everything else. `urllib3.disable_warnings()` silences
the self-signed-cert warning spam that would otherwise contaminate stdio.

### Configuration (env vars)

| Variable             | Required                | Default                      | Notes                                     |
| -------------------- | ----------------------- | ---------------------------- | ----------------------------------------- |
| `WAZUH_INDEXER_URL`  | yes                     | `https://localhost:9200`     | OpenSearch endpoint                       |
| `WAZUH_INDEXER_USER` | yes                     | `admin`                      | HTTP Basic                                |
| `WAZUH_INDEXER_PASS` | yes                     | *(empty)*                    | HTTP Basic — set this                     |
| `WAZUH_API_URL`      | if using manager tools  | `https://localhost:55000`    | Wazuh RESTful API                         |
| `WAZUH_API_USER`     | if using manager tools  | `wazuh-wui`                  | authenticates once per 850s               |
| `WAZUH_API_PASS`     | if using manager tools  | *(empty)*                    | authenticates once per 850s               |
| `WAZUH_VERIFY_TLS`   | no                      | `0` (off)                    | `1` to enforce; use when behind a real CA |

**No file-based config.** Every endpoint comes from env. The MCP registration
command *is* the config file.

### SSL verify behaviour

A stock Wazuh install ships with a self-signed root. `WAZUH_VERIFY_TLS=0` is
the default because that matches 95% of real homelabs — the alternative is
either (a) walking a self-signed cert into the system trust store, or (b)
putting Wazuh behind a reverse proxy with a public cert. Both are correct,
neither is universal. `ponytail:` set `WAZUH_VERIFY_TLS=1` the moment you have
a real cert; the knob exists so you can.

Transport is still HTTPS either way — verify-off doesn't downgrade to HTTP,
it just skips chain validation. On a Tailscale-only indexer the practical
threat model (someone MITMing your tailnet) is already weaker than the
indexer admin password leaking.

### Query DSL mapping (NL → tool → OpenSearch)

| Natural language                             | Tool call                                           | OpenSearch body (sketch)                                                           |
| -------------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------------------- |
| "failed logins last hour, high severity"     | `wazuh_alerts(hours=1, min_level=10)`               | `bool.must: [range @timestamp, range rule.level >=10]`                             |
| "ssh brute-force on proxmox"                 | `wazuh_search("rule.groups:authentication_failed AND agent.name:proxmox")` | `bool.must: [range @timestamp, query_string …]`           |
| "top 10 rules firing today"                  | `wazuh_top_rules(hours=24, size=10)`                | `size:0, aggs.terms rule.id size:10`                                               |
| "which agents are chatty right now"          | `wazuh_top_agents(hours=1, size=20)`                | `size:0, aggs.terms agent.name size:20`                                            |
| "what changed on web01 overnight"            | `wazuh_fim(agent_name="web01", hours=12)`           | `query_string: rule.groups:syscheck AND agent.name:web01`                          |

### Extending

Add a tool in `server.py`:

```python
@mcp.tool()
def wazuh_vulns(agent_name: str = "", hours: int = 24, limit: int = 50) -> list[dict]:
    """CVE detections (vulnerability-detector module)."""
    return wazuh_search(
        f"rule.groups:vulnerability-detector"
        + (f" AND agent.name:{agent_name}" if agent_name else ""),
        hours=hours, limit=limit,
    )
```

Restart Claude Desktop (reloads MCP servers on launch). The tool shows up
in the model's tool list immediately — the schema is derived from the type
hints, no decorators or Pydantic models to maintain.

For a new backend (e.g. a direct `/syscheck` endpoint instead of searching
alerts), add a thin wrapper around `_api_get()` and expose it with
`@mcp.tool()`. Pattern-match on the eight tools that already exist.

---

## Why This Was Built

Homelab Wazuh deployment: 8 agents (Proxmox host, 2 LXCs, 2 VMs, a Pi, a
Windows box, pfSense syslog), ~2–4k alerts/day. The dashboard is fine for
weekly review but a terrible first stop for *"something just pinged me, what
is it?"* The latency between curiosity and answer was high enough that
genuine investigations lost to shrugs.

The AI hacking team project already runs Claude Code as the ops console
(scope-guarded shell, five Hermes personas, SSH aliases). Giving Claude a
read-only MCP into the SIEM closes the loop: the same chat that lets me
pivot across HTB boxes can now pivot across my own fleet, and the natural
pairing — "the SOC analyst persona asks the SIEM" — needed exactly this
MCP to exist.

Secondary motive: this is a clean, legible example of the pattern "wrap a
read-heavy enterprise API in an MCP". The code is 280 lines, no clever
abstractions, no DSL builder — just function-per-tool with the real
OpenSearch body visible inline. Easy to point at in interviews, easy to
fork for a different SIEM (Elastic, Splunk, Graylog) in an afternoon.

---

## FAQ

**Q: Will this scale beyond a homelab?**
A: Up to a few hundred agents, yes — the OpenSearch index itself scales
further than you do. Beyond ~500 alerts per tool call you'll want
server-side truncation (`_source` filtering, PIT cursors). The 500-row cap
in `_indexer_search` is a deliberate ceiling, not a limit of the backend.
`ponytail:` paginate with `search_after` if a real caller measurably needs
page 2 — until then, sharper queries beat deeper pagination for the LLM.

**Q: Which auth model does the manager API use?**
A: Bearer tokens via `POST /security/user/authenticate` with HTTP Basic.
Tokens are 15-minute JWTs. This MCP caches one per process with an 850s TTL
and transparent re-auth on 401. No refresh-token flow — Wazuh doesn't
expose one; re-authenticating against the password is the official path.

**Q: Can I run this offline / air-gapped?**
A: Yes. Nothing phones home. All three Python deps are offline-installable
from a local wheelhouse (`pip download -r requirements.txt`). The only
network traffic from `server.py` is to `WAZUH_INDEXER_URL` and
`WAZUH_API_URL`. If your Wazuh is on a tailnet, so is this.

**Q: How do I paginate past 500 alerts?**
A: Don't — refine instead. Add a filter (`rule_id=`, `min_level=`,
narrower `hours=`). The LLM is better at narrowing a question than at
reading page 7. If you genuinely need bulk export, use the OpenSearch
`_search?scroll=1m` API directly — this MCP intentionally doesn't
re-expose it.

**Q: Is there any write/mutation path?**
A: No. By design. Every tool is a GET or a `_search` POST. The manager
endpoints that mutate state (`PUT /agents/<id>/restart`,
`DELETE /rules/files/...`) are not wired in. See *Design Decisions*.

**Q: What happens if the indexer is up but the manager is down?**
A: `wazuh_health` returns `{"indexer": {"cluster_status": "green"}, "api":
"error: …"}` — indexer-only tools (`wazuh_alerts`, `wazuh_top_rules`,
`wazuh_top_agents`, `wazuh_search`, `wazuh_fim`) keep working. Only
`wazuh_agents` and `wazuh_rule` fail, with the error surfaced as a
one-item list `[{"error": "..."}]` so the LLM sees it instead of a 500.

**Q: What about rate limiting / query cost?**
A: OpenSearch has no built-in per-user QPS cap — your cluster CPU is the
limit. The 15s `timeout` in `_indexer_search` guards runaway queries. For
busy clusters, bump the `size` default down (currently 50) or add a per-tool
`size` cap in `server.py`.

**Q: Does it work with Elastic / stock Elasticsearch instead of Wazuh's indexer?**
A: Yes — the indexer tools are plain `_search` against `wazuh-alerts-*`.
Any Elastic/OpenSearch cluster with a Wazuh-shaped index pattern responds
identically. The manager API tools (`wazuh_agents`, `wazuh_rule`) are
Wazuh-specific and will fail against bare Elastic.

**Q: How are credentials stored?**
A: In the MCP registration (env vars passed by Claude Desktop /
`claude mcp add`). Never read from disk by `server.py`. Rotate the Wazuh
password → rotate the MCP registration. No `.env` files, no secrets in
code, no secrets in the repo. The pre-push scanner on this repo rejects
internal IPs so `wazuh.example.com` is the only hostname that ever shows up
in commits.

---

## License

MIT. Use it, fork it, point it at your SIEM, break it over your knee. See
`LICENSE` if present; otherwise consider this notice the grant.
