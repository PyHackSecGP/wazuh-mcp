# wazuh-mcp

MCP server for Wazuh SIEM triage. Queries the Wazuh indexer (OpenSearch) + manager API behind one tool surface.

## Why

Triage SIEM alerts from the terminal / Claude Code instead of tabbing to the Wazuh dashboard every time. One MCP = `wazuh_alerts`, `wazuh_top_rules`, `wazuh_top_agents`, `wazuh_search`, `wazuh_agents`, `wazuh_rule`, `wazuh_fim`.

## Tools

| Tool | Purpose |
|---|---|
| `wazuh_health` | indexer + API reachability check |
| `wazuh_alerts` | recent alerts (filter by rule_id / level / agent / hours) |
| `wazuh_top_rules` | top firing rules over N hours |
| `wazuh_top_agents` | agents with most alerts over N hours |
| `wazuh_search` | Lucene `query_string` search |
| `wazuh_agents` | manager API agent list (status filter) |
| `wazuh_rule` | rule definition by id |
| `wazuh_fim` | file-integrity-monitoring (syscheck) events |

## Install

```bash
cd ~/projects/wazuh-mcp
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

## Configure (env)

All endpoint info comes from env — nothing hardcoded. Set via `claude mcp add -e KEY=VAL`:

| Var | Default | Required |
|---|---|---|
| `WAZUH_INDEXER_URL` | `https://localhost:9200` | yes (set to your indexer) |
| `WAZUH_INDEXER_USER` | `admin` | yes |
| `WAZUH_INDEXER_PASS` | *(empty)* | **yes** |
| `WAZUH_API_URL` | `https://localhost:55000` | optional (only for /api tools) |
| `WAZUH_API_USER` | `wazuh-wui` | optional |
| `WAZUH_API_PASS` | *(empty)* | **yes if using /api tools** |
| `WAZUH_VERIFY_TLS` | `0` | `1` to enforce TLS verify |

## Register with Claude Code

```bash
claude mcp add --scope user \
  -e WAZUH_INDEXER_URL=https://your-indexer:9200 \
  -e WAZUH_INDEXER_USER=admin \
  -e WAZUH_INDEXER_PASS=... \
  -e WAZUH_API_URL=https://your-manager:55000 \
  -e WAZUH_API_USER=wazuh-wui \
  -e WAZUH_API_PASS=... \
  wazuh -- /home/tony/projects/wazuh-mcp/venv/bin/python /home/tony/projects/wazuh-mcp/server.py
```

## Example queries

```
> show me ssh brute-force attempts on proxmox in the last 6 hours
→ wazuh_search("rule.groups:authentication_failed AND agent.name:proxmox", hours=6)

> what's firing most on the network today?
→ wazuh_top_rules(hours=24, size=10)

> any disconnected agents?
→ wazuh_agents(status="disconnected")
```

## Design notes

- Indexer queries hit OpenSearch directly (no manager API round-trip) → fast.
- API token cached in-process (900s TTL, re-auth transparent).
- `WAZUH_VERIFY_TLS=0` default fits self-signed deployments (common Wazuh install). Set to `1` for prod CA.
- No destructive operations exposed. Read-only MCP.
- All creds via env; never read from disk.

## Deploying over Tailscale

If Wazuh is Tailscale-only (recommended), set `WAZUH_INDEXER_URL` to the Tailscale hostname/IP. Pre-push scanner on this repo rejects internal IPs in commits, so examples here stay as `your-indexer`.
