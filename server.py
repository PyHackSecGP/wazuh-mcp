#!/usr/bin/env python3
"""wazuh-mcp — MCP server for Wazuh SIEM triage.

Queries Wazuh indexer (OpenSearch) + Wazuh API behind one surface. All
endpoint info comes from env (never hardcoded):

    WAZUH_INDEXER_URL   https://<host>:9200   (default: https://localhost:9200)
    WAZUH_INDEXER_USER  (default: admin)
    WAZUH_INDEXER_PASS  (required for live use)
    WAZUH_API_URL       https://<host>:55000  (default: https://localhost:55000)
    WAZUH_API_USER      (default: wazuh-wui)
    WAZUH_API_PASS      (required for /api/* tools)
    WAZUH_VERIFY_TLS    "1" to verify, "0" to skip  (default: 0 — self-signed)

Transport: stdio.
"""
from __future__ import annotations

import datetime
import json
import os
from typing import Optional

import requests
import urllib3
from mcp.server.fastmcp import FastMCP

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _indexer_url() -> str:
    return _env("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/")


def _api_url() -> str:
    return _env("WAZUH_API_URL", "https://localhost:55000").rstrip("/")


def _verify() -> bool:
    return _env("WAZUH_VERIFY_TLS", "0") == "1"


def _indexer_auth() -> tuple[str, str]:
    return (_env("WAZUH_INDEXER_USER", "admin"), _env("WAZUH_INDEXER_PASS", ""))


def _api_creds() -> tuple[str, str]:
    return (_env("WAZUH_API_USER", "wazuh-wui"), _env("WAZUH_API_PASS", ""))


# ── Indexer (OpenSearch) ─────────────────────────────────────────────────────
def _indexer_search(body: dict, index: str = "wazuh-alerts-*", timeout: int = 15) -> dict:
    url = f"{_indexer_url()}/{index}/_search"
    r = requests.post(url, json=body, auth=_indexer_auth(), verify=_verify(), timeout=timeout)
    r.raise_for_status()
    return r.json()


def _hits_to_alerts(res: dict) -> list[dict]:
    hits = res.get("hits", {}).get("hits", [])
    out = []
    for h in hits:
        s = h.get("_source", {})
        rule = s.get("rule", {}) or {}
        agent = s.get("agent", {}) or {}
        out.append({
            "ts":          s.get("timestamp") or s.get("@timestamp"),
            "rule_id":     rule.get("id"),
            "level":       rule.get("level"),
            "description": rule.get("description"),
            "groups":      rule.get("groups", [])[:5],
            "agent":       {"id": agent.get("id"), "name": agent.get("name"), "ip": agent.get("ip")},
            "location":    s.get("location"),
            "full_log":    (s.get("full_log") or "")[:400],
        })
    return out


# ── API (manager) token ──────────────────────────────────────────────────────
_api_token_cache: dict = {"token": None, "exp": 0}


def _api_token() -> str:
    import time
    if _api_token_cache["token"] and _api_token_cache["exp"] > time.time() + 30:
        return _api_token_cache["token"]
    user, pw = _api_creds()
    r = requests.post(
        f"{_api_url()}/security/user/authenticate",
        auth=(user, pw),
        verify=_verify(),
        timeout=10,
    )
    r.raise_for_status()
    token = r.json().get("data", {}).get("token")
    _api_token_cache["token"] = token
    _api_token_cache["exp"] = time.time() + 850  # tokens valid ~900s
    return token


def _api_get(path: str, params: Optional[dict] = None, timeout: int = 10) -> dict:
    r = requests.get(
        f"{_api_url()}{path}",
        headers={"Authorization": f"Bearer {_api_token()}"},
        params=params or {},
        verify=_verify(),
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


# ── MCP ────────────────────────────────────────────────────────────────────────
mcp = FastMCP("wazuh")


@mcp.tool()
def wazuh_health() -> dict:
    """Confirm indexer + API reachable and auth works. Non-destructive."""
    out = {
        "indexer_url": _indexer_url(),
        "api_url":     _api_url(),
        "verify_tls":  _verify(),
    }
    try:
        r = requests.get(f"{_indexer_url()}/_cluster/health", auth=_indexer_auth(),
                         verify=_verify(), timeout=5)
        out["indexer"] = {"status_code": r.status_code,
                          "cluster_status": r.json().get("status") if r.ok else None}
    except Exception as e:
        out["indexer"] = f"error: {e}"
    try:
        _api_token()
        out["api"] = "token_ok"
    except Exception as e:
        out["api"] = f"error: {e}"
    return out


@mcp.tool()
def wazuh_alerts(hours: int = 24, rule_id: str = "", min_level: int = 0,
                 agent_name: str = "", limit: int = 50) -> list[dict]:
    """Fetch Wazuh alerts from the indexer.

    Filters are AND-combined. Omit to broaden. Timestamps are UTC.
    """
    since = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).isoformat() + "Z"
    must: list[dict] = [{"range": {"timestamp": {"gte": since}}}]
    if rule_id:
        must.append({"term": {"rule.id": rule_id}})
    if min_level > 0:
        must.append({"range": {"rule.level": {"gte": min_level}}})
    if agent_name:
        must.append({"match": {"agent.name": agent_name}})
    body = {
        "size": min(limit, 500),
        "sort": [{"timestamp": "desc"}],
        "query": {"bool": {"must": must}},
    }
    try:
        return _hits_to_alerts(_indexer_search(body))
    except Exception as e:
        return [{"error": str(e)}]


@mcp.tool()
def wazuh_top_rules(hours: int = 24, size: int = 20) -> list[dict]:
    """Aggregate: top firing rule IDs over the last N hours."""
    since = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).isoformat() + "Z"
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": since}}},
        "aggs": {
            "top_rules": {
                "terms": {"field": "rule.id", "size": size},
                "aggs": {"desc": {"terms": {"field": "rule.description.keyword", "size": 1}}}
            }
        }
    }
    try:
        res = _indexer_search(body)
        buckets = res.get("aggregations", {}).get("top_rules", {}).get("buckets", [])
        out = []
        for b in buckets:
            desc_buckets = b.get("desc", {}).get("buckets", [])
            out.append({
                "rule_id":     b["key"],
                "count":       b["doc_count"],
                "description": (desc_buckets[0]["key"] if desc_buckets else None),
            })
        return out
    except Exception as e:
        return [{"error": str(e)}]


@mcp.tool()
def wazuh_top_agents(hours: int = 24, size: int = 20) -> list[dict]:
    """Aggregate: agents with most alerts over last N hours."""
    since = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).isoformat() + "Z"
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": since}}},
        "aggs": {"top_agents": {"terms": {"field": "agent.name", "size": size}}},
    }
    try:
        res = _indexer_search(body)
        return [{"agent": b["key"], "count": b["doc_count"]}
                for b in res.get("aggregations", {}).get("top_agents", {}).get("buckets", [])]
    except Exception as e:
        return [{"error": str(e)}]


@mcp.tool()
def wazuh_search(query_string: str, hours: int = 24, limit: int = 50) -> list[dict]:
    """Lucene query_string search against wazuh-alerts-*.

    Example queries:
      'rule.groups:authentication_failed'
      'data.srcip:1.2.3.4 AND rule.level:>=10'
      'agent.name:proxmox AND rule.description:*ssh*'
    """
    since = (datetime.datetime.utcnow() - datetime.timedelta(hours=hours)).isoformat() + "Z"
    body = {
        "size": min(limit, 500),
        "sort": [{"timestamp": "desc"}],
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": since}}},
                    {"query_string": {"query": query_string}},
                ]
            }
        },
    }
    try:
        return _hits_to_alerts(_indexer_search(body))
    except Exception as e:
        return [{"error": str(e)}]


@mcp.tool()
def wazuh_agents(status: str = "", limit: int = 100) -> list[dict]:
    """List registered Wazuh agents via the manager API.

    status filter: active|disconnected|never_connected|pending  (omit for all).
    """
    params = {"limit": min(limit, 500)}
    if status:
        params["status"] = status
    try:
        res = _api_get("/agents", params=params)
        return res.get("data", {}).get("affected_items", [])
    except Exception as e:
        return [{"error": str(e)}]


@mcp.tool()
def wazuh_rule(rule_id: str) -> dict:
    """Fetch a Wazuh rule definition from the manager API."""
    try:
        res = _api_get(f"/rules", params={"rule_ids": rule_id, "limit": 1})
        items = res.get("data", {}).get("affected_items", [])
        return items[0] if items else {"error": f"rule {rule_id} not found"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def wazuh_fim(agent_name: str = "", hours: int = 24, limit: int = 50) -> list[dict]:
    """File-integrity monitoring events (syscheck). Optionally scoped to one agent."""
    return wazuh_search(
        f"rule.groups:syscheck" + (f" AND agent.name:{agent_name}" if agent_name else ""),
        hours=hours, limit=limit,
    )


if __name__ == "__main__":
    mcp.run()
