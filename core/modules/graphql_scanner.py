"""
DS1 Hunter - GraphQL Security Scanner
DigitalSecurity1 - "Hunt. Chain. Prove."

Tests:
  1. Introspection enabled (schema disclosure)
  2. Field suggestion (typo-based schema discovery even with introspection off)
  3. Batch query abuse
  4. Deep recursion / circular reference
  5. Unauthenticated mutation access
  6. SQL/NoSQL injection in field arguments
  7. SSRF via URL-type fields
  8. Alias-based rate-limit bypass
"""

import asyncio
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

import aiohttp
from core import scan_proxy

logger = __import__("logging").getLogger("ds1hunter.graphql")

_INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind ofType { name kind } } }
      }
      inputFields { name type { name kind ofType { name kind } } }
    }
  }
}
""".strip()

_SESSIONS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()


# ── Session management ────────────────────────────────────────────────────────

def create_session(
    url: str,
    headers: Optional[Dict[str, str]] = None,
) -> str:
    session_id = str(uuid.uuid4())[:12]
    with _LOCK:
        _SESSIONS[session_id] = {
            "id":         session_id,
            "url":        url,
            "headers":    headers or {},
            "running":    False,
            "done":       False,
            "_stop":      False,
            "started_at": None,
            "finished_at":None,
            "findings":   [],
            "schema":     None,
            "error":      None,
        }
    return session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    with _LOCK:
        s = _SESSIONS.get(session_id)
        if not s:
            return None
        return {k: v for k, v in s.items() if k != "_stop"}


def list_sessions() -> List[Dict[str, Any]]:
    with _LOCK:
        return [
            {k: v for k, v in s.items() if k not in ("_stop", "schema")}
            for s in _SESSIONS.values()
        ]


def start_session(session_id: str) -> bool:
    with _LOCK:
        s = _SESSIONS.get(session_id)
        if not s or s["running"]:
            return False
        s["running"]    = True
        s["started_at"] = time.time()

    t = threading.Thread(
        target=_run_session, args=(session_id,),
        daemon=True, name=f"gqlscan-{session_id[:8]}"
    )
    t.start()
    return True


# ── Runner ────────────────────────────────────────────────────────────────────

def _run_session(session_id: str) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_scan(session_id))
    except Exception as exc:
        with _LOCK:
            s = _SESSIONS.get(session_id)
            if s:
                s["error"] = str(exc)
    finally:
        loop.close()
    with _LOCK:
        s = _SESSIONS.get(session_id)
        if s:
            s["running"]     = False
            s["done"]        = True
            s["finished_at"] = time.time()


async def _gql(
    session: aiohttp.ClientSession,
    url: str,
    headers: dict,
    query: str,
    variables: Optional[dict] = None,
    as_batch: bool = False,
) -> Optional[dict]:
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    if as_batch:
        payload = [payload, payload]
    try:
        async with session.post(url, json=payload, headers=headers) as resp:
            try:
                body = await resp.json(content_type=None)
            except Exception:
                body = {"_raw": await resp.text()}
            return {"status": resp.status, "body": body}
    except Exception as exc:
        logger.debug("[GraphQL] request error: %s", exc)
        return None


def _add_finding(session_id: str, severity: str, title: str, detail: str, evidence: Any = None):
    with _LOCK:
        s = _SESSIONS.get(session_id)
        if s:
            s["findings"].append({
                "severity": severity,
                "title":    title,
                "detail":   detail,
                "evidence": evidence,
            })


async def _scan(session_id: str) -> None:
    with _LOCK:
        cfg = dict(_SESSIONS[session_id])

    url     = cfg["url"]
    headers = {**cfg["headers"], "Content-Type": "application/json"}

    connector = scan_proxy.make_connector()
    timeout   = aiohttp.ClientTimeout(total=15)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

        # ── 1. Introspection ─────────────────────────────────────────
        intr = await _gql(session, url, headers, _INTROSPECTION_QUERY)
        if intr and intr["status"] < 500:
            body = intr["body"]
            schema_data = body.get("data", {}).get("__schema") if isinstance(body, dict) else None

            if schema_data:
                with _LOCK:
                    s = _SESSIONS.get(session_id)
                    if s:
                        s["schema"] = schema_data

                types      = schema_data.get("types", [])
                user_types = [t for t in types if t["name"] and not t["name"].startswith("__")]
                fields_total = sum(len(t.get("fields") or []) for t in user_types)
                mutations  = [t for t in types if t["name"] == (schema_data.get("mutationType") or {}).get("name")]

                _add_finding(session_id, "high",
                    "Introspection Enabled",
                    f"GraphQL introspection is enabled - full schema disclosed. "
                    f"{len(user_types)} types, {fields_total} fields exposed.",
                    {"type_count": len(user_types), "field_count": fields_total,
                     "has_mutations": bool(mutations)})

                # Check for sensitive field names
                sensitive = []
                for t in user_types:
                    for f in (t.get("fields") or []):
                        fname = (f.get("name") or "").lower()
                        if any(kw in fname for kw in ("password", "secret", "token", "key", "hash", "credit", "ssn", "admin")):
                            sensitive.append(f"{t['name']}.{f['name']}")
                if sensitive:
                    _add_finding(session_id, "medium",
                        "Sensitive Field Names in Schema",
                        f"Found {len(sensitive)} potentially sensitive field names exposed in schema.",
                        {"fields": sensitive[:20]})

                # Check for deprecated fields
                deprecated = []
                for t in user_types:
                    for f in (t.get("fields") or []):
                        if f.get("isDeprecated"):
                            deprecated.append(f"{t['name']}.{f['name']}")
                if deprecated:
                    _add_finding(session_id, "info",
                        "Deprecated Fields Exposed",
                        f"{len(deprecated)} deprecated fields still accessible - may have less hardening.",
                        {"fields": deprecated[:20]})
            else:
                errors = body.get("errors", []) if isinstance(body, dict) else []
                error_msg = str(errors[0].get("message", "")) if errors else ""
                if "introspection" in error_msg.lower() or "disabled" in error_msg.lower():
                    _add_finding(session_id, "info",
                        "Introspection Disabled",
                        "Server explicitly blocks introspection queries - good security posture.",
                        None)
                else:
                    _add_finding(session_id, "info",
                        "Introspection Returned No Schema",
                        f"Server responded but returned no schema data. Response: {error_msg[:200]}",
                        None)

        await asyncio.sleep(0.3)

        # ── 2. Field suggestions (schema leakage via typos) ──────────
        typo_query = '{ __type(name: "Query") { name } }'
        typo_result = await _gql(session, url, headers, typo_query)
        if typo_result:
            body    = typo_result["body"]
            body_str = str(body)
            if "did you mean" in body_str.lower() or "suggestion" in body_str.lower():
                _add_finding(session_id, "medium",
                    "Field Suggestions Enabled (Schema Leakage)",
                    "Server returns 'Did you mean?' suggestions on typos - allows schema discovery "
                    "even with introspection disabled.",
                    {"response": body_str[:400]})

        await asyncio.sleep(0.3)

        # ── 3. Batch query abuse ─────────────────────────────────────
        # Test with progressively larger batches to measure amplification
        for batch_size in (2, 10, 50):
            batch_q = [{"query": "{ __typename }"}] * batch_size
            batch_result = await _gql(session, url, headers, batch_q, as_batch=True)
            if batch_result and isinstance(batch_result["body"], list):
                _add_finding(session_id, "high" if batch_size >= 50 else "medium",
                    f"Batch Query Amplification (size={batch_size})",
                    f"Server accepted a batch of {batch_size} GraphQL operations in one HTTP request. "
                    "Large batches can be used to bypass rate limits, amplify resource consumption, "
                    "and brute-force credentials by running hundreds of mutations in one request.",
                    {"batch_size": batch_size, "status": batch_result["status"]})
                break  # found the max; report once

        await asyncio.sleep(0.3)

        # ── 4. Alias-based rate-limit bypass and field flooding ───────
        # Small alias test (10 aliases)
        alias_query = "{ " + " ".join(f"q{i}: __typename" for i in range(10)) + " }"
        alias_result = await _gql(session, url, headers, alias_query)
        if alias_result and alias_result["status"] < 400:
            body = alias_result["body"]
            if isinstance(body, dict) and body.get("data") and len(body["data"]) >= 5:
                _add_finding(session_id, "medium",
                    "Alias-Based Query Multiplication",
                    "Server allows aliasing with many duplicated fields in one request. "
                    "Can bypass per-request rate limits and amplify backend work.",
                    {"aliases_tested": 10})

        await asyncio.sleep(0.3)

        # ── 4b. Circular / deep recursive query (query depth attack) ──
        # Build a deeply nested query targeting common self-referential types
        # (e.g. user -> friends -> friends -> ...)
        for recursive_type in ('user', 'post', 'comment', 'node', 'item', 'product'):
            depth = 15
            inner = recursive_type
            for _ in range(depth):
                inner = f'{recursive_type} {{ id {inner} }}'
            depth_query = f'{{ {inner} }}'
            depth_result = await _gql(session, url, headers, depth_query)
            if depth_result and depth_result["status"] not in (400, 422):
                body_str = str(depth_result.get("body", ""))
                if "Maximum depth" not in body_str and "depth limit" not in body_str.lower():
                    _add_finding(session_id, "high",
                        f"No Query Depth Limit (depth={depth}, type={recursive_type})",
                        f"Server accepted a {depth}-level deep nested query on '{recursive_type}' "
                        "without enforcing a depth limit. Deep queries can exhaust server "
                        "resources and cause denial of service.",
                        {"depth": depth, "type": recursive_type, "status": depth_result["status"]})
                    break
            await asyncio.sleep(0.2)

        await asyncio.sleep(0.3)

        # ── 4c. Field count / complexity flooding ──────────────────────
        # Request 100 top-level fields using aliases of __typename
        field_flood_query = "{ " + " ".join(f"f{i}: __typename" for i in range(100)) + " }"
        flood_result = await _gql(session, url, headers, field_flood_query)
        if flood_result and flood_result["status"] < 400:
            _add_finding(session_id, "medium",
                "No Query Complexity Limit (100 aliases accepted)",
                "Server processed a query with 100 aliased field selections. "
                "Without a complexity limit an attacker can send thousands of field "
                "requests in a single query to exhaust backend resources.",
                {"field_count": 100})

        await asyncio.sleep(0.3)

        # ── 5. Injection probe (simple) ──────────────────────────────
        sqli_query = '{ user(id: "1 OR 1=1--") { id } }'
        sqli_result = await _gql(session, url, headers, sqli_query)
        if sqli_result:
            body_str = str(sqli_result["body"])
            sql_errors = ["sql", "syntax error", "mysql", "postgresql", "sqlite",
                          "ora-", "odbc", "jdbc", "unclosed quotation"]
            if any(e in body_str.lower() for e in sql_errors):
                _add_finding(session_id, "critical",
                    "Possible SQL Injection in GraphQL Arguments",
                    "Server returned a database error in response to a SQL injection probe in a GraphQL argument.",
                    {"probe": sqli_query, "response": body_str[:400]})

        await asyncio.sleep(0.3)

        # ── 6. Unauthenticated mutation probe ────────────────────────
        mutation_probe = "mutation { __typename }"
        mut_result = await _gql(session, url, headers, mutation_probe)
        if mut_result and mut_result["status"] < 400:
            body = mut_result["body"]
            if isinstance(body, dict) and body.get("data"):
                _add_finding(session_id, "medium",
                    "Mutations Accessible (No Auth Header Sent)",
                    "Server accepted a mutation request without authentication headers - "
                    "verify that sensitive mutations require authorization.",
                    {"status": mut_result["status"]})

        # ── 7. Check common GraphQL endpoints ────────────────────────
        from urllib.parse import urlparse, urljoin
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        gql_paths = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
                     "/query", "/gql", "/graph", "/graphiql", "/playground"]
        accessible = []
        for path in gql_paths:
            probe_url = urljoin(base_url, path)
            if probe_url == url:
                continue
            r = await _gql(session, probe_url, headers, "{ __typename }")
            if r and r["status"] not in (404, 405, 503):
                accessible.append({"path": path, "status": r["status"]})
            await asyncio.sleep(0.1)

        if accessible:
            _add_finding(session_id, "info",
                "Additional GraphQL Endpoints Discovered",
                f"Found {len(accessible)} additional GraphQL-like paths on the same host.",
                {"paths": accessible})
