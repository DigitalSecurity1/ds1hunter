"""
DS1 Hunter Proxy - REST API Views

GET  /api/proxy/status/          proxy running state, intercept mode, port
GET  /api/proxy/history/         paginated request history
GET  /api/proxy/history/<id>/    single entry detail
DELETE /api/proxy/history/       clear history
POST /api/proxy/intercept/       enable/disable intercept mode
POST /api/proxy/forward/<id>/    forward a held request (with optional edits)
POST /api/proxy/drop/<id>/       drop a held request
GET  /api/proxy/pending/         list entry IDs currently held in intercept queue
POST /api/proxy/replay/          replay a request (edited or original)
GET  /api/proxy/ca.crt           download the CA certificate
POST /api/proxy/send-to-scanner/ export an entry URL to a new Hunt
"""

import asyncio
import logging

import aiohttp
from django.http import HttpResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from core.proxy import history as hist
from apps.proxy.apps import get_proxy_server

logger = logging.getLogger("ds1hunter.proxy.views")


def _apply_accuracy(session: dict | None) -> dict | None:
    """Run findings through the accuracy pipeline (score, dedupe, FP filter) before serialisation."""
    if not session or not session.get("findings"):
        return session
    from core.accuracy import process_findings
    return {**session, "findings": process_findings(session["findings"])}


class ProxyStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        srv = get_proxy_server()
        return Response({
            "running":          bool(srv and srv.running),
            "host":             getattr(srv, "host", "127.0.0.1") if srv else "127.0.0.1",
            "port":             getattr(srv, "port", 8082) if srv else 8082,
            "intercept_mode":   hist.intercept_enabled(),
            "history_count":    len(hist.get_history(limit=9999)),
            "pending_count":    len(hist.pending_intercepts()),
        })


class ProxyHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        limit  = int(request.query_params.get("limit", 100))
        offset = int(request.query_params.get("offset", 0))
        items  = hist.get_history(limit=limit, offset=offset)
        # Strip large body from list view - detail view has full content
        slim = []
        for e in items:
            slim.append({
                "id":              e["id"],
                "timestamp":       e["timestamp"],
                "scheme":          e["scheme"],
                "method":          e["method"],
                "url":             e["url"],
                "response_status": e.get("response_status"),
                "intercepted":     e.get("intercepted", False),
                "dropped":         e.get("dropped", False),
                "body_size":       len(e.get("response_body", "") or ""),
            })
        return Response({"results": slim, "count": len(slim)})

    def delete(self, request):
        hist.clear_history()
        return Response({"detail": "History cleared."})


class ProxyEntryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, entry_id):
        entry = hist.get_entry(entry_id)
        if not entry:
            return Response({"detail": "Not found."}, status=404)
        return Response(entry)


class ProxyInterceptView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        enabled = bool(request.data.get("enabled", False))
        hist.set_intercept(enabled)
        return Response({"intercept_mode": hist.intercept_enabled()})


class ProxyForwardView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, entry_id):
        edited = request.data.get("edited")   # optional dict with method/url/headers/body
        ok = hist.resolve_intercept(entry_id, "forward", edited)
        if not ok:
            return Response({"detail": "Entry not found in intercept queue."}, status=404)
        return Response({"detail": "Forwarded."})


class ProxyDropView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, entry_id):
        ok = hist.resolve_intercept(entry_id, "drop")
        if not ok:
            return Response({"detail": "Entry not found in intercept queue."}, status=404)
        return Response({"detail": "Dropped."})


class ProxyPendingView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        ids = hist.pending_intercepts()
        entries = [hist.get_entry(i) for i in ids if hist.get_entry(i)]
        return Response({"pending": entries})


class ProxyReplayView(APIView):
    """Replay a captured request (optionally with edits) and return the response."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        entry_id = request.data.get("entry_id")
        edited   = request.data.get("edited", {})

        entry = hist.get_entry(entry_id) if entry_id else None
        if not entry and not edited:
            return Response({"detail": "Provide entry_id or edited request."}, status=400)

        method  = edited.get("method")  or (entry["method"]  if entry else "GET")
        url     = edited.get("url")     or (entry["url"]     if entry else "")
        headers = edited.get("request_headers") or (entry.get("request_headers", {}) if entry else {})
        body    = edited.get("request_body")    or (entry.get("request_body", "")    if entry else "")

        if not url:
            return Response({"detail": "url is required."}, status=400)

        # Fire the replayed request using aiohttp
        try:
            loop = asyncio.new_event_loop()
            resp_status, resp_headers, resp_body = loop.run_until_complete(
                _do_replay(method, url, headers, body)
            )
            loop.close()
        except Exception as exc:
            return Response({"detail": f"Replay error: {exc}"}, status=500)

        # Save replayed entry to history
        new_entry = hist.make_entry(
            method=method, url=url,
            request_headers=headers,
            request_body=body.encode(errors="replace") if isinstance(body, str) else (body or b""),
            response_status=resp_status,
            response_headers=resp_headers,
            response_body=resp_body,
            scheme=url.split("://")[0] if "://" in url else "https",
        )
        hist.add_entry(new_entry)

        return Response({
            "entry_id":        new_entry["id"],
            "response_status": resp_status,
            "response_headers": resp_headers,
            "response_body":   resp_body.decode(errors="replace") if resp_body else "",
        })


class ProxyCACertView(APIView):
    """Download the DS1 Hunter Proxy CA certificate (install in browser to trust HTTPS)."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.proxy.ca import ca_cert_pem
        pem = ca_cert_pem()
        response = HttpResponse(pem, content_type="application/x-pem-file")
        response["Content-Disposition"] = 'attachment; filename="ds1hunter-proxy-ca.crt"'
        return response

    def post(self, request):
        """Regenerate the CA (creates a new cert - re-import into browser afterward)."""
        from core.proxy.ca import regenerate_ca
        regenerate_ca()
        return Response({"detail": "CA regenerated. Download and re-import ds1hunter-proxy-ca.crt into your browser."})


class ProxySendToScannerView(APIView):
    """
    Create a Hunt pre-populated with Active Scan data.
    When seeded endpoints are provided Phase 1 crawl is skipped entirely.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        entry_id = request.data.get("entry_id")
        entry    = hist.get_entry(entry_id) if entry_id else None
        url      = request.data.get("url") or (entry["url"] if entry else None)

        if not url:
            return Response({"detail": "url or entry_id required."}, status=400)

        from urllib.parse import urlparse
        parsed = urlparse(url)
        target = f"{parsed.scheme}://{parsed.netloc}"

        # Active Scan data passed from the frontend
        seeded_endpoints = request.data.get("seeded_endpoints", [])
        seeded_findings  = request.data.get("seeded_findings",  [])

        # Normalise endpoints: accept either full URL strings or dicts with a "url" key
        normalised = []
        for ep in seeded_endpoints:
            if isinstance(ep, str):
                normalised.append({"url": ep, "method": "GET", "source": "active_scan"})
            elif isinstance(ep, dict) and ep.get("url"):
                ep.setdefault("source", "active_scan")
                normalised.append(ep)

        from apps.hunts.models import Hunt
        from apps.hunts.views import _dispatch_hunt
        hunt = Hunt.objects.create(
            target           = target,
            created_by       = request.user,
            scan_depth       = "normal",
            seeded_endpoints = normalised,
            seeded_findings  = seeded_findings,
        )
        _dispatch_hunt(str(hunt.id))

        skipped_crawl = len(normalised) > 0
        return Response({
            "hunt_id":       str(hunt.id),
            "target":        target,
            "seeded_count":  len(normalised),
            "skipped_crawl": skipped_crawl,
            "detail": (
                f"Hunt created with {len(normalised)} pre-seeded endpoints - Phase 1 crawl skipped."
                if skipped_crawl else
                "Hunt created and queued."
            ),
        }, status=201)


# ── Match & Replace ──────────────────────────────────────────────────────────

class MatchReplaceListView(APIView):
    """GET list / POST create a rule."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.proxy.match_replace import get_rules
        return Response({"rules": get_rules()})

    def post(self, request):
        from core.proxy.match_replace import add_rule
        d = request.data
        rule = add_rule(
            name        = d.get("name", "rule"),
            scope       = d.get("scope", "both"),
            match_type  = d.get("match_type", "literal"),
            match_str   = d.get("match", ""),
            replace_str = d.get("replace", ""),
            enabled     = bool(d.get("enabled", True)),
        )
        return Response(rule, status=201)


class MatchReplaceDetailView(APIView):
    """PATCH update / DELETE remove a rule by id."""
    permission_classes = [IsAuthenticated]

    def patch(self, request, rule_id: int):
        from core.proxy.match_replace import update_rule
        updated = update_rule(rule_id, **request.data)
        if updated is None:
            return Response({"detail": "Not found."}, status=404)
        return Response(updated)

    def delete(self, request, rule_id: int):
        from core.proxy.match_replace import delete_rule
        if not delete_rule(rule_id):
            return Response({"detail": "Not found."}, status=404)
        return Response(status=204)


# ── Intruder ──────────────────────────────────────────────────────────────────

class IntruderStartView(APIView):
    """POST to launch an intruder attack. Returns attack_id."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from core.proxy.intruder import start_attack
        template       = request.data.get("template", "")
        attack_type    = request.data.get("attack_type", "sniper")
        payload_lists  = request.data.get("payload_lists", [[]])
        grep_match     = request.data.get("grep_match") or None
        grep_extract   = request.data.get("grep_extract") or None
        rate_limit     = float(request.data.get("rate_limit", 0.05))
        timeout        = int(request.data.get("timeout", 15))
        follow_redirects = bool(request.data.get("follow_redirects", False))
        payload_processing = request.data.get("payload_processing", []) or []

        if not template:
            return Response({"detail": "template is required."}, status=400)

        attack_id = start_attack(
            template=template,
            attack_type=attack_type,
            payload_lists=payload_lists,
            grep_match=grep_match,
            grep_extract=grep_extract,
            rate_limit=rate_limit,
            timeout=timeout,
            follow_redirects=follow_redirects,
            payload_processing=payload_processing,
        )
        return Response({"attack_id": attack_id}, status=201)


class IntruderStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, attack_id: str):
        from core.proxy.intruder import get_attack
        attack = get_attack(attack_id)
        if not attack:
            return Response({"detail": "Not found."}, status=404)
        return Response({
            "id":          attack["id"],
            "attack_type": attack["attack_type"],
            "running":     attack["running"],
            "total":       attack["total"],
            "done":        attack["done"],
            "started_at":  attack["started_at"],
            "finished_at": attack["finished_at"],
            "grep_match":  attack["grep_match"],
            "grep_extract":attack["grep_extract"],
            "positions":   attack["positions"],
        })


class IntruderResultsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, attack_id: str):
        from core.proxy.intruder import get_results
        offset = int(request.query_params.get("offset", 0))
        limit  = int(request.query_params.get("limit", 500))
        results = get_results(attack_id, offset=offset, limit=limit)
        return Response({"results": results, "count": len(results)})


class IntruderStopView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, attack_id: str):
        from core.proxy.intruder import stop_attack
        ok = stop_attack(attack_id)
        if not ok:
            return Response({"detail": "Not found."}, status=404)
        return Response({"detail": "Stop signal sent."})


class IntruderListView(APIView):
    """List all attacks (metadata only, no results)."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.proxy.intruder import list_attacks
        return Response({"attacks": list_attacks()})


# ── Scope Manager ────────────────────────────────────────────────────────────

class ScopeListView(APIView):
    """GET list / POST create a scope rule."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.proxy.scope import get_rules
        return Response({"rules": get_rules()})

    def post(self, request):
        from core.proxy.scope import add_rule
        d = request.data
        rule = add_rule(
            pattern    = d.get("pattern", ""),
            rule_type  = d.get("type", "include"),
            match_type = d.get("match_type", "prefix"),
            enabled    = bool(d.get("enabled", True)),
            comment    = d.get("comment", ""),
        )
        return Response(rule, status=201)


class ScopeDetailView(APIView):
    """PATCH update / DELETE remove a scope rule."""
    permission_classes = [IsAuthenticated]

    def patch(self, request, rule_id: int):
        from core.proxy.scope import update_rule
        updated = update_rule(rule_id, **request.data)
        if updated is None:
            return Response({"detail": "Not found."}, status=404)
        return Response(updated)

    def delete(self, request, rule_id: int):
        from core.proxy.scope import delete_rule
        if not delete_rule(rule_id):
            return Response({"detail": "Not found."}, status=404)
        return Response(status=204)


class ScopeCheckView(APIView):
    """POST {url} → {in_scope: bool}"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from core.proxy.scope import is_in_scope
        url = request.data.get("url", "")
        return Response({"url": url, "in_scope": is_in_scope(url)})


# ── Passive Scanner ───────────────────────────────────────────────────────────

class PassiveFindingsView(APIView):
    """GET passive scan findings. POST to run on all existing history."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.passive_scanner import get_findings, findings_count
        offset = int(request.query_params.get("offset", 0))
        limit  = int(request.query_params.get("limit", 500))
        return Response({
            "findings": get_findings(offset=offset, limit=limit),
            "total":    findings_count(),
        })

    def post(self, request):
        """Trigger passive scan on all unscanned history entries."""
        from core.modules.passive_scanner import scan_history
        limit  = int(request.data.get("limit", 500))
        items  = hist.get_history(limit=limit)
        new    = scan_history(items)
        return Response({"scanned": len(items), "new_findings": len(new)})

    def delete(self, request):
        from core.modules.passive_scanner import clear_findings
        clear_findings()
        return Response({"detail": "Findings cleared."})


# ── Scan Proxy Config ────────────────────────────────────────────────────────

class ScanProxyConfigView(APIView):
    """GET / PUT the global outbound scan proxy configuration."""
    permission_classes = [IsAuthenticated]

    def _cfg(self):
        from apps.proxy.models import ScanProxyConfig
        cfg, _ = ScanProxyConfig.objects.get_or_create(pk=1)
        return cfg

    def _serialize(self, cfg):
        return {
            "enabled":    cfg.enabled,
            "proxy_type": cfg.proxy_type,
            "proxy_url":  cfg.proxy_url,
            "rotate":     cfg.rotate,
            "proxy_list": cfg.proxy_list,
        }

    def get(self, request):
        return Response(self._serialize(self._cfg()))

    def put(self, request):
        cfg = self._cfg()
        cfg.enabled    = bool(request.data.get("enabled", False))
        cfg.proxy_type = request.data.get("proxy_type", "http")
        cfg.proxy_url  = (request.data.get("proxy_url") or "").strip()
        cfg.rotate     = bool(request.data.get("rotate", False))
        cfg.proxy_list = (request.data.get("proxy_list") or "").strip()
        cfg.save()
        try:
            from core import scan_proxy
            scan_proxy.invalidate_cache()
        except Exception:
            pass
        return Response(self._serialize(cfg))


class ScanProxyTestView(APIView):
    """POST - fire a test request through the proxy and return the visible IP."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from apps.proxy.models import ScanProxyConfig
        from core.scan_proxy import _ensure_scheme
        cfg, _ = ScanProxyConfig.objects.get_or_create(pk=1)
        raw_url = (request.data.get("proxy_url") or cfg.proxy_url or "").strip()
        if not raw_url:
            return Response({"detail": "No proxy URL provided or configured."}, status=400)
        # Normalise the URL the same way the live scanner does
        proxy_url = _ensure_scheme(raw_url, cfg.proxy_type or "http")
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_test_proxy_connection(proxy_url))
        except Exception as exc:
            return Response({"error": str(exc)}, status=502)
        finally:
            loop.close()
        return Response(result)


async def _test_proxy_connection(proxy_url: str) -> dict:
    """
    Connect through the proxy and return the visible IP.

    SECURITY: no fallback to direct connection. If the proxy fails this
    function raises so the caller receives a clear error, never a silent
    real-IP leak.

    For SOCKS5/Tor proxies:
      - rdns=True is mandatory so DNS resolves inside Tor (prevents DNS leaks)
      - socks5h:// scheme is used (remote hostname resolution)
      - Timeout is extended to 45 s because Tor circuit establishment is slow
      - check.torproject.org confirms the traffic exits through Tor
    """
    from aiohttp_socks import ProxyConnector
    from core.scan_proxy import _ensure_scheme

    is_socks5 = "socks5" in proxy_url.lower() or "socks://" in proxy_url.lower()

    # Normalise to socks5h:// so the proxy server resolves hostnames — required
    # by Tor and prevents DNS leaks regardless of which SOCKS5 daemon is used.
    if is_socks5 and not proxy_url.startswith("socks5h://"):
        proxy_url = _ensure_scheme(proxy_url, "socks5")

    # Tor needs more time: first connection builds a circuit (3 hops).
    total_timeout = 45 if is_socks5 else 20
    timeout = aiohttp.ClientTimeout(total=total_timeout, connect=30)

    # rdns=True: hostname sent to the proxy for resolution, not resolved locally.
    # Without this Tor connections fail and local DNS is used (IP leak).
    connector = ProxyConnector.from_url(proxy_url, ssl=False, rdns=True)

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.get("https://api.ipify.org?format=json") as resp:
                data = await resp.json()
                ip   = data.get("ip", "unknown")
    except Exception as exc:
        err_hint = ""
        if is_socks5:
            err_hint = (
                " For Tor: run 'sudo systemctl start tor' and confirm "
                "port 9050 is listening with 'ss -tlnp | grep 9050'."
            )
        raise Exception(
            f"Proxy connection failed at {proxy_url}.{err_hint} Error: {exc}"
        ) from exc

    is_tor  = None
    country = None

    # For SOCKS5 proxies verify the exit is actually a Tor node.
    if is_socks5:
        try:
            tor_connector = ProxyConnector.from_url(proxy_url, ssl=False, rdns=True)
            tor_timeout   = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(connector=tor_connector, timeout=tor_timeout) as session:
                async with session.get("https://check.torproject.org/api/ip") as r2:
                    tor_data = await r2.json()
                    is_tor   = tor_data.get("IsTor", False)
                    ip       = tor_data.get("IP", ip)
        except Exception:
            is_tor = None  # check.torproject.org unreachable — mark unknown

    # Geo-locate exit IP using a direct connection (not through proxy — no leak
    # risk here since we are only geo-locating an already-public IP).
    try:
        direct_timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=direct_timeout) as session:
            async with session.get(f"https://ipapi.co/{ip}/json/") as r3:
                geo     = await r3.json()
                country = geo.get("country_name")
    except Exception:
        pass

    return {"ip": ip, "country": country, "is_tor": is_tor}


# ── Internal replay helper ────────────────────────────────────────────────────

async def _do_replay(method, url, headers, body):
    from core import scan_proxy
    from urllib.parse import urlparse as _urlparse
    _replay_host = _urlparse(url).hostname or ''
    connector = scan_proxy.make_connector(target_host=_replay_host)
    timeout   = aiohttp.ClientTimeout(total=20)
    body_bytes = body.encode(errors="replace") if isinstance(body, str) else (body or b"")

    # Remove hop-by-hop headers that aiohttp manages itself
    clean_headers = {
        k: v for k, v in (headers or {}).items()
        if k.lower() not in ("host", "content-length", "transfer-encoding",
                             "connection", "proxy-connection")
    }

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        async with session.request(
            method, url,
            headers=clean_headers,
            data=body_bytes or None,
            allow_redirects=False,
        ) as resp:
            resp_body    = await resp.read()
            resp_status  = resp.status
            resp_headers = dict(resp.headers)

    return resp_status, resp_headers, resp_body


# ── Param Miner views ─────────────────────────────────────────────────────────

class ParamMinerListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.param_miner import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.param_miner import create_session, start_session
        d   = request.data
        url = (d.get("url") or "").strip()
        if not url:
            return Response({"detail": "url required."}, status=400)
        session_id = create_session(
            url=url,
            method=d.get("method", "GET"),
            headers=d.get("headers", {}),
            body=d.get("body", ""),
            add_to=d.get("add_to", "query"),
        )
        start_session(session_id)
        return Response({"session_id": session_id}, status=201)


class ParamMinerDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.param_miner import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def delete(self, request, session_id):
        from core.modules.param_miner import stop_session
        stop_session(session_id)
        return Response({"detail": "Stop requested."})


# ── JWT Analyzer views ────────────────────────────────────────────────────────

class JWTAnalyzeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from core.modules.jwt_analyzer import parse_token
        token = (request.data.get("token") or "").strip()
        if not token:
            return Response({"detail": "token required."}, status=400)
        return Response(parse_token(token))


class JWTAttackView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from core.modules.jwt_analyzer import (
            parse_token, attack_none, attack_brute,
            attack_rs256_confusion, forge_custom,
        )
        token  = (request.data.get("token") or "").strip()
        attack = request.data.get("attack", "none")

        if not token:
            return Response({"detail": "token required."}, status=400)

        parsed = parse_token(token)
        if "error" in parsed:
            return Response({"detail": parsed["error"]}, status=400)

        if attack == "none":
            modified = request.data.get("modified_payload") or None
            return Response(attack_none(parsed, modified))

        if attack == "brute":
            extra = request.data.get("extra_secrets", [])
            return Response(attack_brute(parsed, extra))

        if attack == "rs256_confusion":
            pubkey = request.data.get("public_key", "")
            modified = request.data.get("modified_payload") or None
            return Response(attack_rs256_confusion(parsed, pubkey, modified))

        if attack == "forge":
            overrides = request.data.get("payload_overrides", {})
            secret    = request.data.get("secret", "")
            alg       = request.data.get("alg_override", "")
            return Response(forge_custom(parsed, overrides, secret, alg))


# ── OpenAPI Scanner ───────────────────────────────────────────────────────────

class OpenAPIListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.openapi_scanner import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.openapi_scanner import create_session, start_session
        spec_content     = request.data.get("spec_content", "")
        base_url         = request.data.get("base_url", "")
        extra_headers    = request.data.get("headers", {})
        auth_header      = request.data.get("auth_header", "")
        if not spec_content:
            return Response({"detail": "spec_content is required."}, status=400)
        try:
            sid = create_session(spec_content, base_url, extra_headers, auth_header)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=400)
        start_session(sid)
        return Response({"session_id": sid}, status=201)


class OpenAPIDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id: str):
        from core.modules.openapi_scanner import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def post(self, request, session_id: str):
        action = (request.data.get("action") or "").lower()
        if action == "pause":
            from core.modules.openapi_scanner import pause_session
            ok = pause_session(session_id)
            return Response({"detail": "paused" if ok else "not running"})
        elif action == "resume":
            from core.modules.openapi_scanner import resume_session
            ok = resume_session(session_id)
            return Response({"detail": "resumed" if ok else "not found"})
        elif action == "stop":
            from core.modules.openapi_scanner import stop_session
            stop_session(session_id)
            return Response({"detail": "stop requested"})
        return Response({"detail": f"unknown action: {action}"}, status=400)

    def delete(self, request, session_id: str):
        from core.modules.openapi_scanner import get_session, stop_session, delete_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        if s.get("running"):
            stop_session(session_id)
            return Response({"detail": "Stop requested."})
        delete_session(session_id)
        return Response(status=204)


class OpenAPIReportView(APIView):
    """POST /api/proxy/openapi/<session_id>/report/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id: str):
        from core.modules.openapi_scanner import get_session
        from apps.reports.generators import OpenAPIReportGenerator

        s = get_session(session_id)
        if not s:
            return Response({"detail": "Session not found."}, status=404)
        if s.get("running"):
            return Response({"detail": "Scan still running."}, status=400)

        fmt = (request.data.get("format") or "pdf").lower()
        if fmt not in ("pdf", "html", "json"):
            return Response({"detail": "format must be pdf, html, or json."}, status=400)

        gen   = OpenAPIReportGenerator(s)
        safe  = (s.get("title","api") or "api").replace(" ","_")[:40]
        fname = f"openapi_{safe}_{session_id[:8]}.{fmt}"

        if fmt == "pdf":
            gen.generate_pdf(fname)
        elif fmt == "html":
            gen.generate_html(fname)
        else:
            gen.generate_json(fname)

        return Response({"filename": fname, "url": f"/api/proxy/scanner-report/{fname}"})


# ── BOLA/IDOR Tester ─────────────────────────────────────────────────────────

class BOLAListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.bola_tester import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.bola_tester import create_session, start_session
        d               = request.data
        url_template    = d.get("url_template", "")
        method          = d.get("method", "GET")
        victim_headers  = d.get("victim_headers", {})
        attacker_headers= d.get("attacker_headers", {})
        id_list         = d.get("id_list") or None
        body_template   = d.get("body_template", "")
        sensitive_fields= d.get("sensitive_fields") or None
        if not url_template:
            return Response({"detail": "url_template is required."}, status=400)
        sid = create_session(url_template, method, victim_headers,
                             attacker_headers, id_list, body_template, sensitive_fields)
        start_session(sid)
        return Response({"session_id": sid}, status=201)


class BOLADetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id: str):
        from core.modules.bola_tester import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def delete(self, request, session_id: str):
        from core.modules.bola_tester import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── CMDi Exploiter ───────────────────────────────────────────────────────────

class CMDiListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.cmdi_exploiter import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.cmdi_exploiter import create_session, start_session
        d = request.data
        url = d.get("url", "")
        if not url:
            return Response({"detail": "url is required."}, status=400)
        hdrs = {}
        for line in (d.get("headers_text") or "").split("\n"):
            idx = line.find(":")
            if idx > 0:
                hdrs[line[:idx].strip()] = line[idx+1:].strip()
        sid = create_session(
            url=url,
            parameter=d.get("parameter", ""),
            method=d.get("method", "GET"),
            post_data=d.get("post_data", ""),
            auth_header=d.get("auth_header", ""),
            cookie=d.get("cookie", ""),
            extra_headers=hdrs or None,
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response({"session_id": sid}, status=201)


class CMDiDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id: str):
        from core.modules.cmdi_exploiter import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def post(self, request, session_id: str):
        from core.modules.cmdi_exploiter import queue_command, generate_reverse_shell
        d = request.data
        # Reverse shell generation (no session needed)
        if d.get("action") == "revshell":
            shell = d.get("shell", "bash")
            lhost = d.get("lhost", "")
            lport = int(d.get("lport", 4444))
            payload = generate_reverse_shell(shell, lhost, lport)
            return Response({"payload": payload})
        # Queue a command
        cmd = d.get("command", "")
        if not cmd:
            return Response({"detail": "command is required."}, status=400)
        ok = queue_command(session_id, cmd)
        if not ok:
            return Response({"detail": "Session not found or not confirmed."}, status=400)
        return Response({"queued": cmd})

    def delete(self, request, session_id: str):
        from core.modules.cmdi_exploiter import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── SQLi Mapper ───────────────────────────────────────────────────────────────

class SQLiMapListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.sqli_mapper import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.sqli_mapper import create_session, start_session
        d = request.data
        url = d.get("url", "")
        if not url:
            return Response({"detail": "url is required."}, status=400)
        sid = create_session(
            url=url,
            parameter=d.get("parameter", ""),
            method=d.get("method", "GET"),
            post_data=d.get("post_data", ""),
            auth_header=d.get("auth_header", ""),
            cookie=d.get("cookie", ""),
            technique=d.get("technique", "auto"),
            extra_headers=d.get("headers", {}) or {},
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response({"session_id": sid}, status=201)


class SQLiMapDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id: str):
        from core.modules.sqli_mapper import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def post(self, request, session_id: str):
        from core.modules.sqli_mapper import request_action
        action = request.data.get("action", "")
        params = request.data.get("params", {})
        if not action:
            return Response({"detail": "action is required."}, status=400)
        ok = request_action(session_id, action, params)
        if not ok:
            return Response({"detail": "Session not found or not yet confirmed."}, status=400)
        return Response({"queued": action})

    def delete(self, request, session_id: str):
        from core.modules.sqli_mapper import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Active Scanner ────────────────────────────────────────────────────────────

class ActiveScanListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.active_scanner import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.active_scanner import create_session, start_session
        d = request.data
        url = d.get("url", "")
        if not url:
            return Response({"detail": "url is required."}, status=400)
        hdrs = {}
        for line in (d.get("headers_text") or "").split("\n"):
            idx = line.find(":")
            if idx > 0:
                hdrs[line[:idx].strip()] = line[idx+1:].strip()
        hdrs.update(d.get("headers", {}) or {})
        sid = create_session(
            url=url,
            auth_header=d.get("auth_header", ""),
            max_depth=int(d.get("max_depth", 3)),
            max_urls=int(d.get("max_urls", 200)),
            checks=d.get("checks") or None,
            extra_headers=hdrs or None,
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response({"session_id": sid}, status=201)


class ActiveScanDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id: str):
        from core.modules.active_scanner import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def post(self, request, session_id: str):
        action = (request.data.get("action") or "").strip()
        if action == "pause":
            from core.modules.active_scanner import pause_session
            ok = pause_session(session_id)
            return Response({"detail": "paused" if ok else "not running"})
        elif action == "resume":
            from core.modules.active_scanner import resume_session
            ok = resume_session(session_id)
            return Response({"detail": "resumed" if ok else "not found"})
        elif action == "stop":
            from core.modules.active_scanner import stop_session
            stop_session(session_id)
            return Response({"detail": "stop requested"})
        return Response({"detail": f"unknown action: {action}"}, status=400)

    def delete(self, request, session_id: str):
        from core.modules.active_scanner import get_session, stop_session, delete_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        if s.get("running"):
            stop_session(session_id)
            return Response({"detail": "Stop requested - session will be removed when scan finishes."})
        delete_session(session_id)
        return Response(status=204)


# ── API Audit ─────────────────────────────────────────────────────────────────

class APIAuditListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.api_audit import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.api_audit import create_session, start_session
        d      = request.data
        url    = d.get("url", "")
        method = d.get("method", "GET")
        headers= d.get("headers", {})
        body   = d.get("body", "")
        checks = d.get("checks") or None
        if not url:
            return Response({"detail": "url is required."}, status=400)
        sid = create_session(url, method, headers, body, checks)
        start_session(sid)
        return Response({"session_id": sid}, status=201)


class APIAuditDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id: str):
        from core.modules.api_audit import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def post(self, request, session_id: str):
        action = (request.data.get("action") or "").lower()
        if action == "pause":
            from core.modules.api_audit import pause_session
            ok = pause_session(session_id)
            return Response({"detail": "paused" if ok else "not running"})
        elif action == "resume":
            from core.modules.api_audit import resume_session
            ok = resume_session(session_id)
            return Response({"detail": "resumed" if ok else "not found"})
        elif action == "stop":
            from core.modules.api_audit import stop_session
            ok = stop_session(session_id)
            return Response({"detail": "stopped" if ok else "not found"})
        return Response({"detail": f"unknown action: {action}"}, status=400)

    def delete(self, request, session_id: str):
        from core.modules.api_audit import get_session, stop_session, delete_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        if s.get("running"):
            stop_session(session_id)
            return Response({"detail": "Stop requested."})
        delete_session(session_id)
        return Response(status=204)


class APIAuditReportView(APIView):
    """POST /api/proxy/api-audit/<session_id>/report/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id: str):
        from core.modules.api_audit import get_session
        from apps.reports.generators import APIAuditReportGenerator

        s = get_session(session_id)
        if not s:
            return Response({"detail": "Session not found."}, status=404)
        if s.get("running"):
            return Response({"detail": "Audit still running."}, status=400)

        fmt = (request.data.get("format") or "pdf").lower()
        if fmt not in ("pdf", "html", "json"):
            return Response({"detail": "format must be pdf, html, or json."}, status=400)

        gen  = APIAuditReportGenerator(s)
        safe = (s.get("url","") or "api").replace("https://","").replace("http://","") \
                   .replace("/","_").replace(":","_")[:40]
        fname = f"api_audit_{safe}_{session_id[:8]}.{fmt}"

        if fmt == "pdf":
            gen.generate_pdf(fname)
        elif fmt == "html":
            gen.generate_html(fname)
        else:
            gen.generate_json(fname)

        return Response({"filename": fname, "url": f"/api/proxy/scanner-report/{fname}"})


# ── API Pen Tester ─────────────────────────────────────────────────────────

class APIPentestListView(APIView):
    """
    GET  /api/proxy/api-pentest/   - list all sessions
    POST /api/proxy/api-pentest/   - create + start a new pen-test session

    POST body (manual endpoints):
    {
        "endpoints": [
            {
                "url":     "https://api.example.com/users/1",
                "method":  "GET",
                "headers": {"Authorization": "Bearer <token>"},
                "body":    ""
            }
        ],
        "global_headers": {"Authorization": "Bearer <token>"},
        "checks": ["sqli", "xss", "auth_bypass", ...]
    }

    POST body (spec import - auto-populate from OpenAPI/Swagger URL):
    {
        "spec_url":      "https://api.example.com/openapi.json",
        "spec_base_url": "https://api.example.com",        // optional override
        "global_headers": {"Authorization": "Bearer <token>"},
        "checks": [...]
    }
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.api_pentester import list_sessions
        return Response({"sessions": list_sessions()})

    def post(self, request):
        from core.modules.api_pentester import create_session, start_session, ALL_CHECKS
        import asyncio as _asyncio
        d = request.data
        global_headers = d.get("global_headers") or {}
        checks         = d.get("checks") or None

        # ── Spec-import path ────────────────────────────────────────────────
        spec_url = (d.get("spec_url") or "").strip()
        if spec_url:
            from core.modules.api_pentester import fetch_and_import_spec
            try:
                _loop = _asyncio.new_event_loop()
                endpoints = _loop.run_until_complete(
                    fetch_and_import_spec(
                        spec_url,
                        base_url=d.get("spec_base_url", ""),
                        extra_headers=global_headers or None,
                    )
                )
                _loop.close()
            except Exception as exc:
                return Response({"detail": str(exc)}, status=400)
            if not endpoints:
                return Response({"detail": "Spec parsed but no endpoints found. Check the spec URL."}, status=400)
        else:
            # ── Manual endpoint list path ───────────────────────────────────
            endpoints = d.get("endpoints") or []
            if not endpoints or not isinstance(endpoints, list):
                return Response(
                    {"detail": "Provide either 'spec_url' (OpenAPI/Swagger) or 'endpoints' list."},
                    status=400,
                )
            for ep in endpoints:
                if not ep.get("url"):
                    return Response({"detail": "Each endpoint must have a url."}, status=400)

        sid = create_session(endpoints, global_headers, checks)
        start_session(sid)
        return Response({"session_id": sid, "endpoints_loaded": len(endpoints)}, status=201)


class APIPentestDetailView(APIView):
    """
    GET    /api/proxy/api-pentest/<session_id>/  - poll session state
    POST   /api/proxy/api-pentest/<session_id>/  - actions: pause|resume|stop
    DELETE /api/proxy/api-pentest/<session_id>/  - stop + delete session
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id: str):
        from core.modules.api_pentester import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def post(self, request, session_id: str):
        action = (request.data.get("action") or "").lower()
        if action == "pause":
            from core.modules.api_pentester import pause_session
            ok = pause_session(session_id)
            return Response({"detail": "paused" if ok else "not running"})
        elif action == "resume":
            from core.modules.api_pentester import resume_session
            ok = resume_session(session_id)
            return Response({"detail": "resumed" if ok else "not found"})
        elif action == "stop":
            from core.modules.api_pentester import stop_session
            ok = stop_session(session_id)
            return Response({"detail": "stopped" if ok else "not found"})
        return Response({"detail": f"unknown action: {action}"}, status=400)

    def delete(self, request, session_id: str):
        from core.modules.api_pentester import get_session, stop_session, delete_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        if s.get("status") == "running":
            stop_session(session_id)
            return Response({"detail": "Stop requested."})
        delete_session(session_id)
        return Response(status=204)


class APIPentestReportView(APIView):
    """POST /api/proxy/api-pentest/<session_id>/report/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id: str):
        from core.modules.api_pentester import get_session
        from apps.reports.generators import APIPentestReportGenerator

        s = get_session(session_id)
        if not s:
            return Response({"detail": "Session not found."}, status=404)
        if s.get("status") == "running":
            return Response({"detail": "Scan still running."}, status=400)

        fmt = (request.data.get("format") or "pdf").lower()
        if fmt not in ("pdf", "html", "json"):
            return Response({"detail": "format must be pdf, html, or json."}, status=400)

        gen   = APIPentestReportGenerator(s)
        first = (s.get("endpoints") or [{}])[0].get("url","api")
        safe  = first.replace("https://","").replace("http://","").replace("/","_").replace(":","_")[:40]
        fname = f"api_pentest_{safe}_{session_id[:8]}.{fmt}"

        if fmt == "pdf":
            gen.generate_pdf(fname)
        elif fmt == "html":
            gen.generate_html(fname)
        else:
            gen.generate_json(fname)

        return Response({"filename": fname, "url": f"/api/proxy/scanner-report/{fname}"})


class APIPentestMetaView(APIView):
    """GET /api/proxy/api-pentest/meta/ - returns check metadata."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.api_pentester import ALL_CHECKS, CHECK_META
        return Response({"checks": ALL_CHECKS, "meta": CHECK_META})


# ── XSS Scanner ───────────────────────────────────────────────────────────────

class XSSListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.xss_scanner import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.xss_scanner import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            checks=d.get("checks") or None,
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class XSSDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.xss_scanner import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.xss_scanner import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── SSTI Detector ─────────────────────────────────────────────────────────────

class SSTIListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.ssti_detector import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.ssti_detector import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class SSTIDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.ssti_detector import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.ssti_detector import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── SSRF Tester ───────────────────────────────────────────────────────────────

class SSRFListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.ssrf_tester import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.ssrf_tester import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            oast_domain=d.get("oast_domain", ""),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class SSRFDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.ssrf_tester import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.ssrf_tester import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── XXE Injector ──────────────────────────────────────────────────────────────

class XXEListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.xxe_injector import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.xxe_injector import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "POST"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            oast_domain=d.get("oast_domain", ""),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class XXEDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.xxe_injector import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.xxe_injector import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Race Condition ────────────────────────────────────────────────────────────

class RaceConditionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.race_condition import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.race_condition import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "POST"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            concurrency=int(d.get("concurrency", 20)),
            rounds=int(d.get("rounds", 3)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class RaceConditionDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.race_condition import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.race_condition import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Prototype Pollution ───────────────────────────────────────────────────────

class ProtoPollutionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.proto_pollution import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.proto_pollution import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "POST"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class ProtoPollutionDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.proto_pollution import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.proto_pollution import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Open Redirect ─────────────────────────────────────────────────────────────

class OpenRedirectListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.open_redirect import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.open_redirect import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            headers=d.get("headers") or {},
            extra_params=d.get("extra_params") or None,
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class OpenRedirectDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.open_redirect import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.open_redirect import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── WebSocket Tester ──────────────────────────────────────────────────────────

class WebSocketListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.websocket_tester import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.websocket_tester import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            ws_url=d.get("ws_url", ""),
            headers=d.get("headers") or {},
            messages=d.get("messages") or None,
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class WebSocketDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.websocket_tester import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.websocket_tester import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── JS Secret Scanner ─────────────────────────────────────────────────────────

class JSSecretListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.js_secret_scanner import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.js_secret_scanner import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            base_url=d.get("base_url", ""),
            headers=d.get("headers") or {},
            max_scripts=int(d.get("max_scripts", 50)),
            deep_crawl=bool(d.get("deep_crawl", True)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class JSSecretDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.js_secret_scanner import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.js_secret_scanner import stop_session, delete_session, get_session
        s = get_session(session_id)
        if not s:
            return Response(status=404)
        if s.get("running"):
            stop_session(session_id)
        else:
            delete_session(session_id)
        return Response(status=204)


# ── Subdomain Takeover ────────────────────────────────────────────────────────

class SubdomainTakeoverListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.subdomain_takeover import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.subdomain_takeover import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            domain=d.get("domain", ""),
            wordlist=d.get("wordlist") or None,
            check_cname_only=bool(d.get("check_cname_only", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class SubdomainTakeoverDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.subdomain_takeover import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.subdomain_takeover import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── SSL/TLS Analyzer ──────────────────────────────────────────────────────────

class SSLAnalyzerListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.ssl_analyzer import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.ssl_analyzer import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            host=d.get("host", ""),
            port=int(d.get("port", 443)),
            check_http_headers=bool(d.get("check_http_headers", True)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class SSLAnalyzerDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.ssl_analyzer import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.ssl_analyzer import stop_session, delete_session, get_session
        s = get_session(session_id)
        if not s:
            return Response(status=404)
        if s.get("running"):
            stop_session(session_id)
        else:
            delete_session(session_id)
        return Response(status=204)


# ── Git/File Exposure ─────────────────────────────────────────────────────────

class GitExposureListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.git_exposure import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.git_exposure import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            base_url=d.get("base_url", ""),
            headers=d.get("headers") or {},
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class GitExposureDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.git_exposure import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.git_exposure import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Buffer Overflow ───────────────────────────────────────────────────────────

class BufferOverflowListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.buffer_overflow import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.buffer_overflow import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            target_param=d.get("target_param") or None,
            max_length=int(d.get("max_length", 65536)),
            technique=d.get("technique", "all"),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class BufferOverflowDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.buffer_overflow import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.buffer_overflow import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Stack Overflow ───────────────────────────────────────────────────────────

class StackOverflowListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.stack_overflow import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.stack_overflow import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class StackOverflowDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.stack_overflow import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.stack_overflow import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Heap Overflow ────────────────────────────────────────────────────────────

class HeapOverflowListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.heap_overflow import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.heap_overflow import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class HeapOverflowDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.heap_overflow import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.heap_overflow import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── HTTP Response Splitting ───────────────────────────────────────────────────

class HTTPResponseSplittingListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.http_response_splitting import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.http_response_splitting import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class HTTPResponseSplittingDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.http_response_splitting import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.http_response_splitting import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Memory Corruption ─────────────────────────────────────────────────────────

class MemoryCorruptionListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.memory_corruption import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.memory_corruption import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class MemoryCorruptionDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.memory_corruption import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.memory_corruption import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── DOM XSS Scanner ───────────────────────────────────────────────────────────

class DOMXSSListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.dom_xss_scanner import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.dom_xss_scanner import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            target=d.get("target", ""),
            headers=d.get("headers") or {},
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class DOMXSSDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.dom_xss_scanner import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.dom_xss_scanner import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── CORS Scanner ──────────────────────────────────────────────────────────────

class CORSScanListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.cors_scanner import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.cors_scanner import create_session, start_session, get_session
        d   = request.data
        sid = create_session(
            target=d.get("target", ""),
            headers=d.get("headers") or {},
            waf_bypass=bool(d.get("waf_bypass", False)),
        )
        start_session(sid)
        return Response(get_session(sid), status=201)


class CORSScanDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.cors_scanner import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.cors_scanner import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── HTTP Smuggling ────────────────────────────────────────────────────────────

class SmugglingListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.smuggling_scanner import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.smuggling_scanner import create_session, start_session, get_session
        d   = request.data
        sid = create_session(target=d.get("target", ""))
        start_session(sid)
        return Response(get_session(sid), status=201)


class SmugglingDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.smuggling_scanner import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.smuggling_scanner import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── WAF Identifier ────────────────────────────────────────────────────────────

class WAFIdentifierListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.waf_identifier import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.waf_identifier import create_session, start_session, get_session
        d   = request.data
        url = (d.get("url") or "").strip()
        if not url:
            return Response({"detail": "url required."}, status=400)
        sid = create_session(url=url, headers=d.get("headers") or {})
        start_session(sid)
        return Response(get_session(sid), status=201)


class WAFIdentifierDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.waf_identifier import get_session
        s = get_session(session_id)
        return Response(s) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.waf_identifier import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Mobile App Pentesting ─────────────────────────────────────────────────────

class MobilePentestListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.mobile_pentest import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.mobile_pentest import create_session, start_session, get_session
        uploaded = request.FILES.get("file")
        if not uploaded:
            return Response({"detail": "file required (multipart/form-data)."}, status=400)
        if uploaded.size > 200 * 1024 * 1024:
            return Response({"detail": "File too large (max 200 MB)."}, status=400)
        sid = create_session(filename=uploaded.name, file_data=uploaded.read())
        start_session(sid)
        return Response(get_session(sid), status=201)


class MobilePentestDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.mobile_pentest import get_session
        s = get_session(session_id)
        return Response(_apply_accuracy(s)) if s else Response(status=404)

    def post(self, request, session_id):
        action = (request.data.get("action") or "").strip()
        if action == "stop":
            from core.modules.mobile_pentest import stop_session
            stop_session(session_id)
            return Response({"detail": "stop requested"})
        return Response({"detail": f"unknown action: {action}"}, status=400)

    def delete(self, request, session_id):
        from core.modules.mobile_pentest import get_session, stop_session, delete_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        if s.get("running"):
            stop_session(session_id)
            return Response({"detail": "Stop requested - session will be removed when analysis finishes."})
        delete_session(session_id)
        return Response(status=204)


class CodeReviewListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.code_review import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.code_review import create_session, start_session, get_session
        uploaded = request.FILES.get("file")
        if not uploaded:
            return Response({"detail": "file required (multipart/form-data)."}, status=400)
        if uploaded.size > 100 * 1024 * 1024:
            return Response({"detail": "File too large (max 100 MB)."}, status=400)
        sid = create_session(filename=uploaded.name, file_data=uploaded.read())
        start_session(sid)
        return Response(get_session(sid), status=201)


class CodeReviewDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        from core.modules.code_review import get_session
        s = get_session(session_id)
        return Response(s) if s else Response(status=404)

    def delete(self, request, session_id):
        from core.modules.code_review import stop_session
        stop_session(session_id)
        return Response(status=204)


# ── Per-scanner Report Generation ─────────────────────────────────────────────

class ActiveScanReportView(APIView):
    """
    POST /api/proxy/active-scan/<session_id>/report/
    Body: {"format": "pdf"|"html"|"json"}
    Returns: {"filename": "...", "url": "/api/proxy/scanner-report/<filename>"}
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id: str):
        from core.modules.active_scanner import get_session
        from apps.reports.generators import ActiveScanReportGenerator

        s = get_session(session_id)
        if not s:
            return Response({"detail": "Session not found."}, status=404)
        if s.get("running"):
            return Response({"detail": "Scan still running - wait for completion."}, status=400)

        fmt = (request.data.get("format") or "pdf").lower()
        if fmt not in ("pdf", "html", "json"):
            return Response({"detail": "format must be pdf, html, or json."}, status=400)

        gen   = ActiveScanReportGenerator(s)
        safe  = (s.get("url","") or "scan").replace("https://","").replace("http://","") \
                    .replace("/","_").replace(":","_")[:40]
        fname = f"active_scan_{safe}_{session_id[:8]}.{fmt}"

        if fmt == "pdf":
            filepath = gen.generate_pdf(fname)
        elif fmt == "html":
            filepath = gen.generate_html(fname)
        else:
            filepath = gen.generate_json(fname)

        return Response({"filename": fname, "url": f"/api/proxy/scanner-report/{fname}"})


# ── Verifier Views ────────────────────────────────────────────────────────────

class ActiveScanVerifyView(APIView):
    """
    POST /api/proxy/active-scan/<session_id>/verify/  → start verification, returns {vsid}
    GET  /api/proxy/active-scan/<session_id>/verify/  → list verifications for this scan
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id: str):
        from core.modules.active_scanner import get_session as get_scan
        from core.modules.verifier import create_verification_session, start_verification

        scan = get_scan(session_id)
        if not scan:
            return Response({"detail": "Scan session not found."}, status=404)
        if scan.get("running") and not scan.get("done"):
            return Response({"detail": "Scan still running — wait for completion."}, status=400)
        findings = scan.get("findings", [])
        if not findings:
            return Response({"detail": "No findings to verify."}, status=400)

        vsid = create_verification_session(
            scan_sid=session_id,
            findings=findings,
            target_url=scan.get("url", ""),
            auth_header=scan.get("auth_header", ""),
            extra_headers=scan.get("extra_headers") or {},
        )
        start_verification(vsid)
        return Response({"vsid": vsid}, status=201)

    def get(self, request, session_id: str):
        from core.modules.verifier import list_verification_sessions
        all_sessions = list_verification_sessions()
        return Response({
            "verifications": [s for s in all_sessions if s.get("scan_sid") == session_id]
        })


class VerifySessionDetailView(APIView):
    """
    GET    /api/proxy/active-scan/verify/<vsid>/  → full verification state + results
    DELETE /api/proxy/active-scan/verify/<vsid>/  → stop and remove
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, vsid: str):
        from core.modules.verifier import get_verification_session
        s = get_verification_session(vsid)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def delete(self, request, vsid: str):
        from core.modules.verifier import stop_verification, delete_verification_session
        stop_verification(vsid)
        if delete_verification_session(vsid):
            return Response(status=204)
        return Response({"detail": "Not found."}, status=404)


class VerifyReportView(APIView):
    """
    POST /api/proxy/active-scan/verify/<vsid>/report/
    Body: {"format": "pdf"|"html"|"json"}
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, vsid: str):
        from core.modules.verifier import get_verification_session
        from apps.reports.generators import VerifierReportGenerator

        s = get_verification_session(vsid)
        if not s:
            return Response({"detail": "Session not found."}, status=404)
        if s.get("running") and not s.get("done"):
            return Response({"detail": "Verification still running — wait for completion."}, status=400)

        fmt = (request.data.get("format") or "pdf").lower()
        if fmt not in ("pdf", "html", "json"):
            return Response({"detail": "format must be pdf, html, or json."}, status=400)

        gen   = VerifierReportGenerator(s)
        safe  = (s.get("target_url", "") or "verify").replace("https://", "").replace("http://", "") \
                    .replace("/", "_").replace(":", "_")[:40]
        fname = f"verifier_{safe}_{vsid[:8]}.{fmt}"

        if fmt == "pdf":
            gen.generate_pdf(fname)
        elif fmt == "html":
            gen.generate_html(fname)
        else:
            gen.generate_json(fname)

        return Response({"filename": fname, "url": f"/api/proxy/scanner-report/{fname}"})


class MobilePentestReportView(APIView):
    """
    POST /api/proxy/mobile-pentest/<session_id>/report/
    Body: {"format": "pdf"|"html"|"json"}
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id: str):
        from core.modules.mobile_pentest import get_session
        from apps.reports.generators import MobilePentestReportGenerator

        s = get_session(session_id)
        if not s:
            return Response({"detail": "Session not found."}, status=404)
        if s.get("running"):
            return Response({"detail": "Analysis still running - wait for completion."}, status=400)

        fmt = (request.data.get("format") or "pdf").lower()
        if fmt not in ("pdf", "html", "json"):
            return Response({"detail": "format must be pdf, html, or json."}, status=400)

        gen   = MobilePentestReportGenerator(s)
        import os as _os
        raw   = (s.get("filename","") or "app")
        safe  = _os.path.splitext(raw)[0].replace(" ","_")[:40]
        fname = f"mobile_pentest_{safe}_{session_id[:8]}.{fmt}"

        if fmt == "pdf":
            filepath = gen.generate_pdf(fname)
        elif fmt == "html":
            filepath = gen.generate_html(fname)
        else:
            filepath = gen.generate_json(fname)

        return Response({"filename": fname, "url": f"/api/proxy/scanner-report/{fname}"})


class ScannerReportDownloadView(APIView):
    """GET /api/proxy/scanner-report/<filename> - serve a generated scanner report file."""
    permission_classes = [IsAuthenticated]

    def get(self, request, filename: str):
        import os
        from pathlib import Path
        from django.http import FileResponse, Http404
        from django.conf import settings as _dj_settings

        # Sanitise: no path traversal
        safe_name = os.path.basename(filename)
        report_dir = Path(getattr(_dj_settings, "REPORTS_DIR", "/tmp"))
        filepath   = report_dir / safe_name

        if not filepath.exists():
            raise Http404("Report file not found.")

        content_type_map = {
            ".pdf":  "application/pdf",
            ".html": "text/html",
            ".json": "application/json",
        }
        ct = content_type_map.get(filepath.suffix.lower(), "application/octet-stream")
        return FileResponse(
            open(filepath, "rb"),
            content_type=ct,
            as_attachment=(ct not in ("text/html", "application/json")),
            filename=safe_name,
        )


# ─────────────────────────────────────────────────────────────────────────────
#  AI / LLM Scanner
# ─────────────────────────────────────────────────────────────────────────────

class AILLMScannerListView(APIView):
    """GET list sessions · POST create+start"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from core.modules.ai_llm_scanner import list_sessions
        return Response(list_sessions())

    def post(self, request):
        from core.modules.ai_llm_scanner import create_session, start_session
        target = (request.data.get("target") or "").strip()
        if not target:
            return Response({"detail": "target is required."}, status=400)
        options = request.data.get("options") or {}
        sid = create_session(target, options)
        start_session(sid)
        from core.modules.ai_llm_scanner import get_session
        return Response(get_session(sid), status=201)


class AILLMScannerDetailView(APIView):
    """GET status · POST actions (pause/resume/stop) · DELETE"""
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id: str):
        from core.modules.ai_llm_scanner import get_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        return Response(s)

    def post(self, request, session_id: str):
        from core.modules.ai_llm_scanner import (
            get_session, pause_session, resume_session, stop_session
        )
        action = (request.data.get("action") or "").lower()
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        if action == "pause":
            pause_session(session_id)
        elif action == "resume":
            resume_session(session_id)
        elif action == "stop":
            stop_session(session_id)
        else:
            return Response({"detail": "action must be pause|resume|stop."}, status=400)
        return Response(get_session(session_id))

    def delete(self, request, session_id: str):
        from core.modules.ai_llm_scanner import get_session, stop_session, delete_session
        s = get_session(session_id)
        if not s:
            return Response({"detail": "Not found."}, status=404)
        if s.get("running") and not s.get("done"):
            stop_session(session_id)
            return Response({"detail": "Scan stopped."})
        if delete_session(session_id):
            return Response(status=204)
        return Response({"detail": "Cannot delete - session still running."}, status=400)


class AILLMReportView(APIView):
    """POST /api/proxy/ai-llm/<session_id>/report/ - generate PDF/HTML/JSON"""
    permission_classes = [IsAuthenticated]

    def post(self, request, session_id: str):
        from core.modules.ai_llm_scanner import get_session
        from apps.reports.generators import AILLMReportGenerator

        s = get_session(session_id)
        if not s:
            return Response({"detail": "Session not found."}, status=404)
        if s.get("running") and not s.get("done"):
            return Response({"detail": "Scan still running - wait for completion."}, status=400)

        fmt = (request.data.get("format") or "pdf").lower()
        if fmt not in ("pdf", "html", "json"):
            return Response({"detail": "format must be pdf, html, or json."}, status=400)

        gen   = AILLMReportGenerator(s)
        safe  = (s.get("target", "").replace("https://", "").replace("http://", "")
                 .replace("/", "_").replace(":", "_"))[:40]
        fname = f"ai_llm_{safe}_{session_id[:8]}.{fmt}"

        if fmt == "pdf":
            gen.generate_pdf(fname)
        elif fmt == "html":
            gen.generate_html(fname)
        else:
            gen.generate_json(fname)

        return Response({"filename": fname, "url": f"/api/proxy/scanner-report/{fname}"})
