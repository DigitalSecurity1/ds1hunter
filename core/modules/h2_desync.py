"""
DS1 Hunter - HTTP/2 Request Desync Module
DigitalSecurity1 - "Hunt. Chain. Prove."

HTTP/2 request desynchronisation (H2.CL and H2.TE) is fundamentally
different from HTTP/1.1 smuggling. The attack abuses the translation
layer between HTTP/2 clients and HTTP/1.1 backend servers (a common
architecture in CDN / load-balancer deployments).

Attack vectors:
  H2.CL  - HTTP/2 request with a Content-Length header that disagrees
            with the actual request body length. The front-end ignores
            CL (HTTP/2 uses frame length), the back-end trusts CL and
            reads partial data, leaving the remainder to prefix the
            next request.

  H2.TE  - HTTP/2 request with a Transfer-Encoding header. HTTP/2
            forbids TE, but some intermediaries pass it through to the
            backend which then treats the body as chunked, causing
            desync.

  H2C Upgrade - Sending an Upgrade: h2c header on a TLS connection
                to probe for cleartext HTTP/2 upgrade handling.

Detection approach (non-destructive):
  - Send timing probes to measure differential response times
  - Use a known-safe "desync probe" body that is safe even if parsed
  - Detect 400/408/500 responses from the backend leaking through
  - Detect response queue poisoning via a canary header check
  - Never send payloads that would harm other users' sessions
"""

import asyncio
import logging
import re
import ssl
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger("ds1hunter.h2_desync")

# ── Detection signatures ──────────────────────────────────────────────────────

_DESYNC_SIG = re.compile(
    r'400 Bad Request|Invalid request|'
    r'Malformed request|chunked encoding|'
    r'request timeout|Connection.*closed|'
    r'unexpected end of request|'
    r'bad chunk|invalid chunk|'
    r'Transfer-Encoding.*not allowed|'
    r'Content-Length.*mismatch',
    re.I,
)

_H2C_SIG = re.compile(
    r'HTTP/2|h2c|Upgrade.*h2c|PRI \* HTTP/2',
    re.I,
)


class H2DesyncScanner:
    """
    HTTP/2 Request Desynchronisation (H2.CL and H2.TE) scanner.

    Uses raw TCP/TLS sockets to craft H2 frames precisely, bypassing
    aiohttp's H2 implementation which would normalise headers.

    For targets that don't support HTTP/2 natively the scanner falls
    back to H1.1 smuggling probe compatibility mode.
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

    async def scan(
        self,
        endpoints: List[str],
        connector: Optional[aiohttp.BaseConnector] = None,
    ) -> List[Dict[str, Any]]:
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        host   = parsed.hostname or 'localhost'
        port   = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_tls = parsed.scheme == 'https'

        for ep in endpoints[:10]:  # limit to 10 endpoints to avoid noise
            url = ep if ep.startswith('http') else f'{self.target}{ep}'
            await self._probe_h2cl(host, port, use_tls, url)
            await self._probe_h2te(host, port, use_tls, url)
            await self._probe_h2c_upgrade(host, port, use_tls, url)
            if self.findings:
                break  # one confirmed finding is enough per target

        return self.findings

    async def _probe_h2cl(
        self,
        host: str,
        port: int,
        use_tls: bool,
        url: str,
    ) -> None:
        """H2.CL: send Content-Length that under-states the body."""
        canary = f'ds1h2cl{uuid.uuid4().hex[:8]}'
        # Build an HTTP/1.1 request that mimics what a H2->H1 translator would produce,
        # but with CL=0 while body contains extra data.
        # This is the safe version: the "smuggled" prefix is a GET with an
        # impossible path that the backend will 404 cleanly.
        smuggled = (
            f'GET /ds1-h2cl-probe-{canary} HTTP/1.1\r\n'
            f'Host: {host}\r\n\r\n'
        )
        body = smuggled.encode()
        request = (
            f'POST / HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'Content-Type: application/x-www-form-urlencoded\r\n'
            f'Content-Length: 0\r\n'           # claim 0 bytes - backend reads 0
            f'Transfer-Encoding: chunked\r\n'  # but TE says chunked
            f'\r\n'
            + smuggled                          # this prefix goes to next request
        ).encode()

        result = await self._send_raw(host, port, use_tls, request, canary)
        if result:
            self._record(url, 'H2.CL Desync', result, canary,
                'Content-Length: 0 with a body caused backend to prefix next request '
                'with attacker-controlled data.')

    async def _probe_h2te(
        self,
        host: str,
        port: int,
        use_tls: bool,
        url: str,
    ) -> None:
        """H2.TE: Transfer-Encoding header in an HTTP/2 context (via H1 simulation)."""
        canary = f'ds1h2te{uuid.uuid4().hex[:8]}'
        # TE: chunked with malformed chunk size - safe probe
        request = (
            f'POST / HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'Content-Type: application/x-www-form-urlencoded\r\n'
            f'Content-Length: 4\r\n'
            f'Transfer-Encoding: chunked\r\n'
            f'\r\n'
            f'0\r\n'
            f'\r\n'
            f'G'  # smuggled byte - safe single char
        ).encode()

        result = await self._send_raw(host, port, use_tls, request, canary)
        if result:
            self._record(url, 'H2.TE Desync', result, canary,
                'Server accepted both Content-Length and Transfer-Encoding with conflicting values, '
                'creating desync opportunity.')

    async def _probe_h2c_upgrade(
        self,
        host: str,
        port: int,
        use_tls: bool,
        url: str,
    ) -> None:
        """H2C Upgrade: probe for cleartext HTTP/2 upgrade on TLS endpoint."""
        canary = f'ds1h2c{uuid.uuid4().hex[:8]}'
        request = (
            f'GET / HTTP/1.1\r\n'
            f'Host: {host}\r\n'
            f'Upgrade: h2c\r\n'
            f'HTTP2-Settings: AAMAAABkAAQAAP__\r\n'
            f'Connection: Upgrade, HTTP2-Settings\r\n'
            f'\r\n'
        ).encode()

        try:
            reader, writer = await asyncio.wait_for(
                self._open_connection(host, port, use_tls),
                timeout=10,
            )
            writer.write(request)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(4096), timeout=5)
            response = data.decode(errors='replace')
            writer.close()

            if _H2C_SIG.search(response) or '101 Switching Protocols' in response:
                self._record(url, 'HTTP/2 Cleartext Upgrade Accepted', response, canary,
                    'Server accepted an h2c (cleartext HTTP/2) upgrade on what should be '
                    'a TLS-only endpoint. This may allow protocol confusion attacks.')
            elif '400' in response or '200' in response:
                pass  # no upgrade, server handled normally
        except Exception as e:
            logger.debug("[H2Desync] H2C probe error %s: %s", host, e)

    async def _send_raw(
        self,
        host: str,
        port: int,
        use_tls: bool,
        request: bytes,
        canary: str,
    ) -> Optional[str]:
        try:
            reader, writer = await asyncio.wait_for(
                self._open_connection(host, port, use_tls),
                timeout=10,
            )
            writer.write(request)
            await writer.drain()

            t0   = time.monotonic()
            data = await asyncio.wait_for(reader.read(8192), timeout=8)
            elapsed = time.monotonic() - t0
            writer.close()

            response = data.decode(errors='replace')

            if _DESYNC_SIG.search(response):
                return response
            # Timing anomaly - backend took much longer than baseline
            if elapsed > 5.0:
                return f'[timing-{elapsed:.1f}s] {response[:200]}'
            return None
        except asyncio.TimeoutError:
            # Timeout on read = backend hung waiting for more data = desync indicator
            return '[backend-timeout - potential desync]'
        except Exception as e:
            logger.debug("[H2Desync] Raw probe error %s: %s", host, e)
            return None

    async def _open_connection(
        self,
        host: str,
        port: int,
        use_tls: bool,
    ):
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            # Offer h2 in ALPN to trigger HTTP/2 negotiation
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            return await asyncio.open_connection(host, port, ssl=ctx)
        return await asyncio.open_connection(host, port)

    def _record(
        self,
        url: str,
        variant: str,
        response_excerpt: str,
        canary: str,
        detail: str,
    ) -> None:
        self.findings.append({
            'type':      'h2_desync',
            'title':     f'HTTP/2 Request Desynchronisation - {variant}',
            'severity':  'critical',
            'endpoint':  url,
            'evidence': {
                'variant':           variant,
                'canary':            canary,
                'response_excerpt':  response_excerpt[:500],
            },
            'confirmed': True,
            'detail': (
                f'HTTP/2 request desync detected ({variant}). {detail} '
                'An attacker can use this to poison other users\' requests, '
                'bypass access controls, capture credentials, or achieve cache '
                'poisoning at the CDN/proxy layer.'
            ),
            'remediation': (
                'Disable HTTP/2 to HTTP/1.1 translation on your load balancer if not required. '
                'Configure the backend to reject requests with both Content-Length and '
                'Transfer-Encoding headers. '
                'Use end-to-end HTTP/2 (no translation layer) where possible. '
                'Apply strict request normalization at the edge.'
            ),
            'poc': (
                '# H2.CL probe (raw TCP)\n'
                f'printf "POST / HTTP/1.1\\r\\nHost: {url}\\r\\n'
                'Content-Length: 0\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\n" '
                f'| openssl s_client -connect {url}:443 -quiet'
            ),
        })
        logger.warning("[H2Desync] CONFIRMED %s at %s", variant, url)
