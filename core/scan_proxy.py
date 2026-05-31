"""
DS1 Hunter - Scan Proxy Helper
DigitalSecurity1 - "Hunt. Chain. Prove."

Reads the global ScanProxyConfig from the DB and returns ready-to-use
aiohttp connectors and Playwright proxy dicts for all scanning modules.

Results are cached for 30 s so DB isn't hit on every request batch.

NEW: Added ResponseCache for cross-phase HTTP response deduplication.
"""

import asyncio
import concurrent.futures
import ipaddress
import logging
import os
import random
import socket
import time
from typing import Any, Dict, Optional, Tuple

import aiohttp

logger = logging.getLogger("ds1hunter.scan_proxy")

_cache_enabled: bool = False
_cache_url: Optional[str] = None
_cache_ts: float = 0.0
_CACHE_TTL: float = 30.0


# ── ResponseCache: cross-phase deduplication ─────────────────────────────────

class ResponseCache:
    """
    Async-safe LRU cache for HTTP GET responses.
    Prevents Phase 2-5 from re-fetching URLs already crawled in Phase 1.
    """

    def __init__(self, ttl: float = 60.0, maxsize: int = 500):
        self.ttl = ttl
        self.maxsize = maxsize
        self._store: Dict[str, Tuple[float, int, Dict[str, str], bytes]] = {}
        self._lock = asyncio.Lock()

    def _key(self, method: str, url: str, headers_tuple: Tuple[Tuple[str, str], ...]) -> str:
        # Normalize for cache key
        return f"{method.upper()}|{url}|{headers_tuple}"

    async def get(
        self, method: str, url: str, headers: Optional[Dict[str, str]] = None
    ) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        """Return cached (status, headers_dict, body_bytes) or None."""
        if method.upper() != "GET":
            return None
        key = self._key(method, url, tuple(sorted((headers or {}).items())))
        async with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            ts, status, resp_headers, body = entry
            if time.monotonic() - ts > self.ttl:
                del self._store[key]
                return None
            logger.debug("[ResponseCache] HIT %s", url)
            return status, resp_headers, body

    async def set(
        self,
        method: str,
        url: str,
        status: int,
        resp_headers: Dict[str, str],
        body: bytes,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Cache a GET response."""
        if method.upper() != "GET":
            return
        async with self._lock:
            if len(self._store) >= self.maxsize:
                # Evict oldest
                oldest = min(self._store, key=lambda k: self._store[k][0])
                del self._store[oldest]
            key = self._key(method, url, tuple(sorted((headers or {}).items())))
            self._store[key] = (time.monotonic(), status, resp_headers, body)
            logger.debug("[ResponseCache] SET %s", url)

    async def invalidate(self, url_prefix: str = "") -> None:
        """Remove entries matching a URL prefix (e.g. after auth state changes)."""
        async with self._lock:
            if not url_prefix:
                self._store.clear()
            else:
                to_del = [k for k in self._store if url_prefix in k]
                for k in to_del:
                    del self._store[k]


# Global singleton cache used by all modules
response_cache = ResponseCache(ttl=60.0, maxsize=500)


# ── Token-bucket rate limiter ────────────────────────────────────────────────

class AsyncRateLimiter:
    """
    Smooth token-bucket rate limiter.
    Replaces per-coroutine asyncio.sleep() which causes burst-then-throttle.
    """

    def __init__(self, rate: float = 10.0):
        """
        Args:
            rate: Max requests per second (float).
        """
        self.rate = max(rate, 0.1)
        self._tokens = 1.0
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(1.0, self._tokens + elapsed * self.rate)
            self._last = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


# ── Proxy config helpers ─────────────────────────────────────────────────────

def _ensure_scheme(url: str, proxy_type: str) -> str:
    """Ensure the URL has the correct scheme for the selected proxy type.

    Normalises bare `socks://` (not a valid aiohttp-socks scheme) to
    `socks5://`, and prefixes scheme-less addresses like `127.0.0.1:9050`.
    """
    if not url:
        return url
    # Bare socks:// → socks5h:// (h = remote hostname resolution, required by Tor)
    if url.startswith("socks://"):
        url = "socks5h" + url[len("socks"):]
    # socks5:// → socks5h:// — Tor requires remote DNS to prevent DNS leaks.
    # socks5h tells the SOCKS5 server to resolve hostnames, not the local OS.
    if url.startswith("socks5://"):
        url = "socks5h" + url[len("socks5"):]
    # No scheme at all - prefix with proxy_type
    if "://" not in url:
        ptype_scheme = "socks5h" if proxy_type in ("socks5", "socks") else proxy_type
        url = f"{ptype_scheme}://{url}"
    return url


def _db_fetch():
    """Fetch proxy config from DB - always call this from a plain thread, never directly from async context."""
    from apps.proxy.models import ScanProxyConfig
    return ScanProxyConfig.objects.first()


def _load() -> None:
    global _cache_enabled, _cache_url, _cache_ts
    try:
        # Django ORM raises SynchronousOnlyOperation when called from inside
        # a running asyncio event loop.  Run the query in a thread so it is
        # always safe regardless of the calling context.
        try:
            asyncio.get_running_loop()
            in_async = True
        except RuntimeError:
            in_async = False

        if in_async:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                cfg = pool.submit(_db_fetch).result(timeout=5)
        else:
            cfg = _db_fetch()

        if cfg and cfg.enabled and cfg.proxy_url.strip():
            _cache_enabled = True
            ptype = cfg.proxy_type or "http"
            if cfg.rotate and cfg.proxy_list.strip():
                urls = [
                    _ensure_scheme(u.strip(), ptype)
                    for u in cfg.proxy_list.splitlines()
                    if u.strip()
                ]
                _cache_url = random.choice(urls) if urls else _ensure_scheme(cfg.proxy_url.strip(), ptype)
            else:
                _cache_url = _ensure_scheme(cfg.proxy_url.strip(), ptype)
        else:
            _cache_enabled = False
            _cache_url = None
    except Exception as exc:
        # Django not configured (CLI mode) - fall back to DS1_PROXY_URL env var.
        env_url = os.environ.get("DS1_PROXY_URL", "").strip()
        if env_url:
            logger.debug("[ScanProxy] Using DS1_PROXY_URL from environment: %s", env_url)
            _cache_enabled = True
            _cache_url = env_url
        else:
            logger.debug("[ScanProxy] Config load skipped (no DB, no DS1_PROXY_URL): %s", exc)
            _cache_enabled = False
            _cache_url = None
    _cache_ts = time.monotonic()


def _maybe_refresh() -> None:
    if time.monotonic() - _cache_ts > _CACHE_TTL:
        _load()


def get_proxy_url() -> Optional[str]:
    """Return the active proxy URL, or None if proxy is disabled."""
    _maybe_refresh()
    return _cache_url if _cache_enabled else None


_LOOPBACK_NAMES = frozenset({
    'localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0', '0',
    'localhost.localdomain',
})


def _is_loopback(host: str) -> bool:
    """Return True if host is a loopback/localhost address."""
    bare = host.split(':')[0].strip('[]').lower()
    if bare in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(bare).is_loopback
    except ValueError:
        return False


def _proxy_reachable(proxy_url: str, timeout: float = 4.0) -> bool:
    """Quick TCP check — returns True if the proxy port accepts connections."""
    try:
        import urllib.parse as _up
        p  = _up.urlparse(proxy_url)
        ph = p.hostname or "127.0.0.1"
        pp = p.port or 8080
        s  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((ph, pp)) == 0
        s.close()
        return ok
    except Exception:
        return False


def make_connector(
    limit: int = 10,
    ssl: bool = False,
    target_host: Optional[str] = None,
) -> aiohttp.BaseConnector:
    """
    Return an aiohttp connector wired to the configured proxy (if any).

    If `target_host` is a loopback/localhost address the proxy is bypassed —
    most external proxies cannot forward connections back to the same machine.

    If the proxy is configured and enabled but unreachable, falls back to a
    direct connector and logs a warning (so scans never fail just because a
    proxy isn't running).
    """
    proxy_url = get_proxy_url()

    # Loopback targets always go direct - proxies can't reach them anyway.
    if target_host and _is_loopback(target_host):
        if proxy_url:
            logger.info(
                "[ScanProxy] Bypassing proxy for loopback target '%s' - using direct connection",
                target_host,
            )
        # Force IPv4: many Linux systems resolve 'localhost' to ::1 first,
        # but most local dev servers only bind to 127.0.0.1.
        return aiohttp.TCPConnector(ssl=ssl, limit=limit, family=socket.AF_INET)

    if proxy_url:
        # Tor SOCKS5 needs a longer reachability check — circuit establishment
        # can take several seconds on the first attempt.
        is_tor  = "socks5" in proxy_url
        timeout = 12.0 if is_tor else 4.0
        if _proxy_reachable(proxy_url, timeout=timeout):
            from aiohttp_socks import ProxyConnector
            logger.info("[ScanProxy] Using proxy: %s", proxy_url)
            # rdns=True forces hostname resolution through the proxy (Tor requirement).
            # Without it the OS resolver runs locally, causing DNS leaks and Tor failures.
            return ProxyConnector.from_url(proxy_url, limit=limit, ssl=ssl, rdns=True)
        else:
            logger.warning(
                "[ScanProxy] Proxy %s is configured but unreachable — falling back to direct connection",
                proxy_url,
            )

    return aiohttp.TCPConnector(ssl=ssl, limit=limit)


def playwright_proxy(target_host: Optional[str] = None) -> Optional[dict]:
    """
    Return a Playwright proxy dict if a proxy is configured, else None.
    Pass the result as `proxy=` to `playwright.chromium.launch()`.

    If `target_host` is a loopback address, returns None - external proxies
    cannot forward connections back to the local machine.
    """
    if target_host and _is_loopback(target_host):
        proxy_url = get_proxy_url()
        if proxy_url:
            logger.info(
                "[ScanProxy] Bypassing proxy for loopback Playwright target '%s'",
                target_host,
            )
        return None
    proxy_url = get_proxy_url()
    if not proxy_url:
        return None
    return {"server": proxy_url}


def invalidate_cache() -> None:
    """Force a reload on the next access (call after the config changes)."""
    global _cache_ts
    _cache_ts = 0.0
