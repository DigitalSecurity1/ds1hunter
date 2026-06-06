"""
Scanner accuracy layer: false positive reduction, evidence scoring,
and smart deduplication of findings.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

# ── Configurables ──────────────────────────────────────────────────────────────

_SEV_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# Default thresholds
FP_THRESHOLD_CONFIRMED = 0.50  # raised from 0.25 - matches Hunt engine threshold
FP_THRESHOLD_NORMAL    = 0.50  # raised from 0.45 - consistent across all modules
SCORE_CLAMP_MIN = 0.0
SCORE_CLAMP_MAX = 1.0
DEDUPE_SCORE_MERGE_DELTA = 0.05  # Merge evidence if scores within this delta

_WEAK_FP_TITLES = {
    "header injection xss",
    "info disclosure",
    "sensitive file",
    "content type",
    "x-frame-options",
}

# ── Patterns ───────────────────────────────────────────────────────────────────

# Generic high-confidence patterns (expanded)
_HIGH_CONF_PATTERNS = [
    r"time\.based|time-based|time based",
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"pg_sleep",
    r"waitfor\s+delay",
    r"<script[^>]*>",
    r"alert\s*\(",
    r"onerror\s*=",
    r"onload\s*=",
    r"document\.cookie",
    r"document\.location",
    r"request forgery",
    r"\b(root|admin|password|passwd)\b",
    r"stack\.?trace",
    r"syntax\.?error",
    r"sql.*exception",
    r"org\.postgresql",
    r"com\.mysql",
    r"sqlite3\.operational",
    r"ORA-\d{5}",
    r"Microsoft.*ODBC",
    r"7777777",          # SSTI: {{7*'7'}} Jinja2
    r"1787569",          # SSTI: {{1337*1337}}
    r"unauthorized|forbidden",
    r"403|401",
    r"access\.?denied",
    # Extended
    r"uid[=:][\s\w\(\d]",
    r"gid[=:][\s\w\(\d]",
    r"bin/(sh|bash|dash)",
    r"TemplateSyntaxError",
    r"jinja2\.exceptions?",
    r"Twig_Error",
    r"Unsafe\s+JavaScript",
    r"mysql_fetch",
    r"PGSQL.*ERROR",
    r"sh:\s+\w+:\s*command not found",
    r"bash:\s+line \d+:",
    r"/etc/passwd",
    r"\\win\.ini",
    # XXE markers
    r"failed to load external entity",
    r"external.*entity.*declared",
    r"DOCTYPE.*not.*allowed",
    # Deserialization markers
    r"java\.io\.InvalidClassException",
    r"readObject.*exception",
    r"ObjectInputStream",
    # NoSQL markers
    r"MongoError",
    r"\$where.*is.*not.*a.*function",
    # LDAP markers
    r"javax\.naming\.directory",
    r"com\.sun\.jndi\.ldap",
    # JWT markers
    r'"alg"\s*:\s*"none"',
    # Prototype pollution
    r"__proto__.*modified",
    # Cloud metadata (SSRF/XXE)
    r"ami-id",
    r"iam/security-credentials",
    r"computeMetadata",
]
_HIGH_CONF_RE = re.compile("|".join(_HIGH_CONF_PATTERNS), re.I)

# Generic low-confidence (checked FIRST to avoid cancel with high-conf)
_LOW_CONF_PATTERNS = [
    r"^not found$",
    r"page not found",
    r"^404$",
    r"^403$",
    r"^500$",
    r"internal server error",
]
_LOW_CONF_RE = re.compile("|".join(_LOW_CONF_PATTERNS), re.I | re.M)

# Vuln-type specific (expanded)
_SQLI_PATTERNS = [
    r"sql\s+error",
    r"quoted\s+string",
    r"column.*count.*mismatch",
    r"union.*select",
    r"execute\s+error",
    r"\(\d+\)\s*rows?\s*affected",
    r"You have an error in your SQL syntax",
    r"mysql_fetch",
    r"PostgreSQL.*error",
]
_SQLI_RE = re.compile("|".join(_SQLI_PATTERNS), re.I)

_XSS_PATTERNS = [
    r"<svg[^>]*on",
    r"javascript\s*:",
    r"<iframe[^>]*>",
    r"<embed[^>]*>",
    r"<img[^>]*on",
    r"<body[^>]*on",
    r"<marquee[^>]*on",
    r"onmouseover\s*=",
    r"onfocus\s*=",
]
_XSS_RE = re.compile("|".join(_XSS_PATTERNS), re.I)

_IDOR_PATTERNS = [
    r"unauthorized|not authorized",
    r"403|error 403",
    r"permission denied",
    r"user.*not.*owner",
    r"insufficient permissions",
]
_IDOR_RE = re.compile("|".join(_IDOR_PATTERNS), re.I)

# New: Command Injection
_CMDI_PATTERNS = [
    r"sh:?\s+\w+:\s*(command|not found)",
    r"bash:?\s+line \d+:",
    r"Permission denied",
    r"unexpected end of file",
]
_CMDI_RE = re.compile("|".join(_CMDI_PATTERNS), re.I)

# New: SSTI
_SSTI_PATTERNS = [
    r"TemplateSyntaxError",
    r"jinja2\.",
    r"Twig_Error",
    r"undefined variable",
    r"freemarker\.core",
    r"velocity.*exception",
    r"mako.*exception",
    r"nunjucks.*error",
]
_SSTI_RE = re.compile("|".join(_SSTI_PATTERNS), re.I)

# New: XXE
_XXE_PATTERNS = [
    r"xml.*parsing.*error",
    r"sax.*parse.*exception",
    r"dtd.*not.*allowed",
    r"external.*entity",
    r"entity.*declared",
    r"DOCTYPE.*not.*allowed",
    r"failed to load external entity",
    r"root:x:0",
    r"/etc/passwd",
    r"ami-id",
    r"computeMetadata",
]
_XXE_RE = re.compile("|".join(_XXE_PATTERNS), re.I)

# New: Deserialization
_DESER_PATTERNS = [
    r"java\.io\.InvalidClassException",
    r"ClassNotFoundException",
    r"readObject.*exception",
    r"pickle.*error",
    r"unserialize.*error",
    r"phpunit.*serialization",
    r"java\.lang\.ClassCastException",
    r"gadget.*chain",
    r"readResolve",
    r"ObjectInputStream",
    r"deserialization.*failed",
]
_DESER_RE = re.compile("|".join(_DESER_PATTERNS), re.I)

# New: NoSQL Injection
_NOSQLI_PATTERNS = [
    r"\$where.*is.*not.*a.*function",
    r"MongoError",
    r"mongodb.*error",
    r"bson.*error",
    r"QuerySyntaxError.*mongo",
    r"invalid.*operator",
    r"operator.*\$where.*not.*allowed",
    r"mongo.*parse.*error",
]
_NOSQLI_RE = re.compile("|".join(_NOSQLI_PATTERNS), re.I)

# New: LDAP Injection
_LDAPI_PATTERNS = [
    r"ldap_bind",
    r"ldaperror",
    r"invalid.*dn.*syntax",
    r"search.*filter.*error",
    r"ldap.*operational.*error",
    r"javax\.naming\.directory",
    r"com\.sun\.jndi\.ldap",
    r"NamingException",
]
_LDAPI_RE = re.compile("|".join(_LDAPI_PATTERNS), re.I)

# New: Prototype Pollution
_PROTO_PATTERNS = [
    r"__proto__.*modified",
    r"prototype.*polluted",
    r"hasOwnProperty.*override",
    r"isAdmin.*true",
    r"property.*descriptor.*tampered",
    r"prototype.*chain.*modified",
]
_PROTO_RE = re.compile("|".join(_PROTO_PATTERNS), re.I)

# New: Host Header Injection
_HOST_INJ_PATTERNS = [
    r"location:.*injected",
    r"set-cookie:.*injected",
    r"x-forwarded-host.*reflected",
    r"host.*header.*injection",
    r"cache.*poisoned",
]
_HOST_INJ_RE = re.compile("|".join(_HOST_INJ_PATTERNS), re.I)

# New: JWT Attacks
_JWT_PATTERNS = [
    r'"alg"\s*:\s*"none"',
    r"invalid signature",
    r"jwt.*verification.*failed",
    r"token.*expired",
    r"signature.*mismatch",
    r"algorithm.*not.*supported",
]
_JWT_RE = re.compile("|".join(_JWT_PATTERNS), re.I)

# New: GraphQL
_GRAPHQL_PATTERNS = [
    r"__schema",
    r"__typename",
    r"graphql.*syntax.*error",
    r"field.*does not exist.*on type",
    r"introspection.*disabled",
    r'"errors":\s*\[',
]
_GRAPHQL_RE = re.compile("|".join(_GRAPHQL_PATTERNS), re.I)

# ── Vuln type categorization ──────────────────────────────────────────────────

VULN_CATEGORIES = {
    "sqli": ["sql", "sqli"],
    "xss": ["xss", "cross-site"],
    "idor": ["idor", "authorization", "access control", "broken access"],
    "csrf": ["csrf", "cross-site request"],
    "ssrf": ["ssrf", "server-side request"],
    "lfi": ["path traversal", "directory traversal", "local file", "lfi"],
    "rfi": ["remote file", "rfi"],
    "cmdi": ["command", "rce", "remote code", "os command", "command injection"],
    "ssti": ["ssti", "template injection", "template"],
    "open_redirect": ["open redirect", "redirect"],
    "xxe": ["xxe", "xml external", "external entity"],
    "deser": ["deserialization", "deser", "object injection", "unserialize"],
    "nosqli": ["nosql", "nosqli", "mongodb", "mongo injection"],
    "ldapi": ["ldap", "ldap injection"],
    "proto": ["prototype", "proto pollution", "prototype pollution"],
    "host_injection": ["host header", "cache poison", "host injection"],
    "jwt": ["jwt", "json web token", "token forgery"],
    "graphql": ["graphql", "graph injection"],
}

def _get_vuln_category(vuln_type: str) -> str:
    """Return primary category for vuln_type (e.g., 'sqli' for 'SQL Injection')."""
    vt_lower = vuln_type.lower()
    for cat, keywords in VULN_CATEGORIES.items():
        if any(kw in vt_lower for kw in keywords):
            return cat
    return ""

# ── Evidence scoring ──────────────────────────────────────────────────────────

def _score_by_vuln_type(vuln_type: str, text_blob: str, evidence: dict[str, Any]) -> float:
    """Award type-specific confidence bonuses based on vulnerability-type evidence."""
    bonus = 0.0
    cat = _get_vuln_category(vuln_type)
    response_body = text_blob

    if cat == "sqli":
        if _SQLI_RE.search(text_blob):
            bonus += 0.15
        if evidence.get("timing_diff") and float(evidence.get("timing_diff", 0)) > 3.0:
            bonus += 0.10
    elif cat == "xss":
        if _XSS_RE.search(text_blob):
            bonus += 0.20
        if evidence.get("payload_reflected"):
            bonus += 0.10
    elif cat == "idor":
        if _IDOR_RE.search(text_blob):
            bonus += 0.15
        if evidence.get("user_context_mismatch"):
            bonus += 0.10
    elif cat == "csrf":
        if evidence.get("missing_csrf_token") or evidence.get("predictable_token"):
            bonus += 0.20
    elif cat == "ssrf":
        if evidence.get("internal_ip_leaked") or evidence.get("internal_domain_resolved"):
            bonus += 0.20
    elif cat in ("lfi", "rfi"):
        if "root:" in response_body or "bin/bash" in response_body or "NT AUTHORITY" in response_body:
            bonus += 0.20
        if "/etc/passwd" in response_body:
            bonus += 0.25
    elif cat == "cmdi":
        if _CMDI_RE.search(text_blob):
            bonus += 0.20
        if evidence.get("matched_output"):
            bonus += 0.15
    elif cat == "ssti":
        if _SSTI_RE.search(text_blob):
            bonus += 0.20
        if any(str(p) in text_blob for p in ["7777777", "1787569"]):
            bonus += 0.15
    elif cat == "xxe":
        if _XXE_RE.search(text_blob):
            bonus += 0.20
        if "root:x:" in text_blob or "/etc/passwd" in text_blob:
            bonus += 0.20  # Direct file read confirmed
        if "169.254.169.254" in text_blob or "computeMetadata" in text_blob:
            bonus += 0.15  # Cloud metadata exfil via XXE
    elif cat == "deser":
        if _DESER_RE.search(text_blob):
            bonus += 0.20
        if evidence.get("timing_diff") and float(evidence.get("timing_diff", 0)) > 3.0:
            bonus += 0.10  # Blind deser timing confirmation
    elif cat == "nosqli":
        if _NOSQLI_RE.search(text_blob):
            bonus += 0.20
        if evidence.get("auth_bypassed"):
            bonus += 0.20  # Auth bypass confirmed
        if evidence.get("timing_diff") and float(evidence.get("timing_diff", 0)) > 4.0:
            bonus += 0.10  # $where sleep timing
    elif cat == "ldapi":
        if _LDAPI_RE.search(text_blob):
            bonus += 0.20
        if evidence.get("user_enumerated") or evidence.get("auth_bypassed"):
            bonus += 0.15
    elif cat == "proto":
        if _PROTO_RE.search(text_blob):
            bonus += 0.20
        if evidence.get("property_overwritten"):
            bonus += 0.15
    elif cat == "host_injection":
        if _HOST_INJ_RE.search(text_blob):
            bonus += 0.20
        if evidence.get("header_reflected"):
            bonus += 0.15
    elif cat == "jwt":
        if _JWT_RE.search(text_blob):
            bonus += 0.15
        if evidence.get("auth_bypassed"):
            bonus += 0.20
        if evidence.get("alg_none_accepted"):
            bonus += 0.25  # Algorithm confusion confirmed
    elif cat == "graphql":
        if _GRAPHQL_RE.search(text_blob):
            bonus += 0.15
        if "__schema" in text_blob and "types" in text_blob:
            bonus += 0.20  # Introspection succeeded
        if evidence.get("sqli_via_variable"):
            bonus += 0.15

    return min(bonus, 0.25)  # Cap type bonus

def _get_evidence_length(evidence: Any) -> int:
    """Better evidence richness metric for dedup."""
    if isinstance(evidence, dict):
        return sum(len(str(v)) for v in evidence.values())
    return len(str(evidence or ""))

def score_finding(finding: dict[str, Any]) -> float:
    """
    Return a confidence score [0.0 – 1.0] for a finding.
    """
    score = 0.0

    sev = (finding.get("severity") or "info").lower()
    score += _SEV_WEIGHT.get(sev, 0) / 4 * 0.35  # max 0.35

    evidence = finding.get("evidence") or {}
    detail = finding.get("detail") or ""
    vuln_type = finding.get("type") or finding.get("title") or ""

    # Normalize evidence to dict if str
    if isinstance(evidence, str):
        evidence = {"raw": evidence}

    text_blob = detail + " ".join(str(v) for v in evidence.values())

    # Payload indicators
    proof = finding.get("proof") or {}
    payload_value = (
        evidence.get("payload")
        or evidence.get("payload_used")
        or proof.get("payload")
        or proof.get("payload_used")
    )
    if payload_value:
        score += 0.10
    if evidence.get("payload_reflected") or evidence.get("payload_executed"):
        score += 0.15
    if (
        evidence.get("matched_output")
        or evidence.get("matched_error")
        or evidence.get("database_hint")
        or proof.get("matched_output")
        or proof.get("error_snippet")
        or proof.get("delay_seconds")
    ):
        score += 0.10

    # Behavioural findings with a confirmed server response (e.g. rate_limit_bypass)
    if proof.get("bypass_header") and proof.get("response_status") is not None:
        score += 0.20

    # Patterns: low-conf FIRST to avoid cancel-out
    if _LOW_CONF_RE.search(text_blob):
        score -= 0.15
    if _HIGH_CONF_RE.search(text_blob):
        score += 0.15

    # Improved status code scoring
    status_str = str(evidence.get("status", "")).strip()
    try:
        status = int(status_str)
        if status in (401, 403):
            score += 0.15
        elif status not in (200, 0, 404, 500):
            score += 0.10
    except (ValueError, TypeError):
        pass  # Ignore non-numeric

    # Endpoint with parameter
    endpoint = finding.get("endpoint") or ""
    if "?" in endpoint or evidence.get("param"):
        score += 0.05

    # Type-specific bonuses
    type_bonus = _score_by_vuln_type(vuln_type, text_blob, evidence)
    score += type_bonus

    # Base offset
    return max(SCORE_CLAMP_MIN, min(SCORE_CLAMP_MAX, score + 0.10))

# ── False positive filter ─────────────────────────────────────────────────────

def is_likely_false_positive(
    finding: dict[str, Any],
    fp_threshold_normal: float = FP_THRESHOLD_NORMAL,
    fp_threshold_confirmed: float = FP_THRESHOLD_CONFIRMED,
    weak_fp_threshold: float = 0.60,
) -> bool:
    """
    Return True if the finding should be suppressed.
    """
    sev = (finding.get("severity") or "info").lower()
    if sev in ("critical", "high"):
        return False

    s = finding.get("confidence_score", score_finding(finding))
    title = (finding.get("title") or "").lower()
    confirmed = finding.get("confirmed", False)

    threshold = fp_threshold_confirmed if confirmed else fp_threshold_normal
    if s < threshold:
        return True

    if title in _WEAK_FP_TITLES and s < weak_fp_threshold:
        return True

    evidence = finding.get("evidence") or {}
    if isinstance(evidence, dict):
        status = str(evidence.get("status", "")).strip()
        if status in ("404", "500", "400") and s < 0.50:
            return True

    return False

# ── URL normalisation ─────────────────────────────────────────────────────────

def _normalise_url(url: str) -> str:
    """Strip query string and fragment; lowercase scheme+host."""
    try:
        p = urlparse(url)
        return urlunparse((p.scheme.lower(), p.netloc.lower(), p.path, "", "", ""))
    except Exception:
        return url.lower()

# ── Deduplication (enhanced with merge) ───────────────────────────────────────

def _finding_key(finding: dict[str, Any]) -> str:
    """Stable hash key."""
    endpoint = _normalise_url(finding.get("endpoint") or "")
    evidence = finding.get("evidence") or {}
    param = (evidence.get("param") if isinstance(evidence, dict) else "") or ""
    title = (finding.get("title") or "").lower().strip()
    severity = (finding.get("severity") or "info").lower()
    raw = f"{endpoint}|{param}|{title}|{severity}"
    return hashlib.sha256(raw.encode()).hexdigest()

def _merge_evidence(existing: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Merge two evidence dicts: update with new keys, concatenate strings."""
    merged = {**existing}
    for k, v in new.items():
        if k in merged and isinstance(merged[k], str) and isinstance(v, str):
            merged[k] = merged[k] + " | " + v
        else:
            merged[k] = v
    return merged

def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Merge duplicates: prefer confirmed > score > richness.
    If scores close, merge evidence.
    """
    best: dict[str, dict[str, Any]] = {}
    for f in findings:
        key = _finding_key(f)
        if key not in best:
            best[key] = f.copy()
            continue

        existing = best[key]
        existing_confirmed = existing.get("confirmed", False)
        new_confirmed = f.get("confirmed", False)
        existing_score = existing.get("confidence_score", 0.0)
        new_score = f.get("confidence_score", 0.0)

        if new_confirmed and not existing_confirmed:
            best[key] = f.copy()
        elif not new_confirmed and existing_confirmed:
            continue
        elif new_score > existing_score:
            best[key] = f.copy()
        elif new_score > existing_score - DEDUPE_SCORE_MERGE_DELTA:
            # Merge evidence
            existing_evidence = existing.get("evidence") or {}
            new_evidence = f.get("evidence") or {}
            if isinstance(existing_evidence, dict) and isinstance(new_evidence, dict):
                existing["evidence"] = _merge_evidence(existing_evidence, new_evidence)
                # Re-score after merge (simple, as evidence richer)
                existing["confidence_score"] = score_finding(existing)
        elif _get_evidence_length(f.get("evidence")) > _get_evidence_length(existing.get("evidence")):
            best[key] = f.copy()

    return list(best.values())

# ── Sorting ───────────────────────────────────────────────────────────────────

def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort by severity desc, then confidence_score desc, then risk_score."""
    def _rank(f: dict[str, Any]) -> tuple:
        sev = (f.get("severity") or "info").lower()
        sev_idx = _SEV_ORDER.index(sev) if sev in _SEV_ORDER else len(_SEV_ORDER)
        conf = f.get("confidence_score", 0.0)
        sev_w = _SEV_WEIGHT.get(sev, 0)
        risk = conf * sev_w
        return (sev_idx, -conf, -risk)
    return sorted(findings, key=_rank)

# ── Public pipeline ───────────────────────────────────────────────────────────

def process_findings(
    findings: list[dict[str, Any]],
    *,
    dedupe: bool = True,
    fp_filter: bool = True,
    fp_threshold_normal: float = FP_THRESHOLD_NORMAL,
    fp_threshold_confirmed: float = FP_THRESHOLD_CONFIRMED,
    weak_fp_threshold: float = 0.60,
) -> list[dict[str, Any]]:
    """
    Full accuracy pipeline with tunable params.
    Attaches confidence_score and risk_score.
    """
    # Score all
    scored = []
    for f in findings:
        f_copy = f.copy()
        conf_score = score_finding(f_copy)
        sev = (f_copy.get("severity") or "info").lower()
        sev_w = _SEV_WEIGHT.get(sev, 0)
        risk_score = round(conf_score * sev_w / 4, 3)  # Normalize to [0,1]
        f_copy.update({
            "confidence_score": round(conf_score, 3),
            "risk_score": risk_score,
        })
        scored.append(f_copy)

    if fp_filter:
        scored = [
            f for f in scored
            if not is_likely_false_positive(
                f,
                fp_threshold_normal=fp_threshold_normal,
                fp_threshold_confirmed=fp_threshold_confirmed,
                weak_fp_threshold=weak_fp_threshold,
            )
        ]

    if dedupe:
        scored = deduplicate_findings(scored)

    return sort_findings(scored)

# ── Evidence enrichment helpers ────────────────────────────────────────────────

def enrich_evidence(finding: dict[str, Any], extra_evidence: dict[str, Any]) -> dict[str, Any]:
    """Merge additional evidence fields."""
    if not extra_evidence:
        return finding
    evidence = finding.get("evidence") or {}
    if not isinstance(evidence, dict):
        evidence = {}
    evidence.update(extra_evidence)
    finding["evidence"] = evidence
    return finding

def mark_confirmed(finding: dict[str, Any], confirmed: bool = True, narrative: str = "") -> dict[str, Any]:
    """Mark as confirmed."""
    finding["confirmed"] = confirmed
    if narrative:
        evidence = finding.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}
        evidence["exploitation_narrative"] = narrative
        finding["evidence"] = evidence
    return finding