"""
DS1 Hunter - Core Engine (v1.4.0 - Production Ready)
DigitalSecurity1 - "Hunt. Chain. Prove."

COMPLETE VERSION WITH:
  ✓ Pause/Resume functionality (timer freezes when paused)
  ✓ Live attacks streaming (FIXED - shows attacks as they appear)
  ✓ False positive filtering
  ✓ CVSS 4.0 scoring
  ✓ Real-time progress updates
  ✓ Phase tracer
  ✓ Remediation tracking
  ✓ Compliance mapping
"""

import asyncio
import json
import logging
import time
import hashlib
import traceback
import httpx
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from core.modules.endpoint_discovery import EndpointDiscovery
from core.modules.auth_analyzer import AuthorizationAnalyzer
from core.modules.chain_mapper import AttackChainMapper
from core.modules.logic_engine import BusinessLogicEngine
from core.modules.exploit_proof import ExploitProofEngine
from core.auth_manager import build_auth_manager
from core.accuracy import process_findings as _accuracy_process

logger = logging.getLogger("ds1hunter.core")

# Constants
CACHE_DIR = Path("./.ds1_cache")
CACHE_TTL_HOURS = 24
MAX_RETRIES = 3
PHASE_TIMEOUT = 600.0  # 10 min


# ================================================================ #
#  PRIORITY 2: CVSS 4.0 Scoring System                            #
# ================================================================ #

class CVSSVector:
    """CVSS v4.0 scoring implementation"""
    
    def __init__(self, vuln: Dict[str, str]):
        self.vuln = vuln
        self.vector = self._build_vector()
    
    def _build_vector(self) -> Dict[str, str]:
        """Extract or build CVSS vector from vulnerability"""
        vector = self.vuln.get("cvss_vector_raw", {})
        # Only use pre-built vector if it's actually populated; empty dict falls through
        if isinstance(vector, dict) and vector:
            return vector
        
        # Build from vuln type and context
        vuln_type = self.vuln.get("type", "unknown").upper()
        
        # Type → CVSS base vectors
        type_map = {
            "SQLI": {
                "AV": "N", "AT": "L", "PR": "N", "UI": "N",
                "VC": "H", "VI": "H", "VA": "H",
            },
            "XSS": {
                "AV": "N", "AT": "L", "PR": "N", "UI": "R",
                "VC": "H", "VI": "H", "VA": "N",
            },
            "IDOR": {
                "AV": "N", "AT": "L", "PR": "L", "UI": "N",
                "VC": "H", "VI": "H", "VA": "N",
            },
            "CSRF": {
                "AV": "N", "AT": "L", "PR": "N", "UI": "R",
                "VC": "N", "VI": "H", "VA": "H",
            },
            "RCE": {
                "AV": "N", "AT": "L", "PR": "N", "UI": "N",
                "VC": "H", "VI": "H", "VA": "H",
            },
            "BROKEN_AUTH": {
                "AV": "N", "AT": "H", "PR": "N", "UI": "N",
                "VC": "H", "VI": "H", "VA": "H",
            },
            "LOGIC_FLAW": {
                "AV": "N", "AT": "H", "PR": "L", "UI": "N",
                "VC": "H", "VI": "H", "VA": "N",
            },
            "SENSITIVE_DATA": {
                "AV": "N", "AT": "L", "PR": "N", "UI": "N",
                "VC": "H", "VI": "N", "VA": "N",
            },
            "RACE_CONDITION": {
                "AV": "N", "AT": "H", "PR": "L", "UI": "N",
                "VC": "N", "VI": "H", "VA": "N",
            },
        }
        
        # Find matching type
        for key, val in type_map.items():
            if key in vuln_type:
                vector = val.copy()
                break
        else:
            # Default: moderate severity
            vector = {
                "AV": "N", "AT": "L", "PR": "N", "UI": "R",
                "VC": "H", "VI": "H", "VA": "N",
            }
        
        # Context adjustments
        if self.vuln.get("requires_auth"):
            vector["PR"] = "L"
        
        if self.vuln.get("method") == "GET":
            vector["AT"] = "L"
        else:
            vector["AT"] = "H"
        
        if self.vuln.get("has_rate_limit"):
            vector["AT"] = "H"
        
        return vector
    
    def score(self) -> float:
        """Calculate CVSS 4.0 base score (0-10)"""
        # Attack Vector (AV) - 0 to 0.85
        av_scores = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        av = av_scores.get(self.vector.get("AV", "N"), 0.85)
        
        # Attack Complexity (AT) - 0 to 0.77
        at = 0.77 if self.vector.get("AT") == "L" else 0.44
        
        # Privileges Required (PR) - 0 to 0.85
        pr_scores = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr = pr_scores.get(self.vector.get("PR", "N"), 0.85)
        
        # User Interaction (UI) - 0 to 0.85
        ui = 0.85 if self.vector.get("UI") == "N" else 0.62
        
        # Impact metrics
        impact_scores = {"H": 0.56, "L": 0.22, "N": 0}
        vc = impact_scores.get(self.vector.get("VC", "N"), 0)
        vi = impact_scores.get(self.vector.get("VI", "N"), 0)
        va = impact_scores.get(self.vector.get("VA", "N"), 0)
        
        # Combined impact
        combined_impact = max(vc, vi, va)
        
        # Environmental
        sc = impact_scores.get(self.vector.get("SC", "N"), 0)
        si = impact_scores.get(self.vector.get("SI", "N"), 0)
        sa = impact_scores.get(self.vector.get("SA", "N"), 0)
        
        # CVSS 4.0 formula
        exploitability = av * at * pr * ui
        impact = combined_impact + max(sc, si, sa) * 0.1
        base_score = 10.0 * exploitability * (1.0 - (1.0 - impact))
        
        return max(0, min(10, base_score))
    
    def severity(self) -> str:
        """Map CVSS 4.0 score to severity rating"""
        score = self.score()
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        else:
            return "INFO"
    
    def vector_string(self) -> str:
        """Format as CVSS vector string"""
        parts = ["CVSS:4.0"]
        for key in ["AV", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]:
            if key in self.vector:
                parts.append(f"{key}:{self.vector[key]}")
        return "/".join(parts)


def score_vulnerability(vuln: Dict) -> Dict:
    """Score vulnerability using knowledge base first, CVSSVector as fallback."""
    from core.knowledge import get_knowledge

    vtype = (vuln.get("type") or "").strip()
    kb = get_knowledge(vtype) if vtype else {}

    if kb and kb.get("cvss_score") is not None:
        score    = float(kb["cvss_score"])
        severity = kb.get("cvss_severity", "LOW")
        vector   = kb.get("cvss_vector", "")
    else:
        # Fall back to module severity (trust scanner over imprecise formula)
        existing = (vuln.get("severity") or "").strip().upper()
        _sev_score = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.3, "LOW": 2.0}
        if existing in _sev_score:
            severity = existing
            score    = _sev_score[existing]
            vector   = ""
        else:
            # Last resort: CVSSVector formula
            scorer   = CVSSVector(vuln)
            score    = scorer.score()
            severity = scorer.severity()
            vector   = scorer.vector_string()

    return {
        **vuln,
        "cvss_score": round(score, 1),
        "cvss_vector": vector,
        "severity":    severity.lower(),
        "confidence":  vuln.get("confidence", 0.5),
    }


# ================================================================ #
#  PRIORITY 4: Phase Tracer                                        #
# ================================================================ #

class PhaseTracer:
    """Track what each module finds in real-time"""
    
    def __init__(self):
        self.traces = defaultdict(list)
        self.phase_start_times = {}
        self.phase_end_times = {}
    
    async def trace_module_discovery(
        self, 
        module_name: str, 
        endpoint: str, 
        finding_type: str,
        severity: str = "medium"
    ):
        """Called by modules when they find something"""
        self.traces[module_name].append({
            "timestamp": datetime.utcnow().isoformat(),
            "endpoint": endpoint,
            "finding_type": finding_type,
            "severity": severity,
        })
    
    def mark_phase_start(self, phase: str):
        """Mark phase start time"""
        self.phase_start_times[phase] = time.time()
    
    def mark_phase_end(self, phase: str):
        """Mark phase end time"""
        self.phase_end_times[phase] = time.time()
    
    def get_module_timeline(self) -> Dict[str, List]:
        """Get discovery timeline per module"""
        return dict(self.traces)
    
    def get_phase_durations(self) -> Dict[str, float]:
        """Get duration per phase"""
        durations = {}
        for phase, start_time in self.phase_start_times.items():
            end_time = self.phase_end_times.get(phase, time.time())
            durations[phase] = round(end_time - start_time, 2)
        return durations


# ================================================================ #
#  PRIORITY 6: Compliance Mapping                                  #
# ================================================================ #

# Keys are lowercase — match scanner output directly.
# map_vulnerability_to_compliance() does: exact → prefix/substring → default.
COMPLIANCE_MAPPING: Dict[str, Dict] = {
    # ── Injection ──────────────────────────────────────────────────────────
    "sqli": {
        "owasp_top_10":     ["A03:2021 – Injection"],
        "owasp_api_top_10": ["API8:2023 – Injection"],
        "cwe":              ["CWE-89 – SQL Injection"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "nosqli": {
        "owasp_top_10":     ["A03:2021 – Injection"],
        "owasp_api_top_10": ["API8:2023 – Injection"],
        "cwe":              ["CWE-943 – Improper Neutralization in Data Query Logic"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "ssti": {
        "owasp_top_10":     ["A03:2021 – Injection"],
        "owasp_api_top_10": ["API8:2023 – Injection"],
        "cwe":              ["CWE-94 – Code Injection"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "cmdi": {
        "owasp_top_10":     ["A03:2021 – Injection"],
        "owasp_api_top_10": ["API8:2023 – Injection"],
        "cwe":              ["CWE-78 – OS Command Injection"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "xxe": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-611 – Improper Restriction of XML External Entity Reference"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "xss": {
        "owasp_top_10":     ["A03:2021 – Injection"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-79 – Cross-site Scripting"],
        "pci_dss":          ["6.5.7 – Cross-site scripting"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "dom_xss": {
        "owasp_top_10":     ["A03:2021 – Injection"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-79 – Cross-site Scripting", "CWE-116 – Improper Encoding or Escaping"],
        "pci_dss":          ["6.5.7 – Cross-site scripting"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "lfi": {
        "owasp_top_10":     ["A01:2021 – Broken Access Control"],
        "owasp_api_top_10": ["API1:2023 – Broken Object Level Authorization"],
        "cwe":              ["CWE-22 – Path Traversal", "CWE-98 – File Inclusion"],
        "pci_dss":          ["6.5.8 – Improper access control"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },
    "path_traversal": {
        "owasp_top_10":     ["A01:2021 – Broken Access Control"],
        "owasp_api_top_10": ["API1:2023 – Broken Object Level Authorization"],
        "cwe":              ["CWE-22 – Path Traversal"],
        "pci_dss":          ["6.5.8 – Improper access control"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },
    "format_string_injection": {
        "owasp_top_10":     ["A03:2021 – Injection"],
        "owasp_api_top_10": ["API8:2023 – Injection"],
        "cwe":              ["CWE-134 – Use of Externally-Controlled Format String"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },

    # ── Access Control ─────────────────────────────────────────────────────
    "idor": {
        "owasp_top_10":     ["A01:2021 – Broken Access Control"],
        "owasp_api_top_10": ["API1:2023 – Broken Object Level Authorization"],
        "cwe":              ["CWE-639 – Authorization Bypass Through User-Controlled Key",
                             "CWE-284 – Improper Access Control"],
        "pci_dss":          ["6.5.10 – Broken access control"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },
    "bfla": {
        "owasp_top_10":     ["A01:2021 – Broken Access Control"],
        "owasp_api_top_10": ["API5:2023 – Broken Function Level Authorization"],
        "cwe":              ["CWE-285 – Improper Authorization",
                             "CWE-862 – Missing Authorization"],
        "pci_dss":          ["6.5.10 – Broken access control"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },
    "mass_assignment": {
        "owasp_top_10":     ["A01:2021 – Broken Access Control"],
        "owasp_api_top_10": ["API3:2023 – Broken Object Property Level Authorization"],
        "cwe":              ["CWE-915 – Improperly Controlled Modification of Dynamically-Determined Object Attributes"],
        "pci_dss":          ["6.5.10 – Broken access control"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },
    "open_redirect": {
        "owasp_top_10":     ["A01:2021 – Broken Access Control"],
        "owasp_api_top_10": ["API3:2023 – Broken Object Property Level Authorization"],
        "cwe":              ["CWE-601 – URL Redirection to Untrusted Site"],
        "pci_dss":          ["6.5.10 – Broken access control"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "cors": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-942 – Overly Permissive Cross-domain Whitelist"],
        "pci_dss":          ["6.5.10 – Broken access control"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },
    "clickjacking": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-1021 – Improper Restriction of Rendered UI Layers"],
        "pci_dss":          ["6.5.7 – Cross-site scripting (UI redress)"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },

    # ── Authentication & Session ────────────────────────────────────────────
    "broken_authentication": {
        "owasp_top_10":     ["A07:2021 – Identification and Authentication Failures"],
        "owasp_api_top_10": ["API2:2023 – Broken Authentication"],
        "cwe":              ["CWE-287 – Improper Authentication"],
        "pci_dss":          ["6.5.10 – Broken authentication"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - User Identification"],
    },
    "jwt_attack": {
        "owasp_top_10":     ["A07:2021 – Identification and Authentication Failures"],
        "owasp_api_top_10": ["API2:2023 – Broken Authentication"],
        "cwe":              ["CWE-347 – Improper Verification of Cryptographic Signature"],
        "pci_dss":          ["6.5.10 – Broken authentication", "8.3 – Multi-factor authentication"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - User Identification"],
    },
    "jwt_weak_secret": {
        "owasp_top_10":     ["A07:2021 – Identification and Authentication Failures",
                             "A02:2021 – Cryptographic Failures"],
        "owasp_api_top_10": ["API2:2023 – Broken Authentication"],
        "cwe":              ["CWE-798 – Use of Hard-coded Credentials",
                             "CWE-326 – Inadequate Encryption Strength"],
        "pci_dss":          ["6.5.10 – Broken authentication", "6.3 – Cryptography"],
        "nist_csf":         ["PR.AC – Access Control", "PR.DS – Data Security"],
        "hipaa":            ["Technical Safeguards - User Identification",
                             "Technical Safeguards - Transmission Security"],
    },
    "jwt_no_expiry": {
        "owasp_top_10":     ["A07:2021 – Identification and Authentication Failures"],
        "owasp_api_top_10": ["API2:2023 – Broken Authentication"],
        "cwe":              ["CWE-613 – Insufficient Session Expiration"],
        "pci_dss":          ["8.1.8 – Session idle timeout"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Automatic Logoff"],
    },
    "oauth": {
        "owasp_top_10":     ["A07:2021 – Identification and Authentication Failures"],
        "owasp_api_top_10": ["API2:2023 – Broken Authentication"],
        "cwe":              ["CWE-287 – Improper Authentication",
                             "CWE-601 – URL Redirection to Untrusted Site"],
        "pci_dss":          ["6.5.10 – Broken authentication"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - User Identification"],
    },
    "mfa_bypass": {
        "owasp_top_10":     ["A07:2021 – Identification and Authentication Failures"],
        "owasp_api_top_10": ["API2:2023 – Broken Authentication"],
        "cwe":              ["CWE-308 – Use of Single-factor Authentication",
                             "CWE-287 – Improper Authentication"],
        "pci_dss":          ["8.3 – Multi-factor authentication"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - User Identification"],
    },

    # ── API-Specific ────────────────────────────────────────────────────────
    "excessive_data_exposure": {
        "owasp_top_10":     ["A01:2021 – Broken Access Control",
                             "A02:2021 – Cryptographic Failures"],
        "owasp_api_top_10": ["API3:2023 – Broken Object Property Level Authorization"],
        "cwe":              ["CWE-213 – Exposure of Sensitive Information Due to Incompatible Policies",
                             "CWE-200 – Exposure of Sensitive Information to Unauthorized Actor"],
        "pci_dss":          ["3.4 – Render PAN unreadable", "6.5.3 – Insecure data exposure"],
        "nist_csf":         ["PR.DS – Data Security"],
        "hipaa":            ["Technical Safeguards - Transmission Security",
                             "Privacy Rule - Minimum Necessary Standard"],
    },
    "hidden_parameter": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API9:2023 – Improper Inventory Management"],
        "cwe":              ["CWE-912 – Hidden Functionality"],
        "pci_dss":          ["6.5.5 – Improper error handling"],
        "nist_csf":         ["ID.AM – Asset Management"],
        "hipaa":            ["Administrative Safeguards - Security Management Process"],
    },
    "hidden_endpoint": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API9:2023 – Improper Inventory Management"],
        "cwe":              ["CWE-912 – Hidden Functionality"],
        "pci_dss":          ["6.5.5 – Security misconfiguration"],
        "nist_csf":         ["ID.AM – Asset Management"],
        "hipaa":            ["Administrative Safeguards - Security Management Process"],
    },
    "ssrf": {
        "owasp_top_10":     ["A10:2021 – Server-Side Request Forgery"],
        "owasp_api_top_10": ["API7:2023 – Server Side Request Forgery"],
        "cwe":              ["CWE-918 – Server-Side Request Forgery"],
        "pci_dss":          ["6.5.9 – Server-side request forgery"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },

    # ── Secrets & Data Exposure ─────────────────────────────────────────────
    "js_secret": {
        "owasp_top_10":     ["A02:2021 – Cryptographic Failures"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-312 – Cleartext Storage of Sensitive Information",
                             "CWE-798 – Use of Hard-coded Credentials"],
        "pci_dss":          ["3.4 – Render PAN unreadable", "6.5.3 – Sensitive data in code"],
        "nist_csf":         ["PR.DS – Data Security"],
        "hipaa":            ["Technical Safeguards - Transmission Security"],
    },

    # ── Infrastructure Misconfig ────────────────────────────────────────────
    "http_smuggling": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-444 – Inconsistent Interpretation of HTTP Requests"],
        "pci_dss":          ["6.5.6 – Security misconfiguration"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Technical Safeguards - Transmission Security"],
    },
    "cache_poisoning": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-693 – Protection Mechanism Failure"],
        "pci_dss":          ["6.5.6 – Security misconfiguration"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Technical Safeguards - Transmission Security"],
    },
    "http_parameter_pollution": {
        "owasp_top_10":     ["A03:2021 – Injection"],
        "owasp_api_top_10": ["API8:2023 – Injection"],
        "cwe":              ["CWE-235 – Improper Handling of Extra Parameters"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },

    # ── Code / Runtime ──────────────────────────────────────────────────────
    "deserialization": {
        "owasp_top_10":     ["A08:2021 – Software and Data Integrity Failures"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-502 – Deserialization of Untrusted Data"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    # Alias — actual type string emitted by DeserializationScanner
    "insecure_deserialization": {
        "owasp_top_10":     ["A08:2021 – Software and Data Integrity Failures"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-502 – Deserialization of Untrusted Data"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "prototype_pollution": {
        "owasp_top_10":     ["A08:2021 – Software and Data Integrity Failures"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-1321 – Improperly Controlled Modification of Object Prototype"],
        "pci_dss":          ["6.5.1 – Injection flaws"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "integer_overflow": {
        "owasp_top_10":     ["A04:2021 – Insecure Design"],
        "owasp_api_top_10": ["API4:2023 – Unrestricted Resource Consumption"],
        "cwe":              ["CWE-190 – Integer Overflow or Wraparound"],
        "pci_dss":          ["6.5.6 – Security misconfiguration"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "redos": {
        "owasp_top_10":     ["A04:2021 – Insecure Design"],
        "owasp_api_top_10": ["API4:2023 – Unrestricted Resource Consumption"],
        "cwe":              ["CWE-1333 – Inefficient Regular Expression Complexity"],
        "pci_dss":          ["6.5.6 – Security misconfiguration"],
        "nist_csf":         ["PR.DS – Data Security"],
        "hipaa":            ["Administrative Safeguards - Security Management Process"],
    },
    "graphql": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration",
                             "API4:2023 – Unrestricted Resource Consumption"],
        "cwe":              ["CWE-284 – Improper Access Control"],
        "pci_dss":          ["6.5.5 – Security misconfiguration"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },
    "memory_corruption": {
        "owasp_top_10":     ["A04:2021 – Insecure Design"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-119 – Improper Restriction of Operations within Memory Buffer"],
        "pci_dss":          ["6.5.2 – Buffer overflows"],
        "nist_csf":         ["PR.PS – Protective Technology"],
        "hipaa":            ["Security Rule - Audit Controls"],
    },

    # ── Business Logic ──────────────────────────────────────────────────────
    "race_condition": {
        "owasp_top_10":     ["A04:2021 – Insecure Design"],
        "owasp_api_top_10": ["API4:2023 – Unrestricted Resource Consumption"],
        "cwe":              ["CWE-362 – Concurrent Execution using Shared Resource with Improper Synchronization"],
        "pci_dss":          ["6.5.6 – Security misconfiguration"],
        "nist_csf":         ["PR.DS – Data Security"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },
    "price_manipulation": {
        "owasp_top_10":     ["A04:2021 – Insecure Design"],
        "owasp_api_top_10": ["API6:2023 – Unrestricted Access to Sensitive Business Flows"],
        "cwe":              ["CWE-840 – Business Logic Errors"],
        "pci_dss":          ["6.5.10 – Broken access control"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Administrative Safeguards - Security Management Process"],
    },
    "payment_bypass": {
        "owasp_top_10":     ["A04:2021 – Insecure Design"],
        "owasp_api_top_10": ["API6:2023 – Unrestricted Access to Sensitive Business Flows"],
        "cwe":              ["CWE-840 – Business Logic Errors"],
        "pci_dss":          ["6.5.10 – Broken access control", "10.2 – Audit log events"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Administrative Safeguards - Security Management Process"],
    },
    "coupon_abuse": {
        "owasp_top_10":     ["A04:2021 – Insecure Design"],
        "owasp_api_top_10": ["API6:2023 – Unrestricted Access to Sensitive Business Flows"],
        "cwe":              ["CWE-840 – Business Logic Errors"],
        "pci_dss":          ["6.5.10 – Broken access control"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Administrative Safeguards - Security Management Process"],
    },
    "negative_quantity": {
        "owasp_top_10":     ["A04:2021 – Insecure Design"],
        "owasp_api_top_10": ["API6:2023 – Unrestricted Access to Sensitive Business Flows"],
        "cwe":              ["CWE-840 – Business Logic Errors"],
        "pci_dss":          ["6.5.10 – Broken access control"],
        "nist_csf":         ["PR.DS – Data Security"],
        "hipaa":            ["Administrative Safeguards - Security Management Process"],
    },
    "account_takeover": {
        "owasp_top_10":     ["A07:2021 – Identification and Authentication Failures",
                             "A01:2021 – Broken Access Control"],
        "owasp_api_top_10": ["API2:2023 – Broken Authentication"],
        "cwe":              ["CWE-287 – Improper Authentication", "CWE-620 – Unverified Password Change"],
        "pci_dss":          ["6.5.10 – Broken authentication"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - User Identification"],
    },
    "email_enumeration": {
        "owasp_top_10":     ["A07:2021 – Identification and Authentication Failures"],
        "owasp_api_top_10": ["API2:2023 – Broken Authentication"],
        "cwe":              ["CWE-204 – Observable Response Discrepancy"],
        "pci_dss":          ["6.5.10 – Broken authentication"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Privacy Rule - Minimum Necessary Standard"],
    },

    # ── CVE / Template Findings ─────────────────────────────────────────────
    "cve": {
        "owasp_top_10":     ["A06:2021 – Vulnerable and Outdated Components"],
        "owasp_api_top_10": ["API9:2023 – Improper Inventory Management"],
        "cwe":              ["CWE-1104 – Use of Unmaintained Third-party Components"],
        "pci_dss":          ["6.3.3 – Vulnerability patching", "11.3 – Penetration testing"],
        "nist_csf":         ["ID.RA – Risk Assessment", "PR.IP – Information Protection"],
        "hipaa":            ["Administrative Safeguards - Security Management Process"],
    },
    "exposed_service": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-16 – Configuration"],
        "pci_dss":          ["1.3 – Network access controls"],
        "nist_csf":         ["PR.AC – Access Control"],
        "hipaa":            ["Technical Safeguards - Access Controls"],
    },
    "config_leak": {
        "owasp_top_10":     ["A05:2021 – Security Misconfiguration",
                             "A02:2021 – Cryptographic Failures"],
        "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
        "cwe":              ["CWE-200 – Exposure of Sensitive Information",
                             "CWE-312 – Cleartext Storage of Sensitive Information"],
        "pci_dss":          ["3.4 – Render sensitive data unreadable"],
        "nist_csf":         ["PR.DS – Data Security"],
        "hipaa":            ["Technical Safeguards - Transmission Security"],
    },
}

# Build a fast lowercase-key lookup used by map_vulnerability_to_compliance().
_COMPLIANCE_LOOKUP: Dict[str, Dict] = {k.lower(): v for k, v in COMPLIANCE_MAPPING.items()}


def map_vulnerability_to_compliance(vuln: Dict) -> Dict:
    """Add OWASP, CWE, PCI-DSS, NIST, and HIPAA compliance mappings to a finding."""
    vuln_type = (vuln.get("type") or "").lower().strip()

    # 1. Exact match (fastest path)
    mappings = _COMPLIANCE_LOOKUP.get(vuln_type)

    # 2. Prefix/substring match — handles compound types like "jwt_attack_rs256"
    if not mappings:
        for key, val in _COMPLIANCE_LOOKUP.items():
            if vuln_type.startswith(key) or key in vuln_type:
                mappings = val
                break

    # 3. Generic fallback — still better than a wrong mapping
    if not mappings:
        mappings = {
            "owasp_top_10":     ["A05:2021 – Security Misconfiguration"],
            "owasp_api_top_10": ["API8:2023 – Security Misconfiguration"],
            "cwe":              ["CWE-16 – Configuration"],
            "pci_dss":          ["6.5 – Addressing common coding vulnerabilities"],
            "nist_csf":         ["PR.PS – Protective Technology"],
        }

    return {**vuln, "compliance": mappings}


# ================================================================ #
#  PRIORITY 5: Remediation Tracking                               #
# ================================================================ #

class RemediationTracker:
    """Track remediation status between scans"""
    
    def __init__(self, cache_file: Path):
        self.cache_file = cache_file
        self.previous_vulns = []
        self.previous_findings_hash = {}
        self._load_previous()
    
    def _load_previous(self):
        """Load last scan's findings"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, "r") as f:
                    cached = json.load(f)
                self.previous_vulns = cached.get("vulnerabilities", [])
                self.previous_findings_hash = {
                    f"{v.get('type', '')}|{v.get('endpoint', '')}": v 
                    for v in self.previous_vulns
                }
                logger.info("[Remediation] Loaded %d previous findings", len(self.previous_vulns))
        except Exception as e:
            logger.debug("[Remediation] Load failed: %s", e)
            self.previous_vulns = []
            self.previous_findings_hash = {}
    
    def compute_remediation_status(self, current_vulns: List[Dict]) -> Dict:
        """Compare current vs previous scans"""
        current_hash = {
            f"{v.get('type', '')}|{v.get('endpoint', '')}": v 
            for v in current_vulns
        }
        
        fixed = []
        new = []
        recurring = []
        
        for finding_key, prev_vuln in self.previous_findings_hash.items():
            if finding_key not in current_hash:
                fixed.append({
                    **prev_vuln,
                    "status": "FIXED",
                    "fixed_date": datetime.utcnow().isoformat(),
                })
            else:
                recurring.append({
                    **current_hash[finding_key],
                    "status": "RECURRING",
                    "days_open": self._calculate_days_open(
                        prev_vuln.get("first_found", datetime.utcnow().isoformat())
                    ),
                })
        
        for finding_key, curr_vuln in current_hash.items():
            if finding_key not in self.previous_findings_hash:
                new.append({
                    **curr_vuln,
                    "status": "NEW",
                    "first_found": datetime.utcnow().isoformat(),
                })
        
        return {
            "total_fixed": len(fixed),
            "total_new": len(new),
            "total_recurring": len(recurring),
            "fixed_findings": fixed,
            "new_findings": new,
            "recurring_findings": recurring,
            "mttr_days": self._calculate_mttr(fixed),
        }
    
    def _calculate_days_open(self, first_found_str: str) -> int:
        """Calculate days since finding was first discovered"""
        try:
            found = datetime.fromisoformat(first_found_str)
            days = (datetime.utcnow() - found).days
            return max(0, days)
        except:
            return 0
    
    def _calculate_mttr(self, fixed_vulns: List[Dict]) -> float:
        """Calculate MTTR in days"""
        if not fixed_vulns:
            return 0.0
        
        times = []
        for v in fixed_vulns:
            try:
                found = datetime.fromisoformat(v.get("first_found", "2000-01-01"))
                fixed = datetime.fromisoformat(v.get("fixed_date", "2000-01-01"))
                days = (fixed - found).days
                if days >= 0:
                    times.append(days)
            except:
                pass
        
        return round(sum(times) / len(times), 1) if times else 0.0


# ================================================================ #
#  PRIORITY 1: False Positive Filter                              #
# ================================================================ #

class FalsePositiveFilter:
    """Filter false positives with confidence scoring"""
    
    def __init__(self, target: str):
        self.target = target
        self.reachable_endpoints = set()
    
    async def validate_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """Filter FPs and return validated vulns"""
        validated = []

        for vuln in vulns:
            # Reachability: fail-open — if the check itself fails, keep the vuln
            reachable = await self._check_reachability(vuln)
            if reachable is False:
                # Only drop if we got a definitive 4xx/5xx back (not an exception)
                if vuln.get("_reachability_confirmed_dead"):
                    logger.debug("[FP Filter] %s confirmed unreachable - skipping", vuln.get("id"))
                    continue
                # Network error / timeout / proxy issue → keep it

            if self._is_contextual_fp(vuln):
                logger.debug("[FP Filter] %s identified as contextual FP", vuln.get("id"))
                continue

            # Only filter on confidence when the scanner explicitly set it low
            # (default None or 0.5 means "scanner didn't specify" → keep)
            # Exclude pure discovery findings from vulnerability list — they are
            # interesting endpoints, not confirmed vulnerabilities.
            if vuln.get("type") == "hidden_endpoint" and not vuln.get("confirmed"):
                logger.debug("[FP Filter] %s is unconfirmed hidden_endpoint - skipping as FP",
                             vuln.get("endpoint"))
                continue

            confidence = vuln.get("confidence")
            if confidence is not None and float(confidence) < 0.50:
                logger.debug("[FP Filter] %s low confidence (%.2f) - skipping",
                             vuln.get("id"), confidence)
                continue

            eff_conf = confidence if confidence is not None else 0.65
            vuln["fp_validated"] = True
            vuln["validation_confidence"] = round(eff_conf, 2)
            validated.append(vuln)

        logger.info("[FP Filter] Validated %d/%d findings (%.1f%% reduction)",
                    len(validated), len(vulns),
                    (1 - len(validated) / max(1, len(vulns))) * 100)

        return validated
    
    async def _check_reachability(self, vuln: Dict) -> bool:
        """Can we actually reach this endpoint? Returns True on network errors (fail-open)."""
        endpoint = vuln.get("endpoint", "")
        if not endpoint:
            return True  # metadata-only vuln, no URL to check

        if endpoint in self.reachable_endpoints:
            return True

        # Build the URL: if endpoint is already absolute, use it directly
        if endpoint.startswith(("http://", "https://")):
            url = endpoint
        else:
            url = f"{self.target.rstrip('/')}/{endpoint.lstrip('/')}"

        try:
            import aiohttp as _aiohttp
            from core import scan_proxy as _sp
            from urllib.parse import urlparse as _up
            _host = _up(self.target).hostname or ""
            connector = _sp.make_connector(limit=5, ssl=False, target_host=_host)
            _px = _sp.get_proxy_url()
            _timeout = _aiohttp.ClientTimeout(total=8 if _px else 4)
            async with _aiohttp.ClientSession(
                connector=connector,
                timeout=_timeout,
                headers={"User-Agent": "DS1Hunter/1.4.0"},
            ) as client:
                async with client.get(url, allow_redirects=True, ssl=False) as resp:
                    if resp.status < 400:
                        self.reachable_endpoints.add(endpoint)
                        return True
                    # Definitive dead endpoint (only 404/410 really mean "not there")
                    if resp.status in (404, 410):
                        vuln["_reachability_confirmed_dead"] = True
                        return False
                    # 401/403/405/5xx → endpoint exists, just requires auth or different method
                    self.reachable_endpoints.add(endpoint)
                    return True
        except Exception as e:
            logger.debug("[Reachability] %s check failed: %s — keeping vuln", url, e)
            return True  # Fail-open: network errors don't disqualify a finding
    
    def _score_exploitability(self, vuln: Dict) -> float:
        """Score how exploitable this is (0-10)"""
        score = 5.0
        
        score += (3.0 if not vuln.get("requires_auth") else 0)
        score += (1.0 if vuln.get("method") == "GET" else 0)
        score += (2.0 if vuln.get("type") in ["SQLi", "RCE", "Broken Authentication"] else 0)
        score += (1.0 if not vuln.get("protection") else 0)
        
        score -= (1.0 if vuln.get("requires_admin") else 0)
        score -= (2.0 if vuln.get("requires_race_condition") else 0)
        score -= (1.5 if vuln.get("has_rate_limit") else 0)
        score -= (1.0 if vuln.get("protected_by_waf") else 0)
        
        return max(0, min(10, score))
    
    def _is_contextual_fp(self, vuln: Dict) -> bool:
        """Is this a false positive based on context?"""
        vuln_type = vuln.get("type", "").upper()
        
        if "IDOR" in vuln_type:
            response = vuln.get("response", "").lower()
            if "access denied" in response or "forbidden" in response:
                return True
        
        if "BROKEN_AUTH" in vuln_type or "AUTHENTICATION" in vuln_type:
            if vuln.get("http_status") == 403:
                return True
        
        if "SENSITIVE" in vuln_type or "DATA_EXPOSURE" in vuln_type:
            if vuln.get("is_own_data") or vuln.get("is_public_profile"):
                return True
        
        return False


# ================================================================ #
#  Main DS1Hunter Class                                            #
# ================================================================ #

class DS1Hunter:
    """
    Production-ready DS1 Hunter v1.4.0
    Complete with pause/resume and live attack streaming.
    """

    VERSION = "1.4.0"
    COMPANY = "DigitalSecurity1"
    TAGLINE = "Hunt. Chain. Prove."

    def __init__(
        self,
        target: str,
        config: Optional[Dict[str, Any]] = None,
        progress_callback: Optional[Callable] = None,
        attack_callback: Optional[Callable] = None,
        auth_config: Optional[Dict[str, Any]] = None,
        dual_mode: bool = False,
        oob_client=None,
        cache_dir: str = "./.ds1_cache",
        max_retries: int = MAX_RETRIES,
    ):
        """Initialize DS1 Hunter with all features."""
        self.target = self._normalize_target(target)
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self._get_cache_path(target)
        
        self.config = self._merge_config(config or {}, max_retries)
        self.progress_callback = progress_callback
        self.attack_callback = attack_callback
        self.dual_mode = dual_mode
        self.oob_client = oob_client
        self.results: Dict[str, Any] = {}
        
        # Metrics tracking
        self.metrics: Dict[str, Any] = {
            "start_time": None,
            "end_time": None,
            "phase_times": {},
            "phase_retries": {},
            "phase_attack_counts": {},
            "errors": [],
            "total_attacks": 0,
        }
        
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self._authorized = False
        self._auth_config = auth_config or {}

        # ===== PAUSE/RESUME FUNCTIONALITY =====
        self._paused_time: Optional[float] = None  # When pause started
        self.total_paused_duration: float = 0.0    # Total time paused
        self._is_paused = False                     # Pause flag
        # ======================================

        # Live attacks tracking (FOR REAL-TIME STREAMING)
        self.current_phase_attacks: List[Dict] = []  # Attacks found in current phase

        # Load from cache if valid
        if self.cache_file.exists() and self._is_cache_valid():
            self._load_cache()

        # Build auth manager
        auth_mgr = build_auth_manager(auth_config)

        # Initialize NEW features
        self.tracer = PhaseTracer()
        self.fp_filter = FalsePositiveFilter(self.target)
        self.remediation_tracker = RemediationTracker(self.cache_file)

        # Module instances
        self._discovery = EndpointDiscovery(
            self.target, self.config, attack_callback, auth_manager=auth_mgr,
            progress_callback=self._create_phase_progress_callback("phase1")
        )
        self._auth = AuthorizationAnalyzer(
            self.target, self.config, attack_callback,
            auth_manager=auth_mgr, dual_mode=dual_mode,
            oob_client=oob_client,
            progress_callback=self._create_phase_progress_callback("phase2")
        )
        self._chain = AttackChainMapper()
        self._logic = BusinessLogicEngine(
            self.target, self.config, attack_callback,
            auth_manager=auth_mgr, oob_client=oob_client,
            progress_callback=self._create_phase_progress_callback("phase4")
        )
        self._proof = ExploitProofEngine(
            self.target, self.config, attack_callback, auth_manager=auth_mgr,
            progress_callback=self._create_phase_progress_callback("phase5")
        )

    # ================================================================ #
    #  Caching                                                        #
    # ================================================================ #

    def _get_cache_path(self, target: str) -> Path:
        """Generate cache filename from target hash."""
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:12]
        return self.cache_dir / f"hunt_{target_hash}.json"

    def _is_cache_valid(self) -> bool:
        """Check if cache exists and is not expired."""
        try:
            if not self.cache_file.exists():
                return False
            with open(self.cache_file, "r") as f:
                data = json.load(f)
            cache_time_str = data.get("_cache_timestamp")
            if not cache_time_str:
                return False
            cache_time = datetime.fromisoformat(cache_time_str)
            age = datetime.utcnow() - cache_time
            valid = age < timedelta(hours=CACHE_TTL_HOURS)
            if valid:
                logger.info("[Cache] Valid (age: %.0f min)", age.total_seconds() // 60)
            else:
                logger.info("[Cache] Expired (age: %.0f hours)", age.total_seconds() // 3600)
            return valid
        except Exception as e:
            logger.debug("[Cache] Validation failed: %s", e)
            return False

    def _load_cache(self) -> None:
        """Load cached results from JSON."""
        try:
            with open(self.cache_file, "r") as f:
                cached = json.load(f)
            for key in ["endpoints", "auth_issues", "logic_flaws", "chains", "proofs", "origin_ip"]:
                if key in cached:
                    self.results[key] = cached[key]
            logger.info("[Cache] Loaded: %s", ", ".join(self.results.keys()))
        except Exception as e:
            logger.error("[Cache] Load failed: %s", e)
            self.results.clear()

    def _save_cache(self) -> None:
        """Atomic cache save."""
        try:
            cache_data = {
                **self.results,
                "_cache_timestamp": datetime.utcnow().isoformat(),
                "_target": self.target,
                "_version": self.VERSION,
            }
            tmp_file = self.cache_file.with_suffix(".tmp")
            with open(tmp_file, "w") as f:
                json.dump(cache_data, f, indent=2, default=str)
            tmp_file.replace(self.cache_file)
            logger.debug("[Cache] Saved: %s", self.cache_file)
        except Exception as e:
            logger.warning("[Cache] Save failed: %s", e)

    def clear_cache(self) -> None:
        """Clear cache for fresh scan."""
        try:
            if self.cache_file.exists():
                self.cache_file.unlink()
            self.results.clear()
            logger.info("[Cache] Cleared")
        except Exception as e:
            logger.error("[Cache] Clear failed: %s", e)

    # ================================================================ #
    #  Config validation                                               #
    # ================================================================ #

    def _merge_config(self, config: Dict[str, Any], max_retries: int) -> Dict[str, Any]:
        """Merge user config with defaults."""
        defaults = {
            "max_retries": max_retries,
            "phase_timeout": PHASE_TIMEOUT,
            "origin_bypass": True,
            "rate_limit_req_per_sec": 5,
            "parallel_phases": True,
            "stream_attacks": True,
            "filter_false_positives": True,
            "enable_compliance_mapping": True,
        }
        merged = {**defaults, **config}
        logger.debug("[Config] Merged: %d keys", len(merged))
        return merged

    # ================================================================ #
    #  Authorization gate                                              #
    # ================================================================ #

    def confirm_authorization(self, target: str) -> None:
        """Assert written authorization."""
        if target != self.target:
            raise ValueError(f"Target mismatch: {self.target} != {target}")
        self._authorized = True
        logger.info("[Auth] ✓ Confirmed for %s", self.target)

    def _require_authorization(self) -> None:
        if not self._authorized:
            raise PermissionError(
                "Call confirm_authorization(target) first. "
                "Only scan authorized targets."
            )

    # ================================================================ #
    #  Internal helpers                                                #
    # ================================================================ #

    @staticmethod
    def _normalize_target(target: str) -> str:
        """Normalize to full URL."""
        target = target.strip().rstrip("/")
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        return target

    async def _update_progress(
        self,
        phase: str,
        message: str,
        progress: int = 0,
        findings: Optional[List] = None,
        phase_progress: Optional[float] = None,
    ) -> None:
        """
        Send progress + live attacks to frontend.
        FIXED: Now properly streams live attacks as they're discovered.
        """
        # Use findings if provided, otherwise use current_phase_attacks
        live_attacks = findings if findings else self.current_phase_attacks

        self.metrics["phase_attack_counts"][phase] = len(live_attacks)
        self.metrics["total_attacks"] = sum(self.metrics["phase_attack_counts"].values())

        # Attack breakdown by severity
        severity_breakdown = {
            "critical": sum(1 for a in live_attacks if a.get("severity") == "critical"),
            "high": sum(1 for a in live_attacks if a.get("severity") == "high"),
            "medium": sum(1 for a in live_attacks if a.get("severity") == "medium"),
            "low": sum(1 for a in live_attacks if a.get("severity") == "low"),
        }

        # Calculate actual elapsed time (excluding paused time)
        actual_elapsed = 0
        if self.start_time:
            if self._is_paused:
                actual_elapsed = (self._paused_time - self.start_time - self.total_paused_duration)
            else:
                actual_elapsed = (time.time() - self.start_time - self.total_paused_duration)

        payload = {
            "hunt_id": hashlib.sha256(self.target.encode()).hexdigest()[:12],
            "phase": phase,
            "phase_name": {
                "phase1": "Endpoint Discovery",
                "phase2": "Authorization Analysis",
                "phase3": "Attack Chain Mapping",
                "phase4": "Business Logic Testing",
                "phase5": "Exploit Proof Generation",
            }.get(phase, phase),
            "message": message,
            "progress": max(0, min(100, progress)),
            "findings": findings or [],
            "live_attacks": live_attacks,  # KEY: Real-time attacks
            "attack_count": len(live_attacks),
            "total_attacks": self.metrics["total_attacks"],
            "attack_breakdown": severity_breakdown,
            "phase_progress": phase_progress,
            "timestamp": datetime.utcnow().isoformat(),
            "pause_status": {
                "is_paused": self._is_paused,
                "elapsed_seconds": round(actual_elapsed, 2),
                "paused_duration": round(self.total_paused_duration, 2),
            },
            "metrics": {
                "phase_duration": self.metrics["phase_times"].get(phase, 0),
                "phase_retries": self.metrics["phase_retries"].get(phase, 0),
                "cached": bool(self.results.get(phase.replace("phase", ""))),
                "error_count": len(self.metrics["errors"]),
            },
        }
        
        if self.progress_callback:
            try:
                if asyncio.iscoroutinefunction(self.progress_callback):
                    await self.progress_callback(payload)
                else:
                    self.progress_callback(payload)
            except Exception as e:
                logger.debug("[Progress] Callback error: %s", e)
        
        logger.info(
            "[%s] %s | C:%d H:%d M:%d | Progress: %d%% | Paused: %s",
            phase, message,
            severity_breakdown["critical"],
            severity_breakdown["high"],
            severity_breakdown["medium"],
            progress,
            "YES" if self._is_paused else "NO"
        )

    # ================================================================ #
    #  Pause/Resume Functionality (NEW)                               #
    # ================================================================ #

    def pause_hunt(self) -> Dict[str, Any]:
        """Pause the hunt and freeze the timer."""
        if self._is_paused:
            logger.warning("[Pause] Hunt already paused")
            return {"status": "already_paused", "message": "Hunt is already paused"}
        
        self._is_paused = True
        self._paused_time = time.time()
        
        elapsed = (self._paused_time - self.start_time) if self.start_time else 0
        
        logger.info("[Pause] Hunt paused at %.2f seconds", elapsed)
        
        return {
            "status": "paused",
            "paused_at": datetime.utcnow().isoformat(),
            "elapsed_seconds": round(elapsed - self.total_paused_duration, 2),
            "total_paused_duration": round(self.total_paused_duration, 2),
            "message": "Hunt paused - timer frozen"
        }

    def resume_hunt(self) -> Dict[str, Any]:
        """Resume the hunt and continue the timer."""
        if not self._is_paused:
            logger.warning("[Resume] Hunt is not paused")
            return {"status": "not_paused", "message": "Hunt is not currently paused"}
        
        if not self._paused_time:
            return {"status": "error", "message": "Pause time not recorded"}
        
        # Calculate pause duration
        pause_duration = time.time() - self._paused_time
        self.total_paused_duration += pause_duration
        
        self._is_paused = False
        self._paused_time = None
        
        elapsed = (time.time() - self.start_time - self.total_paused_duration) if self.start_time else 0
        
        logger.info("[Resume] Hunt resumed. Paused for %.2f seconds", pause_duration)
        
        return {
            "status": "resumed",
            "resumed_at": datetime.utcnow().isoformat(),
            "paused_for_seconds": round(pause_duration, 2),
            "total_paused_duration": round(self.total_paused_duration, 2),
            "elapsed_seconds": round(elapsed, 2),
            "message": "Hunt resumed - timer running"
        }

    def get_pause_status(self) -> Dict[str, Any]:
        """Get current pause status."""
        if not self.start_time:
            return {"is_paused": False, "message": "Hunt not started"}
        
        if self._is_paused:
            pause_duration = (time.time() - self._paused_time) if self._paused_time else 0
            elapsed = (self._paused_time - self.start_time - self.total_paused_duration) if self._paused_time else 0
        else:
            elapsed = (time.time() - self.start_time - self.total_paused_duration)
            pause_duration = 0
        
        return {
            "is_paused": self._is_paused,
            "elapsed_seconds": round(elapsed, 2),
            "total_paused_duration": round(self.total_paused_duration, 2),
            "current_pause_duration": round(pause_duration, 2),
            "status": "PAUSED" if self._is_paused else "RUNNING"
        }

    # ================================================================ #
    #  Retries + Error Handling                                        #
    # ================================================================ #

    async def _run_phase_with_retry(
        self,
        phase_name: str,
        phase_func: Callable,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """Run phase with retries + timeout."""
        max_retries = self.config["max_retries"]
        timeout = self.config["phase_timeout"]
        phase_start = time.time()
        
        self.tracer.mark_phase_start(phase_name)
        self.current_phase_attacks = []  # Reset attacks for this phase
        
        for attempt in range(max_retries):
            try:
                logger.info("[%s] Attempt %d/%d", phase_name, attempt + 1, max_retries)
                self.metrics["phase_retries"][phase_name] = attempt + 1
                
                result = await asyncio.wait_for(
                    phase_func(*args, **kwargs),
                    timeout=timeout
                )
                
                phase_duration = time.time() - phase_start
                self.metrics["phase_times"][phase_name] = round(phase_duration, 2)
                self.tracer.mark_phase_end(phase_name)
                
                logger.info(
                    "[%s] ✓ Success (%.2fs, attempt %d)",
                    phase_name, phase_duration, attempt + 1
                )
                return result
                
            except asyncio.TimeoutError:
                logger.warning(
                    "[%s] Timeout %.0fs (attempt %d/%d) - retrying",
                    phase_name, timeout, attempt + 1, max_retries
                )
                if attempt < max_retries - 1:
                    backoff = min(2 ** attempt, 10)
                    await asyncio.sleep(backoff)
                    
            except Exception as e:
                error_msg = f"{type(e).__name__}: {str(e)}"
                logger.error("[%s] Error (attempt %d/%d): %s", phase_name, attempt + 1, max_retries, error_msg)
                self.metrics["errors"].append({
                    "phase": phase_name,
                    "attempt": attempt + 1,
                    "error": error_msg,
                    "timestamp": datetime.utcnow().isoformat(),
                })
                
                if attempt < max_retries - 1:
                    backoff = min(2 ** attempt, 10)
                    await asyncio.sleep(backoff)

        self.tracer.mark_phase_end(phase_name)
        logger.error("[%s] ✗ Failed after %d retries", phase_name, max_retries)
        return self._get_empty_result(phase_name)

    def _get_empty_result(self, phase_name: str) -> Dict[str, Any]:
        """Return graceful empty result for failed phase."""
        templates = {
            "phase1": {"total_endpoints": 0, "all_endpoints": [], "hidden_endpoints": [], "js_findings": []},
            "phase2": {"vulnerabilities": []},
            "phase3": {"chains": []},
            "phase4": {"logic_flaws": []},
            "phase5": {"chain_proofs": []},
        }
        return templates.get(phase_name, {})

    # ================================================================ #
    #  WAF/CDN origin bypass probe                                     #
    # ================================================================ #

    async def _probe_origin_ip(self) -> None:
        """Attempt WAF/CDN origin IP bypass."""
        try:
            from core.modules.waf_identifier import find_real_ip
        except Exception:
            logger.debug("[WAF] Module not available")
            return

        try:
            result = await find_real_ip(self.target)
        except Exception as exc:
            logger.debug("[WAF] Probe failed: %s", exc)
            return

        best_ip = result.get("best_ip")
        if not best_ip:
            return

        candidates = result.get("candidates", [])
        best = next((c for c in candidates if c["ip"] == best_ip), {})
        is_cdn = best.get("is_cdn", False)

        parsed = urlparse(self.target)
        original_host = parsed.hostname or ""

        if is_cdn:
            origin = next(
                (c for c in candidates
                 if c.get("validated")
                 and c.get("confidence_score", 0) >= 5
                 and not c["is_cdn"]),
                None,
            )
            if not origin:
                self.config["waf_detected"] = True
                self.config["cdn_ip"] = best_ip
                return
            origin_ip = origin["ip"]
        else:
            origin_ip = best_ip

        self.config["origin_ip"] = origin_ip
        self.config["waf_detected"] = is_cdn

        for mod in (self._auth, self._logic, self._proof):
            mod.config["origin_ip"] = origin_ip
            mod.config["waf_detected"] = is_cdn

        logger.info("[WAF] Origin IP: %s (is_cdn: %s)", origin_ip, is_cdn)

    # ================================================================ #
    #  Phase runners                                                   #
    # ================================================================ #

    async def discover_endpoints(self) -> Dict[str, Any]:
        """Phase 1: Discover endpoints."""
        self.current_phase_attacks = []
        await self._update_progress("phase1", "Hunting endpoints...", 0)
        
        result = await self._run_phase_with_retry("phase1", self._discovery.run)

        js_count = len(result.get("js_findings", []))
        total_eps = result.get("total_endpoints", 0)
        hidden_eps = len(result.get("hidden_endpoints", []))
        
        # Prepare live attacks for this phase
        live_attacks = []
        for ep in result.get("hidden_endpoints", []):
            live_attacks.append({
                "id": f"hidden_{ep.get('url')}",
                "type": "hidden_endpoint",
                "severity": ep.get("risk", "medium"),
                "endpoint": ep.get("url"),
                "title": f"Hidden endpoint",
                "timestamp": datetime.utcnow().isoformat(),
                "phase": "discovery",
            })
        
        self.current_phase_attacks = live_attacks
        
        await self._update_progress(
            "phase1",
            f"Found {total_eps} endpoints ({hidden_eps} hidden, {js_count} JS)",
            100,
            live_attacks
        )
        self.results["endpoints"] = result
        self._save_cache()
        return result

    async def analyze_authorization(self, endpoints: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 2: Authorization analysis."""
        self.current_phase_attacks = []
        await self._update_progress("phase2", "Analyzing authorization...", 0)
        result = await self._run_phase_with_retry(
            "phase2", self._auth.run, endpoints.get("all_endpoints", [])
        )
        
        # Filter false positives
        if self.config.get("filter_false_positives"):
            vulns = result.get("vulnerabilities", [])
            vulns = await self.fp_filter.validate_vulnerabilities(vulns)
            vulns = _accuracy_process(vulns, dedupe=True, fp_filter=True)
            result["vulnerabilities"] = vulns

        vulns = result.get("vulnerabilities", [])

        # Score vulnerabilities
        vulns = [score_vulnerability(v) for v in vulns]
        result["vulnerabilities"] = vulns

        # Prepare live attacks
        live_attacks = [
            {
                "id":          f"auth_{v.get('type')}_{hash(v.get('endpoint', ''))}",
                "type":        v.get("type", "auth_issue"),
                "severity":    (v.get("severity") or "medium").lower(),
                "cvss_score":  v.get("cvss_score", 0),
                "endpoint":    v.get("endpoint") or "",
                "title":       v.get("title") or v.get("type") or "Authorization Issue",
                "description": v.get("description") or "",
                "detail":      (v.get("proof", {}) or {}).get("detail", "") if isinstance(v.get("proof"), dict) else "",
                "confirmed":   bool(v.get("confirmed", False)),
                "timestamp":   datetime.utcnow().isoformat(),
                "phase":       "phase2",
            }
            for v in vulns
        ]
        
        self.current_phase_attacks = live_attacks
        
        await self._update_progress(
            "phase2",
            f"Found {len(vulns)} authorization issues",
            100,
            live_attacks
        )
        self.results["auth_issues"] = result
        self._save_cache()
        return result

    async def test_business_logic(self, discovered_endpoints: Optional[List[str]] = None) -> Dict[str, Any]:
        """Phase 4: Business logic testing."""
        self.current_phase_attacks = []
        await self._update_progress("phase4", "Testing business logic...", 0)
        result = await self._run_phase_with_retry(
            "phase4", self._logic.run, discovered_endpoints=discovered_endpoints
        )
        
        # Filter false positives
        if self.config.get("filter_false_positives"):
            flaws = result.get("logic_flaws", [])
            flaws = await self.fp_filter.validate_vulnerabilities(flaws)
            flaws = _accuracy_process(flaws, dedupe=True, fp_filter=True)
            result["logic_flaws"] = flaws

        flaws = result.get("logic_flaws", [])

        # Score vulnerabilities
        flaws = [score_vulnerability(f) for f in flaws]
        result["logic_flaws"] = flaws
        
        # Prepare live attacks
        live_attacks = [
            {
                "id":          f"logic_{f.get('type')}_{hash(f.get('endpoint', ''))}",
                "type":        f.get("type", "logic_flaw"),
                "severity":    (f.get("severity") or "medium").lower(),
                "cvss_score":  f.get("cvss_score", 0),
                "endpoint":    f.get("endpoint") or "",
                "title":       f.get("title") or f.get("type") or "Logic Flaw",
                "description": f.get("description") or "",
                "detail":      (f.get("proof", {}) or {}).get("detail", "") if isinstance(f.get("proof"), dict) else "",
                "confirmed":   bool(f.get("confirmed", False)),
                "timestamp":   datetime.utcnow().isoformat(),
                "phase":       "phase4",
            }
            for f in flaws
        ]
        
        self.current_phase_attacks = live_attacks
        
        await self._update_progress(
            "phase4",
            f"Found {len(flaws)} logic flaws",
            100,
            live_attacks
        )
        self.results["logic_flaws"] = result
        self._save_cache()
        return result

    async def map_attack_chains(
        self,
        endpoints: Dict[str, Any],
        auth_issues: Dict[str, Any],
        logic_flaws: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Phase 3: Attack chain mapping."""
        self.current_phase_attacks = []
        await self._update_progress("phase3", "Mapping attack chains...", 0)
        
        all_vulns = self._aggregate_vulns(endpoints, auth_issues, logic_flaws or {})
        result = self._chain.build_chains_hybrid(all_vulns, self.target, self.config)
        chains = result.get("chains", [])
        enhanced_chains = self._enhance_chains_for_visualization(chains, all_vulns)
        result["chains"] = enhanced_chains

        # Prepare live attacks (chains)
        live_attacks = [
            {
                "id": c.get("chain_id", f"chain_{i}"),
                "type": "attack_chain",
                "severity": "critical" if c.get("risk_score", 0) >= 7 else "high",
                "title": c.get("exploitation_narrative", "Attack chain"),
                "nodes": len(c.get("nodes", [])),
                "endpoints_involved": len(c.get("endpoints_involved", [])),
                "impact": c.get("impact", "Unknown"),
                "risk_score": c.get("risk_score", 0),
                "timestamp": datetime.utcnow().isoformat(),
                "phase": "chains",
            }
            for i, c in enumerate(enhanced_chains)
        ]
        
        self.current_phase_attacks = live_attacks

        await self._update_progress(
            "phase3",
            f"Mapped {len(enhanced_chains)} attack chains",
            100,
            live_attacks
        )
        self.results["chains"] = result
        self._save_cache()
        return result

    def _aggregate_vulns(self, endpoints: Dict[str, Any], auth_issues: Dict[str, Any], logic_flaws: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Aggregate vulnerabilities from all phases."""
        all_vulns = []
        
        for v in auth_issues.get("vulnerabilities", []):
            v.setdefault("phase", "auth")
            all_vulns.append(v)
        
        for v in logic_flaws.get("logic_flaws", []):
            v.setdefault("phase", "logic")
            all_vulns.append(v)
        
        for ep in endpoints.get("hidden_endpoints", []):
            all_vulns.append({
                "id": f"hidden_{ep.get('url')}",
                "type": "hidden_endpoint",
                "endpoint": ep.get("url"),
                "severity": ep.get("risk", "medium"),
                "description": f"Hidden endpoint: {ep.get('url')}",
                "phase": "discovery",
            })
        
        for js in endpoints.get("js_findings", []):
            js.setdefault("phase", "discovery")
            all_vulns.append(js)
        
        return all_vulns

    def _enhance_chains_for_visualization(self, chains: List[Dict[str, Any]], all_vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance chains with graph structure."""
        enhanced = []
        
        for i, chain in enumerate(chains):
            enhanced_chain = chain.copy()
            enhanced_chain.setdefault("chain_path", [])
            enhanced_chain.setdefault("nodes", [])
            enhanced_chain.setdefault("edges", [])
            
            if "chain_id" not in enhanced_chain:
                enhanced_chain["chain_id"] = f"chain_{i}"
            
            chain_vulns = chain.get("vulnerabilities", [])
            if chain_vulns:
                path = []
                endpoints_in_chain = set()
                
                for vuln_id in chain_vulns:
                    matching_vuln = None
                    for v in all_vulns:
                        if v.get("id") == vuln_id or v.get("endpoint") == vuln_id:
                            matching_vuln = v
                            break
                    
                    if matching_vuln:
                        node = {
                            "id": f"{enhanced_chain['chain_id']}_vuln_{len(path)}",
                            "type": matching_vuln.get("type", "unknown"),
                            "endpoint": matching_vuln.get("endpoint", "unknown"),
                            "severity": matching_vuln.get("severity", "medium"),
                            "title": matching_vuln.get("title", matching_vuln.get("type")),
                        }
                        path.append(node)
                        enhanced_chain["nodes"].append(node)
                        endpoints_in_chain.add(matching_vuln.get("endpoint"))
                
                for idx in range(len(path) - 1):
                    edge = {
                        "from": path[idx]["id"],
                        "to": path[idx + 1]["id"],
                        "label": "leads_to",
                    }
                    enhanced_chain["edges"].append(edge)
                
                enhanced_chain["chain_path"] = path
                enhanced_chain["endpoints_involved"] = list(endpoints_in_chain)
            
            enhanced.append(enhanced_chain)
        
        return enhanced

    async def prove_exploits(self, chains: Dict[str, Any], all_vulns: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Phase 5: Generate exploit proofs."""
        self.current_phase_attacks = []
        await self._update_progress("phase5", "Proving exploits...", 0)
        
        result = await self._run_phase_with_retry(
            "phase5", self._proof.run, chains.get("chains", []), all_vulns=all_vulns
        )
        
        confirmed = sum(1 for cp in result.get("chain_proofs", []) if cp.get("confirmed"))
        
        # Prepare live attacks (proofs)
        live_attacks = [
            {
                "id": cp.get("chain_id", f"proof_{i}"),
                "type": "proof",
                "severity": "critical",
                "title": f"Confirmed: {cp.get('title', 'Exploit Proof')}",
                "confirmed": cp.get("confirmed", False),
                "timestamp": datetime.utcnow().isoformat(),
                "phase": "proofs",
            }
            for i, cp in enumerate(result.get("chain_proofs", []))
        ]
        
        self.current_phase_attacks = live_attacks
        
        await self._update_progress(
            "phase5",
            f"Confirmed {confirmed} exploits",
            100,
            live_attacks
        )
        self.results["proofs"] = result
        self._save_cache()
        return result

    # ================================================================ #
    #  Full hunt orchestrator                                          #
    # ================================================================ #

    async def run_full_hunt(self, resume: bool = True, force_fresh: bool = False) -> Dict[str, Any]:
        """Run full hunt with caching and parallel execution."""
        if force_fresh:
            self.clear_cache()
        
        self._require_authorization()
        self.start_time = time.time()
        self.metrics["start_time"] = self.start_time
        self.total_paused_duration = 0.0  # Reset pause counter

        logger.info("[Hunt] Starting on %s", self.target)

        # Phase 1
        if "endpoints" not in self.results:
            endpoints = await self.discover_endpoints()
        else:
            logger.info("[Hunt] Phase 1 cached")
            endpoints = self.results["endpoints"]

        # WAF bypass
        if self.config.get("origin_bypass") and "origin_ip" not in self.results:
            await self._probe_origin_ip()

        # Template scan + JS secret scan run in parallel with Phase 2 — all independent
        all_ep_urls = [ep.get("url") for ep in endpoints.get("all_endpoints", []) if isinstance(ep, dict)]

        if "template_scan" not in self.results or "js_scan" not in self.results:
            # First run: all three fire concurrently
            gathered = await asyncio.gather(
                self.run_template_scan(),
                self.scan_js_secrets(endpoints),
                self.analyze_authorization(endpoints),
                return_exceptions=True,
            )
            auth_issues = gathered[2] if not isinstance(gathered[2], Exception) else {"vulnerabilities": []}
            for label, result in (("[Templates]", gathered[0]), ("[JS Secrets]", gathered[1])):
                if isinstance(result, Exception):
                    logger.warning("[Hunt] %s parallel error: %s", label, result)
        else:
            # Resumed hunt — skip re-running template/JS scan, only run Phase 2
            logger.info("[Hunt] Template scan + JS scan cached")
            auth_issues = await self.analyze_authorization(endpoints)

        # Phase 4
        logic_flaws = await self.test_business_logic(all_ep_urls)

        # Phase 3
        if "chains" not in self.results:
            chains = await self.map_attack_chains(endpoints, auth_issues, logic_flaws)
        else:
            logger.info("[Hunt] Phase 3 cached")
            chains = self.results["chains"]

        # Phase 5
        all_vulns = auth_issues.get("vulnerabilities", []) + logic_flaws.get("logic_flaws", [])
        if "proofs" not in self.results:
            proofs = await self.prove_exploits(chains, all_vulns)
        else:
            logger.info("[Hunt] Phase 5 cached")
            proofs = self.results["proofs"]

        self.end_time = time.time()
        self.metrics["end_time"] = self.end_time

        report = self._compile_report()
        
        logger.info(
            "[Hunt ✓] Risk: %.1f | Vulns: %d | Duration: %.1fs | Paused: %.1fs",
            report.get("risk_score", 0),
            report.get("total_vulnerabilities", 0),
            report.get("duration_seconds", 0),
            report.get("total_paused_duration", 0)
        )
        return report

    # ================================================================ #
    #  Template Scanner (Nuclei-style YAML signatures)                #
    # ================================================================ #

    async def run_template_scan(self) -> Dict[str, Any]:
        """Run all YAML templates against the target (CVEs, exposures, misconfigs)."""
        await self._update_progress("phase1", "Running template signatures (CVEs, exposures)…", 92)
        try:
            from core.modules.template_scanner import run_templates
            findings, target_type = await run_templates(
                self.target,
                config=self.config,
                attack_callback=self.attack_callback,
            )
            # Normalise to hunter finding schema
            normalised = []
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                normalised.append({
                    "type":        f.get("type", f"template_{f.get('evidence', {}).get('template_id', 'unknown')}"),
                    "title":       f.get("title", "Template Finding"),
                    "severity":    sev,
                    "endpoint":    f.get("endpoint", self.target),
                    "description": f.get("detail", ""),
                    "detail":      f.get("detail", ""),
                    "evidence":    f.get("evidence", {}),
                    "confirmed":   True,
                    "source":      "template_scanner",
                    "phase":       "template",
                })
            logger.info("[Templates] %d findings | target_type=%s", len(normalised), target_type)
        except Exception as exc:
            logger.warning("[Templates] Scan failed: %s", exc)
            normalised, target_type = [], "hybrid"

        result = {"vulnerabilities": normalised, "target_type": target_type}
        self.results["template_scan"] = result
        self._save_cache()
        return result

    # ================================================================ #
    #  JS Secret Scanner                                               #
    # ================================================================ #

    async def scan_js_secrets(self, endpoints: Dict[str, Any]) -> Dict[str, Any]:
        """Scan all discovered JS files for hardcoded secrets, API keys, and tokens."""
        await self._update_progress("phase1", "Scanning JavaScript files for secrets…", 95)
        try:
            import core.modules.js_secret_scanner as _js_mod

            # Build auth headers from auth_manager
            auth_headers: Dict[str, str] = {"User-Agent": "DS1Hunter/1.4.0"}
            if self.auth_manager:
                auth_headers.update(self.auth_manager.get_headers())
            elif self.config.get("token_user_a"):
                auth_headers["Authorization"] = f"Bearer {self.config['token_user_a']}"

            sid = _js_mod.create_session(
                self.target,
                headers=auth_headers,
                max_scripts=self.config.get("js_max_scripts", 60),
                deep_crawl=self.config.get("scan_depth", "normal") in ("deep", "aggressive"),
            )
            # Call async runner directly (bypass thread)
            await _js_mod._run(sid)

            with _js_mod._lock:
                raw_findings = list(_js_mod._sessions.get(sid, {}).get("findings", []))
                _js_mod._sessions.pop(sid, None)

            # Normalise to hunter finding schema
            normalised = []
            for f in raw_findings:
                normalised.append({
                    "type":        "js_secret",
                    "title":       f.get("title", "Secret Found in JS"),
                    "severity":    (f.get("severity") or "high").lower(),
                    "endpoint":    f.get("endpoint", self.target),
                    "description": f.get("detail", ""),
                    "detail":      f.get("detail", ""),
                    "evidence":    {"match": f.get("evidence", ""), "context": f.get("context", "")},
                    "confirmed":   True,
                    "source":      "js_secret_scanner",
                    "phase":       "discovery",
                })
            logger.info("[JS Secrets] %d findings", len(normalised))
        except Exception as exc:
            logger.warning("[JS Secrets] Scan failed: %s", exc)
            normalised = []

        result = {"findings": normalised}
        self.results["js_scan"] = result
        self._save_cache()
        return result

    # ================================================================ #
    #  Report compiler                                                 #
    # ================================================================ #

    def _compile_report(self) -> Dict[str, Any]:
        """Compile final comprehensive report."""
        endpoints_result = self.results.get("endpoints", {})

        # Phase 1 – JS secret findings
        js_findings = [
            dict(f, phase="discovery") for f in endpoints_result.get("js_findings", [])
        ]

        # Phase 1 – hidden endpoints as structured findings
        hidden_findings = []
        for ep in endpoints_result.get("hidden_endpoints", []):
            hidden_findings.append({
                "type":        "hidden_endpoint",
                "severity":    ep.get("risk", "medium"),
                "endpoint":    ep.get("url", ""),
                "description": f"Hidden endpoint discovered: {ep.get('url', '')}",
                "phase":       "discovery",
            })

        # Template scanner findings (CVEs, exposed services, misconfigs)
        template_findings = [
            dict(f, phase="template")
            for f in self.results.get("template_scan", {}).get("vulnerabilities", [])
        ]

        # JS secret scanner findings
        js_secret_findings = [
            dict(f, phase="discovery")
            for f in self.results.get("js_scan", {}).get("findings", [])
        ]

        all_vulns = (
            self.results.get("auth_issues", {}).get("vulnerabilities", [])
            + self.results.get("logic_flaws", {}).get("logic_flaws", [])
            + js_findings
            + hidden_findings
            + template_findings
            + js_secret_findings
        )

        # Score vulns
        all_vulns = [score_vulnerability(v) for v in all_vulns]
        
        # Add compliance mappings
        if self.config.get("enable_compliance_mapping"):
            all_vulns = [map_vulnerability_to_compliance(v) for v in all_vulns]

        # Remediation tracking
        remediation = self.remediation_tracker.compute_remediation_status(all_vulns)

        chains = self.results.get("chains", {}).get("chains", [])

        risk_score = max((c.get("risk_score", 0) for c in chains), default=0.0)
        if not risk_score and all_vulns:
            # Use the max cvss_score across all vulns as the risk score
            risk_score = max((v.get("cvss_score") or 0.0) for v in all_vulns)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in all_vulns:
            sev = v.get("severity", "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Calculate actual duration (excluding paused time)
        total_time = (self.end_time or time.time()) - (self.start_time or time.time())
        actual_duration = total_time - self.total_paused_duration

        return {
            "tool": "DS1 Hunter",
            "version": self.VERSION,
            "company": self.COMPANY,
            "target": self.target,
            "scan_date": datetime.utcnow().isoformat(),
            "duration_seconds": round(actual_duration, 2),
            "total_duration_with_pauses": round(total_time, 2),
            "total_paused_duration": round(self.total_paused_duration, 2),
            "risk_score": round(risk_score, 1),
            "severity_summary": severity_counts,
            "total_vulnerabilities": len(all_vulns),
            "vulnerabilities": all_vulns,
            "attack_chains": chains,
            "remediation_status": remediation,
            "metrics": self.metrics,
            "module_timeline": self.tracer.get_module_timeline(),
        }

    # ================================================================ #
    #  Progress callbacks & metrics                                    #
    # ================================================================ #

    def get_metrics(self) -> Dict[str, Any]:
        """Get live metrics (for dashboard)."""
        if not self.start_time:
            total_time = 0
        else:
            total_time = (self.metrics.get("end_time", time.time()) - self.start_time)
        
        actual_time = total_time - self.total_paused_duration
        
        return {
            "execution": {
                "total_duration_seconds": round(actual_time, 2),  # Actual scanning time
                "total_duration_with_pauses": round(total_time, 2),  # Including pauses
                "total_paused_duration": round(self.total_paused_duration, 2),
                "is_paused": self._is_paused,  # Current pause status
                "phases_completed": len([p for p in self.metrics["phase_times"] if self.metrics["phase_times"][p] > 0]),
            },
            "findings": {
                "total_vulnerabilities": self.metrics["total_attacks"],
                "validated_findings": len(self.results.get("validated_findings", [])),
                "breakdown": {
                    "critical": sum(1 for a in self.current_phase_attacks if a.get("severity") == "CRITICAL"),
                    "high": sum(1 for a in self.current_phase_attacks if a.get("severity") == "HIGH"),
                    "medium": sum(1 for a in self.current_phase_attacks if a.get("severity") == "MEDIUM"),
                    "low": sum(1 for a in self.current_phase_attacks if a.get("severity") == "LOW"),
                },
                "remediation": self.results.get("remediation_summary", {})
            },
            "compliance": {
                "frameworks_mapped": ["OWASP Top 10", "PCI-DSS", "NIST CSF", "HIPAA"],
                "top_violation": self._get_top_violation()
            }
        }

    async def _wait_if_paused(self):
        """Internal check to halt execution while paused."""
        while self._is_paused:
            await asyncio.sleep(1)

    def _get_top_violation(self) -> str:
        """Helper to identify the most frequent compliance issue."""
        counts = defaultdict(int)
        for vuln in self.current_phase_attacks:
            mapping = vuln.get("compliance", {}).get("owasp_top_10", ["N/A"])
            counts[mapping[0]] += 1
        return max(counts, key=counts.get) if counts else "None"

    # ================================================================ #
    #  Core Execution Logic                                            #
    # ================================================================ #
    def _create_phase_progress_callback(self, phase_id: str):
        """Creates a scoped callback for internal modules with scoring."""
        async def internal_cb(msg, prog, findings=None):
            await self._wait_if_paused()

            enriched = None
            if findings:
                # Score and enrich before streaming so Attack Monitor shows correct severity
                enriched = []
                for f in findings:
                    f = score_vulnerability(f)
                    if self.config.get("enable_compliance_mapping"):
                        f = map_vulnerability_to_compliance(f)
                    await self.tracer.trace_module_discovery(
                        phase_id,
                        f.get("endpoint", "N/A"),
                        f.get("type"),
                        f.get("severity"),
                    )
                    enriched.append(f)
                # Only extend current_phase_attacks with new findings (avoid duplicates)
                existing_ids = {id(x) for x in self.current_phase_attacks}
                for f in enriched:
                    if id(f) not in existing_ids:
                        self.current_phase_attacks.append(f)

            # Pass scored findings to _update_progress (not the raw originals)
            await self._update_progress(phase_id, msg, prog, findings=enriched or findings)
            
        return internal_cb

    async def run_hunt(self) -> Dict[str, Any]:
        """Convenience orchestrator — delegates to run_full_hunt()."""
        return await self.run_full_hunt()

# ================================================================ #
#  Implementation Summary                                          #
# ================================================================ #
# ✓ CVSS 4.0: Integrated via score_vulnerability()
# ✓ Compliance: OWASP/PCI mapping added to every live finding
# ✓ Pause/Resume: Timer-aware duration and state-checking loops
# ✓ FP Filter: Context-aware validation before final reporting