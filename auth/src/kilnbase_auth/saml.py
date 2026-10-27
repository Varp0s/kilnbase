"""SAML 2.0 sign-in as a service provider: SP-initiated, HTTP-Redirect request, HTTP-POST response.

Every value is read from the element the IdP's signature covers (signxml's `signed_xml`), never from
the posted document, which is what defeats signature wrapping. Only responses to a request we sent
are accepted, so IdP-initiated sign-in and replays fail on InResponseTo.
"""

import base64
import binascii
import re
import secrets
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode
from xml.sax.saxutils import escape, quoteattr

from cryptography import x509
from lxml import etree
from signxml import SignatureMethod, XMLVerifier
from signxml.exceptions import InvalidInput, InvalidSignature
from signxml.verifier import SignatureConfiguration

from .oauth import ExternalUser

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
EMAIL_ATTRIBUTES = {
    "email",
    "mail",
    "emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
}
CLOCK_SKEW = timedelta(seconds=60)
MAX_RESPONSE_BYTES = 256 * 1024
# SHA-2 RSA/ECDSA only: no SHA-1, and no HMAC (a shared secret has no place in SAML).
SIGNATURE_METHODS = frozenset(
    m
    for m in SignatureMethod
    if m.name.startswith(("RSA_SHA", "ECDSA_SHA", "SHA256_RSA", "SHA384_RSA", "SHA512_RSA"))
    and "SHA1" not in m.name
)
PARSER = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, huge_tree=False)


class SamlError(Exception):
    pass


@dataclass(frozen=True)
class IdentityProvider:
    name: str
    entity_id: str
    sso_url: str
    cert: x509.Certificate
    # The only email domains this IdP may sign in or link accounts for.
    domains: frozenset[str]


def load_identity_providers(env: Mapping[str, str]) -> dict[str, IdentityProvider]:
    """Enabled by KILNBASE_SAML_<NAME>_SSO_URL, plus _ENTITY_ID, _CERT and _DOMAINS."""
    providers = {}
    prefix, suffix = "KILNBASE_SAML_", "_SSO_URL"
    for key, sso_url in env.items():
        if not (key.startswith(prefix) and key.endswith(suffix)) or not sso_url.strip():
            continue
        upper = key[len(prefix) : -len(suffix)]

        def setting(field: str, _upper=upper) -> str:
            value = env.get(f"KILNBASE_SAML_{_upper}_{field}", "").strip()
            if not value:
                raise ValueError(f"KILNBASE_SAML_{_upper}_{field} is required")
            return value

        if not sso_url.strip().startswith("https://") and "localhost" not in sso_url:
            raise ValueError(f"KILNBASE_SAML_{upper}_SSO_URL must be an https URL")
        domains = frozenset(d.strip().lower() for d in setting("DOMAINS").split(",") if d.strip())
        providers[upper.lower()] = IdentityProvider(
            name=upper.lower(),
            entity_id=setting("ENTITY_ID"),
            sso_url=sso_url.strip(),
            cert=load_cert(setting("CERT"), f"KILNBASE_SAML_{upper}_CERT"),
            domains=domains,
        )
    return providers


def load_cert(value: str, name: str) -> x509.Certificate:
    """A PEM, or the single-line base64 body IdP consoles show."""
    if "-----BEGIN" not in value:
        body = re.sub(r"\s+", "", value)
        value = "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
    try:
        return x509.load_pem_x509_certificate(value.replace("\\n", "\n").encode())
    except ValueError as e:
        raise ValueError(f"{name} is not a valid X.509 certificate") from e


def new_request_id() -> str:
    # xs:ID values must not start with a digit.
    return "_" + secrets.token_hex(20)


def authn_redirect(
    idp: IdentityProvider,
    sp_entity_id: str,
    acs_url: str,
    request_id: str,
    relay_state: str,
    now: datetime | None = None,
) -> str:
    issued = (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}"'
        f' ID={quoteattr(request_id)} Version="2.0" IssueInstant="{issued}"'
        f" Destination={quoteattr(idp.sso_url)} AssertionConsumerServiceURL={quoteattr(acs_url)}"
        ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f"<saml:Issuer>{escape(sp_entity_id)}</saml:Issuer>"
        '<samlp:NameIDPolicy AllowCreate="true"/>'
        "</samlp:AuthnRequest>"
    )
    deflate = zlib.compressobj(wbits=-15)  # the Redirect binding uses raw DEFLATE
    encoded = base64.b64encode(deflate.compress(xml.encode()) + deflate.flush()).decode()
    separator = "&" if "?" in idp.sso_url else "?"
    query = urlencode({"SAMLRequest": encoded, "RelayState": relay_state})
    return f"{idp.sso_url}{separator}{query}"


def _time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as e:
        raise SamlError(f"invalid time {value!r}") from e
    if parsed.tzinfo is None:
        raise SamlError(f"time without a zone {value!r}")
    return parsed


def _verify(element: etree._Element, idp: IdentityProvider) -> etree._Element:
    """Checks the signature that is a direct child of `element`; returns what it covers."""
    try:
        result = XMLVerifier().verify(
            element,
            x509_cert=idp.cert,
            expect_config=SignatureConfiguration(
                location="./", expect_references=1, signature_methods=SIGNATURE_METHODS
            ),
        )
    except (InvalidSignature, InvalidInput) as e:
        raise SamlError(f"signature: {e}") from e
    signed = result.signed_xml
    if signed is None or signed.tag != element.tag:
        raise SamlError("the signature does not cover the whole element")
    return signed


def verify_response(
    raw: str,
    idp: IdentityProvider,
    *,
    sp_entity_id: str,
    acs_url: str,
    request_id: str,
    now: datetime | None = None,
) -> ExternalUser:
    """Validates a posted SAMLResponse; raises SamlError with the reason (for logs, not users)."""
    now = now or datetime.now(UTC)
    if len(raw) > MAX_RESPONSE_BYTES * 4 // 3 + 4:
        raise SamlError("response too large")
    try:
        document = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as e:
        raise SamlError("response is not base64") from e
    if b"<!DOCTYPE" in document.upper() or b"<!ENTITY" in document.upper():
        raise SamlError("DTDs are not allowed")
    try:
        root = etree.fromstring(document, PARSER)
    except etree.XMLSyntaxError as e:
        raise SamlError("response is not XML") from e
    if root.tag != f"{{{NS['samlp']}}}Response":
        raise SamlError("not a SAML Response")
    if root.find("saml:EncryptedAssertion", NS) is not None:
        raise SamlError("encrypted assertions are not supported")

    if root.find("ds:Signature", NS) is not None:
        response = _verify(root, idp)
        assertions = response.findall("saml:Assertion", NS)
        if len(assertions) != 1:
            raise SamlError("expected exactly one assertion")
        assertion = assertions[0]
        if assertion.find("ds:Signature", NS) is not None:
            # Both signed: the assertion's own signature must hold too.
            assertion = _verify(assertion, idp)
    else:
        response = root  # unsigned envelope: only the signed assertion below is trusted
        assertions = root.findall("saml:Assertion", NS)
        if len(assertions) != 1:
            raise SamlError("expected exactly one assertion")
        assertion = _verify(assertions[0], idp)

    status = response.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != SUCCESS:
        raise SamlError("the IdP reported a failure")
    if response.get("Destination") not in (None, acs_url):
        raise SamlError("wrong Destination")

    if assertion.findtext("saml:Issuer", namespaces=NS) != idp.entity_id:
        raise SamlError("wrong Issuer")

    conditions = assertion.find("saml:Conditions", NS)
    if conditions is None:
        raise SamlError("no Conditions")
    not_before = _time(conditions.get("NotBefore"))
    not_after = _time(conditions.get("NotOnOrAfter"))
    if not_before and now + CLOCK_SKEW < not_before:
        raise SamlError("assertion not yet valid")
    if not not_after or now - CLOCK_SKEW >= not_after:
        raise SamlError("assertion expired")
    audiences = [a.text for a in conditions.findall("saml:AudienceRestriction/saml:Audience", NS)]
    if sp_entity_id not in audiences:
        raise SamlError("wrong Audience")

    subject = assertion.find("saml:Subject", NS)
    name_id = subject.find("saml:NameID", NS) if subject is not None else None
    if name_id is None or not (name_id.text or "").strip():
        raise SamlError("no NameID")
    confirmed = False
    for confirmation in subject.findall("saml:SubjectConfirmation", NS):
        data = confirmation.find("saml:SubjectConfirmationData", NS)
        if confirmation.get("Method") != BEARER or data is None:
            continue
        expires = _time(data.get("NotOnOrAfter"))
        if (
            data.get("Recipient") == acs_url
            and data.get("InResponseTo") == request_id
            and expires is not None
            and now - CLOCK_SKEW < expires
        ):
            confirmed = True
    if not confirmed:
        raise SamlError("no valid bearer SubjectConfirmation for this request")

    email = None
    for attribute in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        if attribute.get("Name", "").lower() in EMAIL_ATTRIBUTES:
            email = attribute.findtext("saml:AttributeValue", namespaces=NS)
            break
    if email is None and name_id.get("Format") == EMAIL_FORMAT:
        email = name_id.text
    email = email.strip().lower() if email else None
    domain = email.rpartition("@")[2] if email and "@" in email else None
    return ExternalUser(
        id=name_id.text.strip(),
        email=email,
        # The IdP vouches only for its own domains; anything else could take over other accounts.
        email_verified=domain in idp.domains,
    )
