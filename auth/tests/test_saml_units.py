import base64
import copy
import zlib
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from kilnbase_auth.saml import (
    IdentityProvider,
    SamlError,
    authn_redirect,
    load_identity_providers,
    new_request_id,
    verify_response,
)
from lxml import etree
from signxml import XMLSigner

SP = "https://api.example.com/auth/v1/saml"
ACS = "https://api.example.com/auth/v1/callback"
IDP_ENTITY = "https://idp.example.com"
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
REQUEST_ID = "_abc123"


def keypair(name="idp"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


KEY, CERT = keypair()
OTHER_KEY, OTHER_CERT = keypair("attacker")
IDP = IdentityProvider(
    "acme", IDP_ENTITY, "https://idp.example.com/sso", CERT, frozenset({"acme.com"})
)


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def assertion_xml(
    name_id="u-1",
    email="ada@acme.com",
    audience=SP,
    recipient=ACS,
    in_response_to=REQUEST_ID,
    not_after=NOW + timedelta(minutes=5),
    issuer=IDP_ENTITY,
    aid="_a1",
):
    return f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}"
 Version="2.0" IssueInstant="{iso(NOW)}"><saml:Issuer>{issuer}</saml:Issuer>
<saml:Subject><saml:NameID>{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData Recipient="{recipient}" InResponseTo="{in_response_to}"
 NotOnOrAfter="{iso(not_after)}"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="{iso(NOW - timedelta(minutes=1))}" NotOnOrAfter="{iso(not_after)}">
<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AttributeStatement><saml:Attribute Name="email">
<saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"""


def sign(xml, key=KEY, cert=CERT):
    element = etree.fromstring(xml.encode())
    signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    signed = signer.sign(element, key=key, cert=[cert], reference_uri=element.get("ID"))
    # signxml appends the signature; SAML's schema wants it right after Issuer.
    signature = signed[-1]
    signed.remove(signature)
    signed.insert(1, signature)
    return signed


def response(assertion, signed_response=False, destination=ACS, status="Success"):
    root = etree.fromstring(
        f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0"
 IssueInstant="{iso(NOW)}" Destination="{destination}" InResponseTo="{REQUEST_ID}">
<saml:Issuer>{IDP_ENTITY}</saml:Issuer><samlp:Status>
<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:{status}"/>
</samlp:Status></samlp:Response>""".encode()
    )
    root.append(assertion)
    if signed_response:
        root = sign(etree.tostring(root).decode())
    return base64.b64encode(etree.tostring(root)).decode()


def check(raw, **kwargs):
    args = {"sp_entity_id": SP, "acs_url": ACS, "request_id": REQUEST_ID, "now": NOW} | kwargs
    return verify_response(raw, IDP, **args)


def test_signed_assertion_is_accepted():
    user = check(response(sign(assertion_xml())))
    assert (user.id, user.email, user.email_verified) == ("u-1", "ada@acme.com", True)


def test_signed_response_around_unsigned_assertion_is_accepted():
    user = check(response(etree.fromstring(assertion_xml().encode()), signed_response=True))
    assert user.id == "u-1"


def test_response_and_assertion_both_signed_is_accepted():
    assert check(response(sign(assertion_xml()), signed_response=True)).id == "u-1"


def test_email_outside_the_idps_domains_is_not_verified():
    assert check(response(sign(assertion_xml(email="ceo@victim.com")))).email_verified is False


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (lambda: response(etree.fromstring(assertion_xml().encode())), "signature"),
        (lambda: response(sign(assertion_xml(), OTHER_KEY, OTHER_CERT)), "signature"),
        (lambda: response(sign(assertion_xml(audience="https://other"))), "Audience"),
        (lambda: response(sign(assertion_xml(recipient="https://evil/acs"))), "Confirmation"),
        (lambda: response(sign(assertion_xml(in_response_to="_other"))), "Confirmation"),
        (lambda: response(sign(assertion_xml(not_after=NOW - timedelta(minutes=5)))), "expired"),
        (lambda: response(sign(assertion_xml(issuer="https://evil"))), "Issuer"),
        (lambda: response(sign(assertion_xml()), destination="https://evil/acs"), "Destination"),
        (lambda: response(sign(assertion_xml()), status="Requester"), "failure"),
    ],
)
def test_bad_responses_are_rejected(raw, reason):
    with pytest.raises(SamlError, match=reason):
        check(raw())


def test_signature_wrapping_is_rejected():
    genuine = sign(assertion_xml(name_id="victim-id", email="victim@acme.com"))
    forged = etree.fromstring(assertion_xml(name_id="attacker", aid="_a1").encode())
    # The forged assertion carries the genuine signature; the genuine one hides inside it.
    forged.insert(1, copy.deepcopy(genuine.find("{http://www.w3.org/2000/09/xmldsig#}Signature")))
    with pytest.raises(SamlError):
        check(response(forged))
    # Two assertions side by side, only one signed: refused outright.
    root = etree.fromstring(base64.b64decode(response(genuine)))
    root.append(etree.fromstring(assertion_xml(name_id="attacker", aid="_a2").encode()))
    with pytest.raises(SamlError, match="exactly one"):
        check(base64.b64encode(etree.tostring(root)).decode())


def test_dtds_are_refused():
    xml = b'<!DOCTYPE r [<!ENTITY x "y">]><r xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>'
    with pytest.raises(SamlError, match="DTD"):
        check(base64.b64encode(xml).decode())


def test_authn_request_round_trips():
    request_id = new_request_id()
    assert request_id[0] == "_"
    url = authn_redirect(IDP, SP, ACS, request_id, "state-1", NOW)
    query = parse_qs(urlsplit(url).query)
    assert query["RelayState"] == ["state-1"]
    xml = etree.fromstring(zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), wbits=-15))
    assert xml.get("ID") == request_id and xml.get("AssertionConsumerServiceURL") == ACS


def test_config_needs_every_field_and_accepts_a_bare_certificate():
    body = base64.b64encode(CERT.public_bytes(serialization.Encoding.DER)).decode()
    env = {
        "KILNBASE_SAML_ACME_SSO_URL": "https://idp.example.com/sso",
        "KILNBASE_SAML_ACME_ENTITY_ID": IDP_ENTITY,
        "KILNBASE_SAML_ACME_CERT": body,
        "KILNBASE_SAML_ACME_DOMAINS": "Acme.com, acme.io",
    }
    idp = load_identity_providers(env)["acme"]
    assert idp.cert == CERT and idp.domains == {"acme.com", "acme.io"}
    with pytest.raises(ValueError, match="DOMAINS"):
        load_identity_providers({k: v for k, v in env.items() if "DOMAINS" not in k})
