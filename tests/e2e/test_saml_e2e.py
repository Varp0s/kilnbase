"""SAML sign-in through the gateway; the test plays the IdP with the test-only key in tests/saml."""

import base64
import uuid
import zlib
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import ROOT
from lxml import etree
from signxml import XMLSigner
from test_oauth import APP, exchange, pkce

ACS = "http://localhost:8000/auth/v1/callback"
SP = "http://localhost:8000/auth/v1/saml"
IDP = "https://idp.e2e.test"
KEY = (ROOT / "tests/saml/idp.key").read_bytes()
CERT = (ROOT / "tests/saml/idp.crt").read_text()


@pytest.fixture(scope="module", autouse=True)
def enabled(client):
    r = client.get(
        "/auth/v1/authorize",
        params={"provider": "testidp", "redirect_to": APP, "code_challenge": "x" * 43},
    )
    if r.status_code != 302:
        pytest.skip("start the stack with docker-compose.test.yml to run SAML tests")


def start(client, challenge):
    """Returns the AuthnRequest ID and RelayState the IdP would receive."""
    r = client.get(
        "/auth/v1/authorize",
        params={"provider": "testidp", "redirect_to": APP, "code_challenge": challenge},
    )
    assert r.status_code == 302, r.text
    query = parse_qs(urlsplit(r.headers["location"]).query)
    request = zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), wbits=-15)
    return etree.fromstring(request).get("ID"), query["RelayState"][0]


def signed_response(request_id, name_id, email):
    now = datetime.now(UTC)
    t = lambda d: (now + d).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    assertion = etree.fromstring(
        f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
 ID="_a{uuid.uuid4().hex}" Version="2.0" IssueInstant="{t(timedelta())}">
<saml:Issuer>{IDP}</saml:Issuer>
<saml:Subject><saml:NameID>{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData Recipient="{ACS}" InResponseTo="{request_id}"
 NotOnOrAfter="{t(timedelta(minutes=5))}"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="{t(-timedelta(minutes=1))}" NotOnOrAfter="{t(timedelta(minutes=5))}">
<saml:AudienceRestriction><saml:Audience>{SP}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions><saml:AttributeStatement><saml:Attribute Name="email">
<saml:AttributeValue>{email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion>""".encode()
    )
    signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    assertion = signer.sign(assertion, key=KEY, cert=CERT, reference_uri=assertion.get("ID"))
    response = etree.fromstring(
        f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"
 Version="2.0" IssueInstant="{t(timedelta())}" Destination="{ACS}" InResponseTo="{request_id}">
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
</samlp:Status></samlp:Response>""".encode()
    )
    response.append(assertion)
    return base64.b64encode(etree.tostring(response)).decode()


def post_back(client, saml_response, relay_state):
    """What the browser does with the IdP's auto-submitting form; no API key."""
    return client.post(
        "/auth/v1/callback", data={"SAMLResponse": saml_response, "RelayState": relay_state}
    )


def landing(r):
    assert r.status_code == 302, r.text
    assert r.headers["location"].startswith(APP)
    return {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}


def test_sign_in_creates_a_user_and_replays_fail(client, keys):
    verifier, challenge = pkce()
    request_id, relay = start(client, challenge)
    email = f"saml-{uuid.uuid4().hex[:8]}@saml.e2e.test"
    saml = signed_response(request_id, f"id-{uuid.uuid4().hex}", email)

    params = landing(post_back(client, saml, relay))
    session = exchange(client, keys, params["code"], verifier)
    assert session.status_code == 200, session.text
    assert session.json()["user"]["email"] == email

    assert post_back(client, saml, relay).status_code == 400  # state is single use


def test_tampered_and_foreign_responses_are_refused(client):
    _, challenge = pkce()
    request_id, relay = start(client, challenge)
    saml = signed_response(request_id, "id-1", "ada@saml.e2e.test")
    tampered = base64.b64encode(
        base64.b64decode(saml).replace(b"ada@saml.e2e.test", b"eve@saml.e2e.test")
    ).decode()
    assert landing(post_back(client, tampered, relay)) == {"error": "provider_error"}

    # A valid response to a different request does not answer this one.
    _, relay = start(client, challenge)
    assert landing(post_back(client, saml, relay)) == {"error": "provider_error"}


def test_emails_outside_the_idps_domains_cannot_claim_accounts(client):
    _, challenge = pkce()
    request_id, relay = start(client, challenge)
    saml = signed_response(request_id, f"id-{uuid.uuid4().hex}", "victim@example.com")
    assert landing(post_back(client, saml, relay)) == {"error": "email_not_verified"}
