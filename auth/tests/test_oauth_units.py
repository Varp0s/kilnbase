import pytest
from kilnbase_auth.oauth import load_providers, pkce_challenge, redirect_allowed

ALLOWED = ["https://app.example.com", "http://localhost:3000/callback"]


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://app.example.com", True),
        ("https://app.example.com/auth/done", True),
        ("http://localhost:3000/callback", True),
        ("https://app.example.com.evil.net/", False),
        ("https://app.example.comevil.net", False),
        ("https://user:pass@app.example.com/x", False),
        ("http://localhost:3000/callbackx", False),
        ("javascript:alert(1)", False),
        ("//app.example.com/x", False),
    ],
)
def test_redirect_allow_list(url, ok):
    assert redirect_allowed(url, ALLOWED) is ok


def test_known_providers_need_only_credentials():
    providers = load_providers(
        {"KILNBASE_OAUTH_GITHUB_CLIENT_ID": "id", "KILNBASE_OAUTH_GITHUB_CLIENT_SECRET": "s"}
    )
    assert providers["github"].token_url == "https://github.com/login/oauth/access_token"


def test_unknown_providers_need_urls_and_empty_ids_are_ignored():
    with pytest.raises(ValueError, match="AUTHORIZE_URL"):
        load_providers(
            {"KILNBASE_OAUTH_ACME_CLIENT_ID": "id", "KILNBASE_OAUTH_ACME_CLIENT_SECRET": "s"}
        )
    assert load_providers({"KILNBASE_OAUTH_GITHUB_CLIENT_ID": ""}) == {}


def test_pkce_matches_rfc7636_example():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
