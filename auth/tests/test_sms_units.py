import pytest
from kilnbase_auth.config import ConfigError, load
from kilnbase_auth.sms import http_allowed, normalize_phone
from test_config import VALID

SECRET = "x" * 32


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("+15551234567", "+15551234567"),
        ("+90 (532) 123-45.67", "+905321234567"),
        ("15551234567", None),
        ("+05551234567", None),
        ("+1234567", None),
        ("+1234567890123456", None),
        ("+1555abc4567", None),
        ("", None),
    ],
)
def test_normalize_phone(raw, expected):
    assert normalize_phone(raw) == expected


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://sms.example.com/send", True),
        ("http://sms-hook:8080/send", True),
        ("http://localhost:9000/", True),
        ("http://sms.example.com/send", False),
        ("ftp://sms-hook/", False),
        ("https://", False),
    ],
)
def test_hook_url(url, ok):
    assert http_allowed(url) is ok


def test_sms_config():
    assert load(VALID).sms_url is None
    good = load(
        VALID | {"KILNBASE_SMS_URL": "https://h.example.com", "KILNBASE_SMS_SECRET": SECRET}
    )
    assert good.sms_url == "https://h.example.com"
    for bad in (
        {"KILNBASE_SMS_URL": "https://h.example.com"},
        {"KILNBASE_SMS_URL": "https://h.example.com", "KILNBASE_SMS_SECRET": "short"},
        {"KILNBASE_SMS_URL": "http://h.example.com", "KILNBASE_SMS_SECRET": SECRET},
    ):
        with pytest.raises(ConfigError):
            load(VALID | bad)
