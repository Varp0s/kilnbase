import hashlib
import hmac

from kilnbase_auth.webhooks import backoff, sign


def test_signature_covers_timestamp_and_body():
    expected = hmac.new(b"k", b'1700000000.{"a":1}', hashlib.sha256).hexdigest()
    assert sign("k", 1700000000, '{"a":1}') == f"v1={expected}"
    assert sign("k", 1700000001, '{"a":1}') != sign("k", 1700000000, '{"a":1}')


def test_backoff_doubles_and_caps():
    assert [backoff(n) for n in (1, 2, 3)] == [10, 20, 40]
    assert backoff(20) == 3600
