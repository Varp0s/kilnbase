import json
import logging

from kilnbase_auth.log import JsonFormatter


def fmt(name, msg, args, level=logging.INFO):
    record = logging.LogRecord(name, level, __file__, 1, msg, args, None)
    return json.loads(JsonFormatter().format(record))


def test_plain_lines_carry_the_shared_fields():
    line = fmt("kilnbase", "applied migration %s", ("0001",), logging.WARNING)
    assert line["msg"] == "applied migration 0001"
    assert (line["level"], line["service"]) == ("warning", "auth")
    assert isinstance(line["ts"], float)


def test_access_lines_drop_the_query_string():
    args = ("10.0.0.1:5000", "GET", "/verify?type=magiclink&token=secret", "1.1", 303)
    line = fmt("uvicorn.access", '%s - "%s %s HTTP/%s" %d', args)
    assert line["msg"] == "request"
    assert (line["method"], line["path"], line["status"]) == ("GET", "/verify", 303)
    assert "secret" not in json.dumps(line)
