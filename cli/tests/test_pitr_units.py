from datetime import UTC, datetime, timedelta

import pytest
from kilnbase_cli.pitr import check_target, parse_target, pgbackrest_time, window

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


def test_targets_need_an_offset_and_use_pgbackrests_format():
    with pytest.raises(ValueError, match="offset"):
        parse_target("2026-10-27T10:00:00")
    t = parse_target("2026-10-27T13:00:00.5+03:00")
    assert pgbackrest_time(t) == "2026-10-27 10:00:00.500000+00"


def test_targets_must_be_inside_the_window():
    earliest = NOW - timedelta(hours=1)
    assert check_target(NOW - timedelta(minutes=5), earliest, NOW) is None
    assert "no backups" in check_target(NOW, None, NOW)
    assert "earliest" in check_target(earliest - timedelta(seconds=1), earliest, NOW)
    assert "not in the past" in check_target(NOW, earliest, NOW)


def test_window_spans_the_backups():
    info = {"backup": [{"timestamp": {"stop": 100}}, {"timestamp": {"stop": 200}}]}
    start, end = window(info)
    assert (start.timestamp(), end.timestamp()) == (100, 200)
    assert window({}) is None
