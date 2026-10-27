from datetime import UTC, datetime

import pytest
from kilnbase_cli.migrate import checksum, new, pending

FILES = {"20260101000000_a": "create table a ();", "20260102000000_b": "create table b ();"}


def test_pending_in_order_and_crlf_is_not_a_change():
    assert pending(FILES, {}) == ["20260101000000_a", "20260102000000_b"]
    files = FILES | {"20260101000000_a": "create table a ();".replace(";", ";\r\n")}
    applied = {"20260101000000_a": checksum("create table a ();\n")}
    assert pending(files, applied) == ["20260102000000_b"]


@pytest.mark.parametrize(
    ("applied", "error"),
    [
        ({"20250101000000_gone": "x"}, "missing locally"),
        ({"20260101000000_a": "tampered"}, "were modified"),
        ({"20260102000000_b": checksum(FILES["20260102000000_b"])}, "sorts before"),
    ],
)
def test_pending_refuses_a_diverged_history(applied, error):
    with pytest.raises(ValueError, match=error):
        pending(FILES, applied)


def test_new_creates_a_timestamped_file(tmp_path, capsys):
    now = datetime(2026, 10, 27, 5, 6, 7, tzinfo=UTC)
    assert new(tmp_path / "m", "add_todos", now) == 0
    path = tmp_path / "m" / "20261027050607_add_todos.sql"
    assert path.read_text(encoding="utf-8") == "-- add_todos\n"
    with pytest.raises(FileExistsError):
        new(tmp_path / "m", "add_todos", now)
    assert new(tmp_path, "Bad Name") == 2
