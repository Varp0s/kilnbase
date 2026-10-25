from pathlib import Path

import pytest
from kilnbase_auth.migrate import MigrationError, checksum, load, verify

MIGRATIONS = [("0001_a", "create table a ();"), ("0002_b", "create table b ();")]


def test_checksum_ignores_line_endings_only():
    assert checksum("a\r\nb\n") == checksum("a\nb\n")
    assert checksum("a\nb\n") != checksum("a\nc\n")


def test_verify_accepts_matching_and_legacy_rows():
    verify({"0001_a": checksum("create table a ();"), "0002_b": None}, MIGRATIONS)
    verify({}, MIGRATIONS)


def test_verify_rejects_edited_migrations():
    with pytest.raises(MigrationError, match="0001_a"):
        verify({"0001_a": checksum("create table a (id int);")}, MIGRATIONS)


def test_verify_rejects_databases_from_newer_versions():
    with pytest.raises(MigrationError, match="0009_future"):
        verify({"0009_future": "x"}, MIGRATIONS)


def test_shipped_migrations_load_in_order():
    root = Path(__file__).resolve().parents[2] / "migrations"
    versions = [v for v, _ in load(root)]
    assert versions == sorted(versions)
    assert versions[0] == "0001_roles"
