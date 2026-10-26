import io
import json
import tarfile
from datetime import UTC, datetime

import pytest
from kilnbase_cli.backup import check_manifest, make_manifest, read_backup, restore

CURRENT = {"0001_roles": "aaa", "0002_auth_helpers": "bbb"}


def manifest(migrations=CURRENT):
    return make_manifest(dict(migrations), "0.1.0", datetime(2026, 10, 27, tzinfo=UTC))


def test_matching_migrations_restore():
    assert check_manifest(manifest(), CURRENT) is None


@pytest.mark.parametrize(
    ("saved", "message"),
    [
        ({"0001_roles": "aaa"}, "predates migrations 0002_auth_helpers"),
        (CURRENT | {"0003_new": "ccc"}, "lacks: 0003_new"),
        (CURRENT | {"0002_auth_helpers": "edited"}, "differ: 0002_auth_helpers"),
    ],
)
def test_mismatched_migrations_are_refused(saved, message):
    problem = check_manifest(manifest(saved), CURRENT)
    assert message in problem
    assert "kilnbase 0.1.0" in problem


def test_unknown_format_is_refused():
    assert "format" in check_manifest(manifest() | {"format": 99}, CURRENT)
    assert "migration" in check_manifest({"format": 1}, CURRENT)


def archive(path, members):
    with tarfile.open(path, "w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_reads_manifest_and_requires_every_member(tmp_path):
    good = tmp_path / "good.tar"
    data = json.dumps(manifest()).encode()
    archive(good, {"manifest.json": data, "db.dump": b"x", "storage.tar": b""})
    saved, tar = read_backup(good)
    tar.close()
    assert saved["migrations"] == CURRENT

    partial = tmp_path / "partial.tar"
    archive(partial, {"manifest.json": data})
    with pytest.raises(ValueError, match="db.dump, storage.tar"):
        read_backup(partial)


def test_restore_rejects_a_non_backup_before_touching_docker(tmp_path):
    bogus = tmp_path / "bogus.tar"
    bogus.write_bytes(b"not a tar")
    assert restore(tmp_path / ".env", bogus, yes=True) == 1
