import json
import subprocess
from contextlib import nullcontext

import pytest
from kilnbase_cli import upgrade

FILES = ["/p/docker-compose.yml", "/p/docker-compose.test.yml", "/p/kilnbase-rollback.json"]
UP = ("up", "-d", "--wait")


class FakeStack:
    def __init__(self, root):
        self.project, self.db = "kb", "dbid"

    def containers(self):
        return [("db", "sha256:d", FILES[:1]), ("core", "sha256:c", FILES)]


@pytest.fixture
def run(monkeypatch, tmp_path):
    """Runs an upgrade against fakes; returns (exit code, calls) where calls name each step."""

    def go(fail_up=False):
        calls = []

        def docker(*args, **kwargs):
            calls.append(args)
            if fail_up and args[-3:] == UP:
                raise subprocess.CalledProcessError(1, args, stderr=b"auth: migration failed")
            return subprocess.CompletedProcess(args, 0, stdout="")

        monkeypatch.setattr(upgrade, "docker", docker)
        monkeypatch.setattr(upgrade, "Stack", FakeStack)
        monkeypatch.setattr(upgrade, "core_healthy", lambda compose: True)
        monkeypatch.setattr(upgrade, "backup", lambda env, out: calls.append(("backup",)) or 0)
        monkeypatch.setattr(upgrade, "read_backup", lambda p: ({"created_at": "t"}, nullcontext()))
        monkeypatch.setattr(upgrade, "stage", lambda stack, tar, tmp: calls.append(("stage",)))
        monkeypatch.setattr(upgrade, "replace_data", lambda st, objects: calls.append(("replace",)))
        return upgrade.run(tmp_path / ".env"), calls

    return go


def compose_steps(calls):
    """Each call without its compose project/file flags (or just the command name)."""
    last_file = lambda c: max(i for i, a in enumerate(c) if a == "-f")  # noqa: E731
    return [c[last_file(c) + 2 :] if c[0] == "compose" else c[:1] for c in calls]


def test_success_backs_up_with_core_stopped_and_drops_old_pins(run, tmp_path):
    (tmp_path / "kilnbase-rollback.json").write_text("{}")
    code, calls = run()
    assert code == 0
    for c in calls:
        if c[0] == "compose":
            assert c[:7] == ("compose", "-p", "kb", "-f", FILES[0], "-f", FILES[1])
            assert c[7] != "-f"  # the previous rollback override is left out
    assert compose_steps(calls) == [
        ("tag",),
        ("tag",),
        ("pull", "--ignore-buildable"),
        ("build",),
        ("stop", "core"),
        ("backup",),
        UP,
        ("image",),
    ]
    assert not (tmp_path / "kilnbase-rollback.json").exists()


def test_failed_start_restores_data_and_pins_previous_images(run, tmp_path):
    code, calls = run(fail_up=True)
    assert code == 1
    pins = json.loads((tmp_path / "kilnbase-rollback.json").read_text())["services"]
    assert set(pins) == {"db", "core"}
    assert pins["core"]["image"].startswith("kilnbase-rollback/core:")
    tagged = {c[2] for c in calls if c[0] == "tag"}
    assert tagged == {p["image"] for p in pins.values()}

    after = calls[[c[-3:] for c in calls].index(UP) + 1 :]
    override = str(tmp_path / "kilnbase-rollback.json")
    assert all(override in c for c in after if c[0] == "compose")
    pinned_up = ("up", "-d", "--no-build", "--pull", "never", "--force-recreate", "--wait")
    assert [c[-8:] if c[0] == "compose" and "up" in c else c[-1:] for c in after] == [
        ("stop",),
        (*pinned_up, "db"),
        ("stage",),
        ("replace",),
        (override, *pinned_up),
    ]
    assert ("image",) not in compose_steps(calls)  # rollback tags are kept
