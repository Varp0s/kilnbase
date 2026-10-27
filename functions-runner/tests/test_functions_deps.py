import subprocess

import pytest
from kilnbase_functions import deps


@pytest.fixture
def runs(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        target = argv[argv.index("--target") + 1]
        if "fail" in open(argv[argv.index("-r") + 1]).read():
            return subprocess.CompletedProcess(argv, 1, "", "no wheel for pkg")
        deps.Path(target).mkdir(parents=True)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(deps.subprocess, "run", fake_run)
    return calls


def test_no_requirements_means_no_install(tmp_path, runs):
    assert deps.install(tmp_path, tmp_path / "deps") is None and runs == []


def test_wheels_only_cached_and_old_sets_removed(tmp_path, runs):
    root = tmp_path / "deps"
    (root / "stale").mkdir(parents=True)
    (tmp_path / "requirements.txt").write_text("six==1.17.0\n")
    target = deps.install(tmp_path, root)
    assert (target / ".complete").exists() and "--no-build" in runs[0]
    assert not (root / "stale").exists()
    assert deps.install(tmp_path, root) == target and len(runs) == 1  # unchanged file: no work


def test_failed_install_leaves_nothing_and_stops_boot(tmp_path, runs):
    (tmp_path / "requirements.txt").write_text("fail\n")
    root = tmp_path / "deps"
    root.mkdir()
    with pytest.raises(deps.DepsError, match="no wheel"):
        deps.install(tmp_path, root)
    assert list(root.iterdir()) == []
