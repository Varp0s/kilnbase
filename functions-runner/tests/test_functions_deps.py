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


@pytest.fixture
def npm(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        target = deps.Path(argv[argv.index("--prefix") + 1])
        if "fail" in (target / "package.json").read_text():
            return subprocess.CompletedProcess(argv, 1, "", "404 Not Found")
        (target / "node_modules").mkdir()
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(deps.subprocess, "run", fake_run)
    return calls


def test_npm_packages_need_a_lock_and_never_run_scripts(tmp_path, npm):
    root = tmp_path / "deps"
    assert deps.install_node(tmp_path, root) is None and npm == []
    (tmp_path / "package.json").write_text('{"dependencies": {"ms": "2.1.3"}}')
    with pytest.raises(deps.DepsError, match="package-lock.json"):
        deps.install_node(tmp_path, root)

    (tmp_path / "package-lock.json").write_text("{}")
    (root / "4f00").mkdir(parents=True)  # a Python set stays
    (root / "node-old").mkdir()
    target = deps.install_node(tmp_path, root)
    assert target.name.startswith("node-") and (target / ".complete").exists()
    assert ["ci", "--ignore-scripts"] == npm[0][2:4]
    assert sorted(p.name for p in root.iterdir()) == ["4f00", target.name]
    assert deps.install_node(tmp_path, root) == target and len(npm) == 1

    (tmp_path / "package.json").write_text('{"dependencies": {"fail": "1"}}')
    with pytest.raises(deps.DepsError, match="404"):
        deps.install_node(tmp_path, root)
    assert sorted(p.name for p in root.iterdir()) == ["4f00", target.name]
