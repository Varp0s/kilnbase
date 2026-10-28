import hashlib
import shutil
import subprocess
from pathlib import Path

DEPS_ROOT = Path("/deps")  # a volume, so a restart with the same requirements installs nothing
NPM = "/usr/local/lib/node_modules/npm/bin/npm-cli.js"


class DepsError(Exception):
    pass


def install(functions_dir: Path, root: Path = DEPS_ROOT) -> Path | None:
    """
    Installs functions/requirements.txt into root/<hash of the file> and removes older sets.
    Wheels only (`--no-build`): building an sdist runs the package's own code, and this happens
    in the runner, outside any jail.
    """
    requirements = functions_dir / "requirements.txt"
    if not requirements.is_file():
        return None
    digest = hashlib.sha256(requirements.read_bytes()).hexdigest()[:16]
    target = root / digest
    if not (target / ".complete").exists():
        shutil.rmtree(target, ignore_errors=True)
        res = subprocess.run(  # noqa: S603 - fixed argv; the file is the operator's own
            [
                "/usr/local/bin/uv", "pip", "install", "--no-build", "--quiet",
                "--python", "/usr/local/bin/python3",
                "--target", str(target),
                "-r", str(requirements),
            ],
            capture_output=True, text=True, check=False,
            env={"UV_CACHE_DIR": str(root / ".cache"), "PATH": "/usr/local/bin:/usr/bin:/bin"},
        )  # fmt: skip
        if res.returncode != 0:
            shutil.rmtree(target, ignore_errors=True)
            raise DepsError(f"installing functions/requirements.txt failed: {res.stderr[-2000:]}")
        (target / ".complete").touch()
    _prune(root, target)
    return target


def install_node(functions_dir: Path, root: Path = DEPS_ROOT) -> Path | None:
    """
    Installs functions/package.json's dependencies, exactly as package-lock.json pins them, into
    root/node-<hash of both files>/node_modules and removes older sets. `--ignore-scripts`: install
    scripts would run in the runner, outside any jail.
    """
    manifest, lock = functions_dir / "package.json", functions_dir / "package-lock.json"
    if not manifest.is_file():
        return None
    if not lock.is_file():
        raise DepsError("functions/package.json needs a package-lock.json; run `npm install` once")
    digest = hashlib.sha256(manifest.read_bytes() + b"\0" + lock.read_bytes()).hexdigest()[:16]
    target = root / f"node-{digest}"
    if not (target / ".complete").exists():
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True)
        shutil.copy(manifest, target)
        shutil.copy(lock, target)
        cache = root / ".npm"
        res = subprocess.run(  # noqa: S603 - fixed argv; the files are the operator's own
            [
                "/usr/local/bin/node", NPM, "ci", "--ignore-scripts", "--omit=dev",
                "--no-audit", "--no-fund", "--prefix", str(target),
            ],
            capture_output=True, text=True, check=False,
            env={
                "HOME": str(cache), "npm_config_cache": str(cache),
                "npm_config_update_notifier": "false", "PATH": "/usr/local/bin:/usr/bin:/bin",
            },
        )  # fmt: skip
        if res.returncode != 0:
            shutil.rmtree(target, ignore_errors=True)
            raise DepsError(f"installing functions/package.json failed: {res.stderr[-2000:]}")
        (target / ".complete").touch()
    _prune(root, target)
    return target


def _prune(root: Path, keep: Path) -> None:
    """Removes the other sets of the same kind; caches (dot directories) stay."""
    node = keep.name.startswith("node-")
    for old in root.iterdir():
        if (
            old.is_dir()
            and old != keep
            and not old.name.startswith(".")
            and old.name.startswith("node-") == node
        ):
            shutil.rmtree(old, ignore_errors=True)
