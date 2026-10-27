import hashlib
import shutil
import subprocess
from pathlib import Path

DEPS_ROOT = Path("/deps")  # a volume, so a restart with the same requirements installs nothing


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
    for old in root.iterdir():
        if old.is_dir() and old.name not in (digest, ".cache"):
            shutil.rmtree(old, ignore_errors=True)
    return target
