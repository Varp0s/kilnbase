import json
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from .backup import Stack, backup, compose_args, docker, read_backup, replace_data, stage

HEALTH_TIMEOUT = 60
OVERRIDE = "kilnbase-rollback.json"
ERRORS = (OSError, RuntimeError, subprocess.CalledProcessError, ValueError, tarfile.TarError)


def why(e: Exception) -> str:
    err = getattr(e, "stderr", None) or str(e)
    return (err.decode(errors="replace") if isinstance(err, bytes) else err).strip()


def core_healthy(compose: list[str]) -> bool:
    # core has no compose healthcheck (distroless), so `up --wait` only means "running".
    port = docker(*compose, "port", "core", "8000", text=True).stdout.strip()
    url = f"http://127.0.0.1:{port.rsplit(':', 1)[1]}/health"
    deadline = time.monotonic() + HEALTH_TIMEOUT
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as res:  # noqa: S310 - fixed local URL
                if res.status == 200:
                    return True
        except OSError:
            pass
        time.sleep(1)
    return False


def run(env_file: Path) -> int:
    """
    Builds/pulls the new version while the old one serves, stops core (the only ingress) and backs
    everything up, then starts the new version. If that fails, the data is restored from the
    backup and the stack is started on the previous images again.
    """
    root = env_file.resolve().parent
    stamp = time.strftime("%Y%m%d-%H%M%S")
    try:
        stack = Stack(root)
        containers = stack.containers()
        # Every file any service was started with (overrides included), in order; a previous
        # rollback's pins are dropped, since this run is meant to move past them.
        seen = dict.fromkeys(f for _, _, paths in containers for f in paths)
        files = [f for f in seen if Path(f).name != OVERRIDE]
        compose = compose_args(stack.project, files)
        # Pinned by image ID before pulling/building: those move mutable tags such as `:dev`, and
        # with the containerd image store the replaced image is gone once nothing tags it.
        pins = {}
        for service, image, _ in containers:
            pins[service] = f"kilnbase-rollback/{service}:{stamp}"
            docker("tag", image, pins[service])
        print("Pulling and building the new version; the stack keeps serving meanwhile...")
        docker(*compose, "pull", "--ignore-buildable")
        docker(*compose, "build")
        docker(*compose, "stop", "core")
    except ERRORS as e:
        print(f"upgrade: nothing was changed: {why(e)}", file=sys.stderr)
        return 1

    archive = root / f"kilnbase-pre-upgrade-{stamp}.tar"
    if backup(env_file, archive) != 0:
        docker(*compose, "start", "core")
        print("upgrade: the backup failed, so nothing was changed", file=sys.stderr)
        return 1

    try:
        docker(*compose, "up", "-d", "--wait")
        if not core_healthy(compose):
            raise RuntimeError("core did not answer /health")
    except ERRORS as e:
        print(f"upgrade failed: {why(e)}\nRolling back to {archive} ...", file=sys.stderr)
        return rollback(root, stack.project, files, archive, pins)

    (root / OVERRIDE).unlink(missing_ok=True)
    try:
        docker("image", "rm", *pins.values())
    except subprocess.CalledProcessError:
        pass  # a tag still naming a running container's image stays; it is harmless
    print(f"Upgraded. The pre-upgrade backup {archive} is kept; delete it once you are sure.")
    return 0


def rollback(
    root: Path, project: str, files: list[str], archive: Path, pins: dict[str, str]
) -> int:
    override = root / OVERRIDE
    override.write_text(json.dumps({"services": {s: {"image": t} for s, t in pins.items()}}))
    pinned = compose_args(project, [*files, str(override)])
    up = [*pinned, "up", "-d", "--no-build", "--pull", "never", "--force-recreate", "--wait"]
    try:
        docker(*pinned, "stop")
        docker(*up, "db")
        stack = Stack(root)
        manifest, tar = read_backup(archive)
        with tar, tempfile.TemporaryDirectory() as tmp:
            replace_data(stack, stage(stack, tar, Path(tmp)))
        docker(*up)
    except ERRORS as e:
        print(
            f"rollback failed: {why(e)}\nThe backup {archive} is intact; restore it with the "
            "previous version running.",
            file=sys.stderr,
        )
        return 1
    flags = " ".join(pinned[1:])
    print(
        f"Rolled back to the data of {manifest['created_at']} and the previous images "
        f"(kilnbase-rollback/*:{archive.stem.removeprefix('kilnbase-pre-upgrade-')}).\n"
        f"Until the next successful `kilnbase upgrade`, start the stack with:\n"
        f"  docker compose {flags} up -d",
        file=sys.stderr,
    )
    return 1
