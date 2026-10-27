import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

from .doctor import query_db

FORMAT = 1
MEMBERS = ("manifest.json", "db.dump", "storage.tar")
# shortcut: only the local storage volume is archived; add the S3 backend once storage can use one.
STORAGE_DIRS = ("objects", "uploads")
MIGRATIONS_SQL = """
select coalesce(json_object_agg(version, checksum order by version), '{}')
  from kilnbase.schema_migrations;
"""
DUMP_IN_DB = "/tmp/kilnbase-backup.dump"  # noqa: S108 - inside the db container
RESTORE_DB = "kilnbase_restore"


def make_manifest(migrations: dict[str, str], cli_version: str, now: datetime) -> dict:
    return {
        "format": FORMAT,
        "kilnbase_version": cli_version,
        "created_at": now.isoformat(timespec="seconds"),
        "migrations": migrations,
    }


def check_manifest(manifest: dict, current: dict[str, str]) -> str | None:
    """Why this backup cannot be restored onto a database with `current` migrations, or None."""
    if manifest.get("format") != FORMAT:
        return f"unknown backup format {manifest.get('format')!r}"
    saved = manifest.get("migrations")
    if not isinstance(saved, dict):
        return "backup has no migration list"
    problems = []
    if missing := sorted(set(current) - set(saved)):
        problems.append(f"backup predates migrations {', '.join(missing)}")
    if extra := sorted(set(saved) - set(current)):
        problems.append(f"backup has migrations this version lacks: {', '.join(extra)}")
    if changed := sorted(v for v in set(saved) & set(current) if saved[v] != current[v]):
        problems.append(f"migrations differ: {', '.join(changed)}")
    if problems:
        origin = manifest.get("kilnbase_version")
        return "; ".join(problems) + f" (backup is from kilnbase {origin})"
    return None


def docker(*args: str, **kwargs) -> subprocess.CompletedProcess:
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    kwargs.setdefault("stdout", subprocess.PIPE)
    argv = ["docker", *args]
    return subprocess.run(argv, check=True, stderr=subprocess.PIPE, **kwargs)  # noqa: S603


def compose_args(project: str, files: list[str]) -> list[str]:
    return ["compose", "-p", project, *(a for f in files for a in ("-f", f))]


class Stack:
    """The running compose project: its db container, storage volume and a helper image."""

    def __init__(self, root: Path):
        self.root = root
        self.db = docker("compose", "ps", "-q", "db", cwd=root, text=True).stdout.strip()
        if not self.db:
            raise RuntimeError("the db service is not running; start it: docker compose up -d")
        info = json.loads(docker("inspect", self.db, text=True).stdout)[0]
        self.project = info["Config"]["Labels"]["com.docker.compose.project"]
        self.volume = f"{self.project}_storage-data"
        # The postgres image has GNU tar; core is distroless.
        self.image = info["Config"]["Image"]

    def psql(self, *args: str, db: str = "template1") -> None:
        docker("exec", self.db, "psql", "-U", "postgres", "-d", db, "-v", "ON_ERROR_STOP=1", *args)

    def storage(self, script: str, read_only: bool, **kwargs) -> subprocess.CompletedProcess:
        mount = f"{self.volume}:/data" + (":ro" if read_only else "")
        return docker("run", "--rm", "-i", "-v", mount, self.image, "sh", "-ec", script, **kwargs)

    def containers(self) -> list[tuple[str, str, list[str]]]:
        """(service, image ID, compose files) of each running container; IDs, since tags move."""
        labels = "{{index .Config.Labels %s}}"
        service = labels % '"com.docker.compose.service"'
        files = labels % '"com.docker.compose.project.config_files"'
        label = f"label=com.docker.compose.project={self.project}"
        ids = docker("ps", "-q", "--filter", label, text=True).stdout.split()
        out = docker("inspect", "-f", f"{service}|{{{{.Image}}}}|{files}", *ids, text=True).stdout
        rows = (line.split("|") for line in out.splitlines() if line.strip())
        return [(svc, image, paths.split(",")) for svc, image, paths in rows]

    def services(self) -> list[str]:
        """Running containers of the project other than the database."""
        out = docker(
            "ps",
            "-q",
            "--filter",
            f"label=com.docker.compose.project={self.project}",
            text=True,
        )
        return [c for c in out.stdout.split() if not self.db.startswith(c)]


def backup(env_file: Path, output: Path | None) -> int:
    root = env_file.resolve().parent
    output = output or Path(f"kilnbase-backup-{time.strftime('%Y%m%d-%H%M%S')}.tar")
    try:
        stack = Stack(root)
        manifest = make_manifest(
            query_db(root, MIGRATIONS_SQL), version("kilnbase"), datetime.now(UTC)
        )
        with tempfile.TemporaryDirectory() as tmp:
            dump, objects = Path(tmp, "db.dump"), Path(tmp, "storage.tar")
            docker("exec", stack.db, "pg_dump", "-U", "postgres", "-Fc", "-f", DUMP_IN_DB)
            docker("cp", f"{stack.db}:{DUMP_IN_DB}", str(dump))
            docker("exec", stack.db, "rm", "-f", DUMP_IN_DB)
            with objects.open("wb") as f:
                dirs = " ".join(STORAGE_DIRS)
                stack.storage(f"tar --numeric-owner -C /data -cf - {dirs}", True, stdout=f)
            # Written under a temp name, so a failed run never leaves a truncated backup behind.
            partial = output.with_name(output.name + ".partial")
            with tarfile.open(partial, "w") as tar:
                data = json.dumps(manifest, indent=2).encode()
                info = tarfile.TarInfo("manifest.json")
                info.size, info.mtime = len(data), int(time.time())
                tar.addfile(info, io.BytesIO(data))
                tar.add(dump, "db.dump")
                tar.add(objects, "storage.tar")
            os.chmod(partial, 0o600)  # holds password hashes and every user's data
            os.replace(partial, output)
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"backup failed: {getattr(e, 'stderr', None) or e}", file=sys.stderr)
        return 1
    print(f"Wrote {output} ({len(manifest['migrations'])} migrations). It does not include .env.")
    return 0


def read_backup(path: Path) -> tuple[dict, tarfile.TarFile]:
    tar = tarfile.open(path)  # noqa: SIM115 - the caller closes it
    names = set(tar.getnames())
    if missing := [m for m in MEMBERS if m not in names]:
        tar.close()
        raise ValueError(f"{path} is not a kilnbase backup (missing {', '.join(missing)})")
    return json.load(tar.extractfile("manifest.json")), tar


def confirm(manifest: dict) -> bool:
    print(
        f"This replaces ALL data (database and stored files) with the backup from "
        f"{manifest['created_at']}.\nServices are stopped while it runs."
    )
    if not sys.stdin.isatty():
        return False
    try:
        return input("Type 'restore' to continue: ").strip() == "restore"
    except EOFError:
        return False


def restore(env_file: Path, path: Path, yes: bool) -> int:
    root = env_file.resolve().parent
    try:
        manifest, tar = read_backup(path)
    except (OSError, ValueError, tarfile.TarError, json.JSONDecodeError) as e:
        print(f"restore: {e}", file=sys.stderr)
        return 1
    with tar, tempfile.TemporaryDirectory() as tmp:
        try:
            stack = Stack(root)
            if problem := check_manifest(manifest, query_db(root, MIGRATIONS_SQL)):
                print(f"restore: refusing: {problem}", file=sys.stderr)
                return 1
            if not yes and not confirm(manifest):
                print("restore: cancelled", file=sys.stderr)
                return 1
            objects = stage(stack, tar, Path(tmp))
            stopped = stack.services()
            if stopped:
                docker("stop", *stopped)
            try:
                replace_data(stack, objects)
            finally:
                if stopped:
                    docker("start", *stopped)
        except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print(f"restore failed: {getattr(e, 'stderr', None) or e}", file=sys.stderr)
            return 1
    print(f"Restored the backup from {manifest['created_at']}.")
    return 0


def stage(stack: Stack, tar: tarfile.TarFile, tmp: Path) -> Path:
    """Copies the dump into the db container and checks it; returns the storage archive."""
    # Members are read by name only, never extracted by their own paths.
    dump, objects = tmp / "db.dump", tmp / "storage.tar"
    for name, target in (("db.dump", dump), ("storage.tar", objects)):
        with target.open("wb") as f:
            shutil.copyfileobj(tar.extractfile(name), f)
    docker("cp", str(dump), f"{stack.db}:{DUMP_IN_DB}")
    docker("exec", stack.db, "pg_restore", "--list", DUMP_IN_DB)  # readable before we stop
    return objects


def replace_data(stack: Stack, objects: Path) -> None:
    """Swaps in the staged database and stored files; the other services must be stopped."""
    restore_db(stack)
    with objects.open("rb") as f:
        stack.storage(
            # Unpacked aside first, so a broken archive leaves the current files alone.
            f"cd /data && rm -rf .restore && mkdir .restore && tar -C .restore -xf -"
            f" && rm -rf {' '.join(STORAGE_DIRS)} && mv .restore/* . && rmdir .restore",
            read_only=False,
            stdin=f,
        )


def restore_db(stack: Stack) -> None:
    """Restores into a scratch database and swaps it in only once that fully succeeded."""
    stack.psql("-c", f"drop database if exists {RESTORE_DB}")
    stack.psql("-c", f"create database {RESTORE_DB} template template0")
    try:
        docker(
            "exec", stack.db, "pg_restore", "-U", "postgres", "--exit-on-error",
            "-d", RESTORE_DB, DUMP_IN_DB,
        )  # fmt: skip
    except subprocess.CalledProcessError:
        stack.psql("-c", f"drop database {RESTORE_DB}")
        raise
    finally:
        docker("exec", stack.db, "rm", "-f", DUMP_IN_DB)
    stack.psql("-c", "drop database postgres with (force)")
    stack.psql("-c", f"alter database {RESTORE_DB} rename to postgres")
