import hashlib
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from .doctor import query_db

APPLIED_SQL = """
select coalesce(json_object_agg(version, checksum), '{}') from kilnbase.app_migrations;
"""
# Runs after the file in the same transaction; psql quotes the variables (`:'name'`).
RECORD_SQL = """
;
insert into kilnbase.app_migrations (version, checksum) values (:'kb_version', :'kb_checksum');
notify pgrst, 'reload schema';
"""
# Serialises concurrent `kilnbase migrate` runs; distinct from the auth runner's lock.
LOCK_SQL = "select pg_advisory_xact_lock(7340002);\n"
NAME = re.compile(r"[a-z0-9_]+")


def checksum(sql: str) -> str:
    # Same normalisation as the platform runner: a Windows checkout is not a modified file.
    return hashlib.sha256(sql.replace("\r\n", "\n").encode()).hexdigest()


def pending(files: dict[str, str], applied: dict[str, str]) -> list[str]:
    """Versions to apply, in order; raises if the database history disagrees with the files."""
    if missing := sorted(set(applied) - set(files)):
        raise ValueError(f"applied migrations are missing locally: {', '.join(missing)}")
    if changed := sorted(v for v in applied if applied[v] != checksum(files[v])):
        raise ValueError(
            f"applied migrations were modified: {', '.join(changed)}; add a new migration instead"
        )
    todo = sorted(set(files) - set(applied))
    if applied and todo and todo[0] < max(applied):
        raise ValueError(
            f"{todo[0]} sorts before the already-applied {max(applied)}; "
            "recreate it with `kilnbase migrate new`"
        )
    return todo


def new(directory: Path, name: str, now: datetime | None = None) -> int:
    if not NAME.fullmatch(name):
        print("migrate: name must be lowercase letters, digits and _", file=sys.stderr)
        return 2
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%d%H%M%S")
    path = directory / f"{stamp}_{name}.sql"
    directory.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        f.write(f"-- {name}\n")
    print(path)
    return 0


def run(env_file: Path, directory: Path) -> int:
    root = env_file.resolve().parent
    files = {p.stem: p.read_text(encoding="utf-8") for p in sorted(directory.glob("*.sql"))}
    try:
        todo = pending(files, query_db(root, APPLIED_SQL))
    except ValueError as e:
        print(f"migrate: {e}", file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"migrate: cannot read the database: {e}", file=sys.stderr)
        return 1
    for version in todo:
        sql = files[version]
        argv = ["docker", "compose", "exec", "-T", "db", "psql", "-U", "postgres", "-q"]
        argv += ["--single-transaction", "-v", "ON_ERROR_STOP=1"]
        argv += ["-v", f"kb_version={version}", "-v", f"kb_checksum={checksum(sql)}"]
        res = subprocess.run(  # noqa: S603 - fixed argv; the SQL is the user's own file
            argv,
            input=LOCK_SQL + sql + RECORD_SQL,
            text=True,
            encoding="utf-8",
            capture_output=True,
            cwd=root,
        )
        if res.returncode != 0:
            print(f"migrate: {version} failed and was rolled back:\n{res.stderr}", file=sys.stderr)
            return 1
        print(f"applied {version}")
    if not todo:
        print("migrate: database is up to date", file=sys.stderr)
    return 0
