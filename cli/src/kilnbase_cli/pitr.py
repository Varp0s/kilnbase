"""Point-in-time recovery with pgBackRest (in the db image; repository on the db-backups volume)."""

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from .backup import ADVANCE_SEQUENCES_SQL, EVENT_SEQUENCES_SQL, Stack, docker
from .doctor import query_db

STANZA = "kilnbase"
ARCHIVE_COMMAND = f"pgbackrest --stanza={STANZA} archive-push %p"
ERRORS = (OSError, RuntimeError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError)
# Database clock and timeline, read before anything is stopped.
STATE_SQL = """
select json_build_object('now', clock_timestamp(),
                         'timeline', (pg_control_checkpoint()).timeline_id)
"""
RECOVERING_SQL = "select json_build_object('recovering', pg_is_in_recovery())"


def why(e: Exception) -> str:
    # pgBackRest reports its errors on stdout.
    parts = [getattr(e, "stderr", None), getattr(e, "stdout", None)]
    text = " ".join(p.decode(errors="replace") if isinstance(p, bytes) else p for p in parts if p)
    return (text or str(e)).strip()


def pgbackrest_time(t: datetime) -> str:
    """pgBackRest rejects ISO 8601's "T"; it wants `YYYY-MM-DD HH:MM:SS.ffffff+00`."""
    return t.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f+00")


def pgbackrest(stack: Stack, *args: str) -> str:
    # As postgres: files written as root would make every later archive-push fail.
    out = docker("exec", "-u", "postgres", stack.db, "pgbackrest", f"--stanza={STANZA}", *args)
    return out.stdout.decode()


def info(stack: Stack) -> dict:
    data = json.loads(pgbackrest(stack, "info", "--output=json"))
    return data[0] if data else {}


def wait_until_ready(root: Path, timeout: int = 120) -> None:
    """Until the server accepts writes: during recovery it already answers, read-only."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if not query_db(root, RECOVERING_SQL)["recovering"]:
                return
        except ERRORS:
            pass
        time.sleep(1)
    raise RuntimeError(f"the database did not finish recovering within {timeout}s")


def enable(env_file: Path) -> int:
    root = env_file.resolve().parent
    try:
        stack = Stack(root)
        pgbackrest(stack, "stanza-create")
        # In postgresql.auto.conf on the data volume, so the setting survives image upgrades; a
        # broken repository then fails archiving loudly instead of silently dropping WAL.
        stack.psql("-c", "alter system set archive_mode = on")
        stack.psql("-c", f"alter system set archive_command = '{ARCHIVE_COMMAND}'")
        print("Restarting the database to turn on WAL archiving...")
        docker("restart", stack.db)
        wait_until_ready(root)
        stack = Stack(root)
        pgbackrest(stack, "check")
        pgbackrest(stack, "--type=full", "backup")
    except ERRORS as e:
        print(f"pitr enable failed: {why(e)}", file=sys.stderr)
        return 1
    print("Point-in-time recovery is on, with a full backup. Run `kilnbase pitr backup` daily.")
    return 0


def backup(env_file: Path) -> int:
    try:
        # Incremental, or full when the repository has none (pgBackRest decides).
        pgbackrest(Stack(env_file.resolve().parent), "backup")
    except ERRORS as e:
        print(f"pitr backup failed: {why(e)}", file=sys.stderr)
        return 1
    print("Backup done.")
    return 0


def window(details: dict) -> tuple[datetime, datetime] | None:
    backups = details.get("backup") or []
    if not backups:
        return None
    start = datetime.fromtimestamp(backups[0]["timestamp"]["stop"], UTC)
    end = datetime.fromtimestamp(backups[-1]["timestamp"]["stop"], UTC)
    return start, end


def list_backups(env_file: Path) -> int:
    try:
        details = info(Stack(env_file.resolve().parent))
    except ERRORS as e:
        print(f"pitr list failed: {why(e)}", file=sys.stderr)
        return 1
    for b in details.get("backup") or []:
        stop = datetime.fromtimestamp(b["timestamp"]["stop"], UTC).isoformat(timespec="seconds")
        print(f"{b['type']:5} {b['label']}  finished {stop}")
    if span := window(details):
        print(f"Restorable from {span[0].isoformat(timespec='seconds')} until now.")
    else:
        print("No backups yet; run `kilnbase pitr enable`.")
    return 0


def parse_target(text: str) -> datetime:
    target = datetime.fromisoformat(text)
    if target.tzinfo is None:
        raise ValueError("give the time with its UTC offset, e.g. 2026-10-27T12:00:00+00:00")
    return target


def check_target(target: datetime, earliest: datetime | None, now: datetime) -> str | None:
    """Why `target` cannot be restored to, or None. Checked before anything is stopped."""
    if earliest is None:
        return "there are no backups; run `kilnbase pitr enable` first"
    if target <= earliest:
        return f"the earliest restorable time is {earliest.isoformat(timespec='seconds')}"
    if target >= now:
        return "the time is not in the past"
    return None


def confirm(where: str) -> bool:
    print(
        f"This rewinds ALL database data to {where}; anything written later is set aside (the "
        "printed undo command brings it back).\nServices are stopped while it runs."
    )
    if not sys.stdin.isatty():
        return False
    try:
        return input("Type 'restore' to continue: ").strip() == "restore"
    except EOFError:
        return False


def restore(env_file: Path, to: str | None, timeline: int | None, yes: bool) -> int:
    """
    To a time (`to`, optionally on an earlier `timeline`), or with only `timeline` to the end of
    that timeline: how a restore is undone, since each restore starts a new timeline.
    """
    root = env_file.resolve().parent
    if to is None and timeline is None:
        print("pitr restore: give --to, --timeline or both", file=sys.stderr)
        return 1
    try:
        target = parse_target(to) if to is not None else None
        stack = Stack(root)
        try:
            state = query_db(root, STATE_SQL)
            seen = query_db(root, EVENT_SEQUENCES_SQL)
        except ERRORS:
            if target is not None:
                raise RuntimeError("the database is not running") from None
            state = seen = None  # undoing a restore that left the database down
        if target is not None:
            span = window(info(stack))
            if problem := check_target(
                target, span and span[0], datetime.fromisoformat(state["now"])
            ):
                print(f"pitr restore: refusing: {problem}", file=sys.stderr)
                return 1
        if state is not None:
            # A commit after the target lets recovery see that the target was reached (an idle
            # database would otherwise end recovery "before the target" and refuse to start), and
            # the WAL switch plus check gets everything up to now into the repository.
            stack.psql("-c", "select txid_current()")
            stack.psql("-c", "select pg_switch_wal()")
            pgbackrest(stack, "check")
    except ERRORS as e:
        print(f"pitr restore: nothing was changed: {why(e)}", file=sys.stderr)
        return 1
    where = target.isoformat() if target else f"the end of timeline {timeline}"
    if not yes and not confirm(where):
        print("pitr restore: cancelled", file=sys.stderr)
        return 1

    undo = f"kilnbase pitr restore --timeline {state['timeline']} --yes" if state else None
    stopped = stack.services()
    # Without a time, recovery replays the whole timeline and then promotes by itself.
    args = ["--delta"]
    if target is not None:
        args += ["--type=time", f"--target={pgbackrest_time(target)}", "--target-action=promote"]
    if timeline is not None:
        args.append(f"--target-timeline={timeline}")
    try:
        if stopped:
            docker("stop", *stopped)
        docker("stop", stack.db)
        docker(
            "run", "--rm", "-u", "postgres",
            "-v", f"{stack.project}_db-data:/var/lib/postgresql",
            "-v", f"{stack.project}_db-backups:/var/lib/pgbackrest",
            stack.image, "pgbackrest", f"--stanza={STANZA}", *args, "restore",
        )  # fmt: skip
        docker("start", stack.db)
        wait_until_ready(root)
        if seen:
            query_db(root, ADVANCE_SEQUENCES_SQL, seen=json.dumps(seen))
    except ERRORS as e:
        # Services stay stopped: they must not run against a half-restored database.
        back = f" To go back to where you were: {undo}" if undo else ""
        print(
            f"pitr restore failed: {why(e)}\nThe other services were left stopped.{back}",
            file=sys.stderr,
        )
        return 1
    if stopped:
        docker("start", *stopped)
    print(f"Restored to {where}." + (f" To undo: {undo}" if undo else ""))
    print("Sessions and passwords are as they were then; after an incident, revoke sessions.")
    return 0
