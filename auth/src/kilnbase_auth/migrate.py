import hashlib
from pathlib import Path

import asyncpg

# Arbitrary constant; serialises concurrent runners (e.g. two auth replicas booting together).
LOCK_ID = 7_340_001


class MigrationError(RuntimeError):
    pass


def load(migrations_dir: Path) -> list[tuple[str, str]]:
    """Return (version, sql) pairs in filename order."""
    files = sorted(migrations_dir.glob("*.sql"))
    if not files:
        raise MigrationError(f"no migrations found in {migrations_dir}")
    return [(f.stem, f.read_text(encoding="utf-8")) for f in files]


def checksum(sql: str) -> str:
    # Line endings are normalised so a Windows checkout does not look like a tampered file.
    return hashlib.sha256(sql.replace("\r\n", "\n").encode()).hexdigest()


def verify(applied: dict[str, str | None], migrations: list[tuple[str, str]]) -> None:
    """Refuse to run against a database whose history disagrees with the shipped migrations."""
    known = dict(migrations)
    unknown = sorted(set(applied) - set(known))
    if unknown:
        raise MigrationError(
            f"database has migrations this build does not know ({', '.join(unknown)}); "
            "it was created by a newer version — upgrade instead of downgrading"
        )
    changed = [v for v, digest in applied.items() if digest and digest != checksum(known[v])]
    if changed:
        raise MigrationError(
            f"already-applied migrations were modified ({', '.join(sorted(changed))}); "
            "never edit an applied migration — add a new one"
        )


async def run(
    database_url: str, migrations: list[tuple[str, str]], authenticator_password: str
) -> list[str]:
    """Apply pending migrations, each in its own transaction."""
    conn = await asyncpg.connect(database_url)
    try:
        await conn.execute("select pg_advisory_lock($1)", LOCK_ID)
        await conn.execute(
            "create schema if not exists kilnbase;"
            "create table if not exists kilnbase.schema_migrations ("
            " version text primary key,"
            " applied_at timestamptz not null default now());"
            "alter table kilnbase.schema_migrations add column if not exists checksum text"
        )
        rows = await conn.fetch("select version, checksum from kilnbase.schema_migrations")
        applied = {r["version"]: r["checksum"] for r in rows}
        verify(applied, migrations)

        newly_applied = []
        for version, sql in migrations:
            if version in applied:
                if applied[version] is None:
                    # Rows from before checksums existed: record what is applied now.
                    await conn.execute(
                        "update kilnbase.schema_migrations set checksum = $2 where version = $1",
                        version,
                        checksum(sql),
                    )
                continue
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "insert into kilnbase.schema_migrations (version, checksum) values ($1, $2)",
                    version,
                    checksum(sql),
                )
            newly_applied.append(version)

        # ALTER ROLE takes no bind parameters; format(%L) quotes the password server-side.
        stmt = await conn.fetchval(
            "select format('alter role authenticator with password %L', $1::text)",
            authenticator_password,
        )
        await conn.execute(stmt)
        return newly_applied
    finally:
        await conn.close()
