from pathlib import Path

import asyncpg

# Arbitrary constant; serialises concurrent runners (e.g. two auth replicas booting together).
LOCK_ID = 7_340_001


def load(migrations_dir: Path) -> list[tuple[str, str]]:
    """Return (version, sql) pairs in filename order."""
    files = sorted(migrations_dir.glob("*.sql"))
    if not files:
        raise RuntimeError(f"no migrations found in {migrations_dir}")
    return [(f.stem, f.read_text(encoding="utf-8")) for f in files]


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
            " applied_at timestamptz not null default now())"
        )
        rows = await conn.fetch("select version from kilnbase.schema_migrations")
        applied = {r["version"] for r in rows}

        newly_applied = []
        for version, sql in migrations:
            if version in applied:
                continue
            async with conn.transaction():
                await conn.execute(sql)
                await conn.execute(
                    "insert into kilnbase.schema_migrations (version) values ($1)", version
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
