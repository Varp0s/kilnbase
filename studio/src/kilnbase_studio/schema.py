"""Database pages: schema objects, advisors, query performance, migrations.

Every query is static and reads the catalog; changes to the schema go through the SQL editor, so
the statement is always shown to the admin before it runs.
"""

import json

import asyncpg
from fastapi import APIRouter, Depends, Request
from kilnbase_cli.doctor import AUDIT_SQL, check_db

from .common import error, rows

TABLES_SQL = """
select c.relname as name, c.reltuples::bigint as estimated_rows,
       pg_total_relation_size(c.oid) as bytes, c.relrowsecurity as rls,
       exists (select 1 from pg_trigger t
                where t.tgrelid = c.oid and t.tgname = 'kilnbase_realtime') as realtime,
       exists (select 1 from pg_index i where i.indrelid = c.oid and i.indisprimary) as has_key,
       obj_description(c.oid, 'pg_class') as comment
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind in ('r', 'p') order by c.relname
"""
FUNCTIONS_SQL = """
select p.proname as name, pg_get_function_identity_arguments(p.oid) as args,
       pg_get_function_result(p.oid) as returns, l.lanname as language,
       p.prosecdef as security_definer, p.prokind = 'p' as procedure,
       pg_get_functiondef(p.oid) as definition
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  join pg_language l on l.oid = p.prolang
 where n.nspname = 'public' and p.prokind in ('f', 'p') order by p.proname, 2
"""
TRIGGERS_SQL = """
select t.tgname as name, c.relname as table, t.tgenabled <> 'D' as enabled,
       pg_get_triggerdef(t.oid) as definition
  from pg_trigger t join pg_class c on c.oid = t.tgrelid
  join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and not t.tgisinternal order by c.relname, t.tgname
"""
INDEXES_SQL = """
select ic.relname as name, c.relname as table, i.indisunique as unique, i.indisprimary as primary,
       pg_relation_size(i.indexrelid) as bytes, coalesce(s.idx_scan, 0) as scans,
       pg_get_indexdef(i.indexrelid) as definition
  from pg_index i join pg_class c on c.oid = i.indrelid join pg_class ic on ic.oid = i.indexrelid
  join pg_namespace n on n.oid = c.relnamespace
  left join pg_stat_user_indexes s on s.indexrelid = i.indexrelid
 where n.nspname = 'public' order by c.relname, ic.relname
"""
ENUMS_SQL = """
select t.typname as name, array_agg(e.enumlabel order by e.enumsortorder) as values
  from pg_type t join pg_enum e on e.enumtypid = t.oid join pg_namespace n on n.oid = t.typnamespace
 where n.nspname = 'public' group by t.typname order by t.typname
"""
VIEWS_SQL = """
select c.relname as name, c.relkind = 'm' as materialized,
       coalesce(c.reloptions && array['security_invoker=true', 'security_invoker=on'], false)
           as security_invoker,
       pg_get_viewdef(c.oid, true) as definition
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind in ('v', 'm') order by c.relname
"""
ROLES_SQL = """
select r.rolname as name, r.rolsuper as superuser, r.rolcanlogin as login,
       r.rolbypassrls as bypass_rls, r.rolconnlimit as connection_limit,
       array(select b.rolname from pg_auth_members m join pg_roles b on b.oid = m.roleid
             where m.member = r.oid order by b.rolname) as member_of
  from pg_roles r where r.rolname not like 'pg\\_%' order by r.rolname
"""
FOREIGN_KEYS_SQL = """
select con.conname as name, c.relname as table, f.relname as references,
       pg_get_constraintdef(con.oid) as definition
  from pg_constraint con join pg_class c on c.oid = con.conrelid
  join pg_class f on f.oid = con.confrelid join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and con.contype = 'f' order by c.relname, con.conname
"""
SCHEMA_SQL = {
    "tables": TABLES_SQL,
    "functions": FUNCTIONS_SQL,
    "triggers": TRIGGERS_SQL,
    "indexes": INDEXES_SQL,
    "enums": ENUMS_SQL,
    "views": VIEWS_SQL,
    "roles": ROLES_SQL,
    "foreign_keys": FOREIGN_KEYS_SQL,
}

# Performance findings; the security ones are `kilnbase doctor`'s (AUDIT_SQL).
PERFORMANCE_AUDIT_SQL = """
select kind, name from (
    -- shortcut: an index covers a foreign key when it holds its columns and starts with the
    -- first one; compare column order instead if this ever reports a false positive.
    select 'unindexed_fk' as kind, con.conname || ' on ' || c.relname as name
      from pg_constraint con join pg_class c on c.oid = con.conrelid
      join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and con.contype = 'f'
       and not exists (select 1 from pg_index i where i.indrelid = con.conrelid
                        and i.indkey::int2[] @> con.conkey::int2[]
                        and (i.indkey::int2[])[0] = con.conkey[1])
    union all
    select 'unused_index', ic.relname || ' on ' || c.relname
      from pg_stat_user_indexes s join pg_index i on i.indexrelid = s.indexrelid
      join pg_class ic on ic.oid = s.indexrelid join pg_class c on c.oid = s.relid
     where s.schemaname = 'public' and s.idx_scan = 0 and not i.indisunique and not i.indisprimary
       and pg_relation_size(s.indexrelid) > 8192 * 16
    union all
    select 'no_primary_key', c.relname
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind in ('r', 'p')
       and not exists (select 1 from pg_index i where i.indrelid = c.oid and i.indisprimary)
    union all
    select 'extension_in_public', e.extname
      from pg_extension e join pg_namespace n on n.oid = e.extnamespace
     where n.nspname = 'public' and e.extname <> 'plpgsql'
    union all
    select 'bloated_table', c.relname
      from pg_stat_user_tables s join pg_class c on c.oid = s.relid
     where s.schemaname = 'public' and s.n_dead_tup > 10000 and s.n_dead_tup > s.n_live_tup / 5
) findings order by kind, name
"""
PERFORMANCE_MESSAGES = {
    "unindexed_fk": (
        "warn",
        "foreign key ",
        " has no index: joins and cascading deletes scan the table",
    ),
    "unused_index": ("info", "index ", " has never been used since statistics were reset"),
    "no_primary_key": (
        "warn",
        "table ",
        " has no primary key: realtime and the table editor need one",
    ),
    "extension_in_public": (
        "info",
        "extension ",
        " is installed in public; move it to the extensions schema",
    ),
    "bloated_table": ("warn", "table ", " holds many dead rows; check autovacuum"),
}

ACTIVITY_SQL = """
select pid, usename as role, application_name as application, state, wait_event_type as waiting,
       query_start, extract(epoch from clock_timestamp() - query_start) * 1000 as ms,
       left(query, 1000) as query
  from pg_stat_activity
 where datname = current_database() and pid <> pg_backend_pid() and backend_type = 'client backend'
 order by query_start nulls last
"""
STATEMENTS_ENABLED_SQL = (
    "select exists (select from pg_extension where extname = 'pg_stat_statements')"
)
STATEMENTS_SQL = """
select s.calls, round(s.total_exec_time)::bigint as total_ms, round(s.mean_exec_time::numeric, 2)
           as mean_ms, round(s.max_exec_time)::bigint as max_ms, s.rows, r.rolname as role,
       left(s.query, 1000) as query
  from pg_stat_statements s join pg_roles r on r.oid = s.userid
 where s.dbid = (select oid from pg_database where datname = current_database())
 order by s.total_exec_time desc limit 50
"""
TABLE_STATS_SQL = """
select relname as name, n_live_tup as live_rows, n_dead_tup as dead_rows, seq_scan, idx_scan,
       pg_total_relation_size(relid) as bytes, last_autovacuum, last_autoanalyze
  from pg_stat_user_tables where schemaname = 'public' order by pg_total_relation_size(relid) desc
"""
MIGRATIONS_SQL = {
    "platform": "select version, checksum from kilnbase.schema_migrations order by version",
    "app": "select version, checksum, applied_at from kilnbase.app_migrations order by version",
}
PID_ACTIONS = {
    "cancel": "select pg_cancel_backend($1)",
    "terminate": "select pg_terminate_backend($1)",
}


def router(admin, _config, _core) -> APIRouter:
    r = APIRouter(prefix="/api", dependencies=[Depends(admin)])

    @r.get("/schema")
    async def schema(request: Request) -> dict:
        async with request.app.state.pool.acquire() as conn:
            return {k: rows(await conn.fetch(sql)) for k, sql in SCHEMA_SQL.items()}

    @r.get("/advisors")
    async def advisors(request: Request) -> dict:
        async with request.app.state.pool.acquire() as conn:
            security = check_db(json.loads(await conn.fetchval(AUDIT_SQL)))
            perf = await conn.fetch(PERFORMANCE_AUDIT_SQL)
        return {
            "security": [{"level": f.level, "message": f.message} for f in security],
            "performance": [
                {"level": level, "message": before + p["name"] + after}
                for p in perf
                for level, before, after in [PERFORMANCE_MESSAGES[p["kind"]]]
            ],
        }

    @r.get("/performance")
    async def performance(request: Request) -> dict:
        async with request.app.state.pool.acquire() as conn:
            statements_enabled = await conn.fetchval(STATEMENTS_ENABLED_SQL)
            return {
                "activity": rows(await conn.fetch(ACTIVITY_SQL)),
                "statements_enabled": statements_enabled,
                "statements": rows(await conn.fetch(STATEMENTS_SQL)) if statements_enabled else [],
                "tables": rows(await conn.fetch(TABLE_STATS_SQL)),
            }

    @r.post("/performance/{pid}/{action}")
    async def backend_action(pid: int, action: str, request: Request):
        sql = PID_ACTIONS.get(action)
        if sql is None:
            return error(400, "invalid_request", "action is cancel or terminate")
        if not await request.app.state.pool.fetchval(sql, pid):
            return error(404, "not_found", "no such backend")
        return {"ok": True}

    @r.post("/performance/reset")
    async def reset_statistics(request: Request):
        async with request.app.state.pool.acquire() as conn:
            await conn.execute("select pg_stat_reset()")
            if await conn.fetchval(STATEMENTS_ENABLED_SQL):
                await conn.execute("select pg_stat_statements_reset()")
        return {"ok": True}

    @r.get("/migrations")
    async def migrations(request: Request) -> dict:
        out = {}
        async with request.app.state.pool.acquire() as conn:
            for kind, sql in MIGRATIONS_SQL.items():
                try:
                    out[kind] = rows(await conn.fetch(sql))
                except asyncpg.UndefinedTableError:
                    out[kind] = []
        return out

    return r
