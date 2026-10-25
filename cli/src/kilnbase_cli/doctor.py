import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PLACEHOLDER = "change-me"
REQUIRED = [
    "POSTGRES_PASSWORD",
    "KILNBASE_AUTHENTICATOR_PASSWORD",
    "KILNBASE_STORAGE_SIGNING_KEY",
    "KILNBASE_JWT_PRIVATE_JWK",
    "KILNBASE_JWKS",
    "KILNBASE_ANON_KEY",
    "KILNBASE_SERVICE_ROLE_KEY",
]


@dataclass(frozen=True)
class Finding:
    level: str  # "fail" | "warn" | "info"
    message: str


def parse_env(text: str) -> dict[str, str]:
    pairs = (
        line.split("=", 1) for line in text.splitlines() if "=" in line and not line.startswith("#")
    )
    return {k.strip(): v.strip().strip("'") for k, v in pairs}


def check_env(env: dict[str, str], mode: int | None) -> list[Finding]:
    findings = []
    for key in REQUIRED:
        value = env.get(key, "")
        if not value or value == PLACEHOLDER:
            findings.append(Finding("fail", f"{key} is missing or still the example value"))
    if len(env.get("POSTGRES_PASSWORD", "")) < 16:
        findings.append(Finding("fail", "POSTGRES_PASSWORD is shorter than 16 characters"))
    anon = env.get("KILNBASE_ANON_KEY")
    if anon and anon == env.get("KILNBASE_SERVICE_ROLE_KEY"):
        findings.append(Finding("fail", "anon and service_role keys are identical"))
    # Group/other permission bits on the secrets file (POSIX only; Windows reports no useful bits).
    if mode is not None and mode & 0o077:
        findings.append(
            Finding(
                "warn", f".env is readable by other users ({oct(mode & 0o777)}); chmod 600 .env"
            )
        )
    if (env.get("KILNBASE_CORS_ORIGINS", "").strip() or "*") == "*":
        findings.append(
            Finding("info", "CORS allows any origin; set KILNBASE_CORS_ORIGINS for production")
        )
    return findings


# Static, parameterless audit query in one round trip; each row is one risky object.
AUDIT_SQL = """
with api_roles as (select unnest(array['anon', 'authenticated']) as role),
rels as (
    select c.oid, c.relkind, c.relrowsecurity, c.reloptions,
           quote_ident(n.nspname) || '.' || quote_ident(c.relname) as name
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm')
),
exposed as (
    select r.* from rels r
     where exists (select 1 from api_roles a
                    where has_table_privilege(a.role, r.oid, 'SELECT,INSERT,UPDATE,DELETE'))
)
select coalesce(json_agg(json_build_object('kind', kind, 'name', name) order by kind, name), '[]')
from (
    select 'unprotected_table' as kind, name from exposed
     where relkind in ('r', 'p') and not relrowsecurity
    union all
    select 'definer_view', name from exposed
     where relkind = 'v' and not coalesce(reloptions && array['security_invoker=true',
           'security_invoker=on', 'security_invoker=1', 'security_invoker=yes'], false)
    union all
    select 'exposed_matview', name from exposed where relkind = 'm'
    union all
    select 'rls_without_policy', name from rels
     where relkind in ('r', 'p') and relrowsecurity
       and not exists (select 1 from pg_policy p where p.polrelid = rels.oid)
    union all
    select 'open_write_policy', quote_ident(p.polname) || ' on ' || r.name
      from pg_policy p join rels r on r.oid = p.polrelid
     where p.polcmd in ('a', 'w', 'd', '*')
       and (0 = any(p.polroles) or 'anon'::regrole::oid = any(p.polroles))
       and (pg_get_expr(p.polqual, p.polrelid) = 'true'
            or pg_get_expr(p.polwithcheck, p.polrelid) = 'true')
    union all
    select 'definer_function', p.oid::regprocedure::text
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.prosecdef
       and exists (select 1 from api_roles a where has_function_privilege(a.role, p.oid, 'EXECUTE'))
    union all
    select 'public_bucket', id from storage.buckets where public
) findings;
"""

# (level, message prefix, message suffix) around the object name.
DB_MESSAGES = {
    "unprotected_table": ("fail", "", " is reachable by API roles but has row level security off"),
    "definer_view": ("fail", "view ", " bypasses RLS (recreate it with security_invoker = true)"),
    "exposed_matview": ("fail", "materialized view ", " has no RLS but is reachable by API roles"),
    "rls_without_policy": (
        "info",
        "",
        " has RLS but no policies, so nobody can read it via the API",
    ),
    "open_write_policy": ("warn", "policy ", " lets anyone write unconditionally"),
    "definer_function": (
        "warn",
        "SECURITY DEFINER function ",
        " is callable by API roles and bypasses RLS",
    ),
    "public_bucket": ("info", "storage bucket ", " is public: anyone can download its files"),
}


def check_db(rows: list[dict]) -> list[Finding]:
    findings = []
    for row in rows:
        level, before, after = DB_MESSAGES[row["kind"]]
        findings.append(Finding(level, before + row["name"] + after))
    return findings


def query_db(root: Path) -> list[dict]:
    """shortcut: audits through `docker compose exec`; add a --database-url mode for other hosts."""
    argv = [
        "docker",
        "compose",
        "exec",
        "-T",
        "db",
        "psql",
        "-U",
        "postgres",
        "-At",
        "-v",
        "ON_ERROR_STOP=1",
    ]
    out = subprocess.run(  # noqa: S603 - fixed argv, static SQL on stdin
        argv, input=AUDIT_SQL, text=True, capture_output=True, check=True, cwd=root
    )
    return json.loads(out.stdout.strip() or "[]")


def run(env_file: Path, skip_db: bool = False) -> int:
    findings: list[Finding] = []
    if not env_file.exists():
        findings.append(Finding("fail", f"{env_file} not found; run `kilnbase init`"))
    else:
        mode = None if os.name == "nt" else env_file.stat().st_mode
        findings += check_env(parse_env(env_file.read_text(encoding="utf-8")), mode)

    if not skip_db:
        try:
            findings += check_db(query_db(env_file.resolve().parent))
        except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as e:
            findings.append(Finding("warn", f"database checks skipped: {e}"))

    order = {"fail": 0, "warn": 1, "info": 2}
    for f in sorted(findings, key=lambda f: order[f.level]):
        print(f"{f.level.upper():5} {f.message}")
    failed = any(f.level == "fail" for f in findings)
    print("doctor: problems found" if failed else "doctor: no blocking problems", file=sys.stderr)
    return 1 if failed else 0
