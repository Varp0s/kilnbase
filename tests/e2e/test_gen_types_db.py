import os
import shutil
import subprocess

import pytest
from conftest import ROOT, psql
from kilnbase_cli.doctor import query_db
from kilnbase_cli.gen_types import META_SQL, render

SETUP = """
drop table if exists public.e2e_gen_todos, public.e2e_gen_hidden;
drop type if exists public.e2e_gen_mood;
create type public.e2e_gen_mood as enum ('happy', 'sad');
create table public.e2e_gen_todos (
    id bigint generated always as identity primary key,
    title text not null,
    note text,
    mood public.e2e_gen_mood not null default 'happy',
    tags text[] not null default '{}'
);
alter table public.e2e_gen_todos enable row level security;
-- No RLS: the event trigger revokes API access, so the API cannot see it.
create table public.e2e_gen_hidden (id int primary key);
"""

# .mts is ESM, which top-level await needs. Wrong usages carry @ts-expect-error,
# so tsc fails if `Database` ever stops constraining them.
CHECK = """
import { createClient } from "{sdk}";
import type { Database } from "./types.js";

const kb = createClient<Database>("http://localhost:8000", "anon");
const { data } = await kb.from("e2e_gen_todos").select();
const title: string = data![0]!.title;
const note: string | null = data![0]!.note;
const mood: "happy" | "sad" = data![0]!.mood;
await kb.from("e2e_gen_todos").insert({ title: "x" });
await kb.from("e2e_gen_todos").update({ note: null });
// @ts-expect-error tables without RLS are not part of the API
kb.from("e2e_gen_hidden");
// @ts-expect-error title is required
kb.from("e2e_gen_todos").insert({ note: "x" });
// @ts-expect-error wrong column type
kb.from("e2e_gen_todos").insert({ title: 1 });
// @ts-expect-error not an enum label
kb.from("e2e_gen_todos").update({ mood: "angry" });
export { title, note, mood };
"""


def test_gen_types_lists_api_tables_and_compiles(tmp_path):
    psql(SETUP)
    try:
        ts = render(query_db(ROOT, META_SQL, schema="public"))
    finally:
        psql(
            "drop table public.e2e_gen_todos, public.e2e_gen_hidden;drop type public.e2e_gen_mood;"
        )
    assert '"e2e_gen_todos"' in ts
    assert '"e2e_gen_hidden"' not in ts
    assert '"e2e_gen_mood": "happy" | "sad";' in ts

    tsc = shutil.which("tsc", path=str(ROOT / "sdk/js/node_modules/.bin"))
    if tsc is None:
        pytest.skip("run `npm install` in sdk/js to type-check the output")
    sdk = os.path.relpath(ROOT / "sdk/js/src/index.js", tmp_path).replace("\\", "/")
    (tmp_path / "types.ts").write_text(ts, encoding="utf-8")
    (tmp_path / "check.mts").write_text(CHECK.replace("{sdk}", sdk), encoding="utf-8")
    flags = "--noEmit --strict --target es2022 --module nodenext --moduleResolution nodenext"
    argv = [tsc, *flags.split(), "--lib", "es2022,dom", "--skipLibCheck", "check.mts"]
    out = subprocess.run(argv, cwd=tmp_path, capture_output=True, text=True)  # noqa: S603
    assert out.returncode == 0, out.stdout + out.stderr
