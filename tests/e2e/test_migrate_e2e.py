from conftest import ROOT, psql, wait_for_schema
from kilnbase_cli.migrate import run

FIRST = """
create table public.e2e_migrate (id int primary key, body text not null);
alter table public.e2e_migrate enable row level security;
create policy read_all on public.e2e_migrate for select to anon using (true);
insert into public.e2e_migrate values (1, 'from a migration');
"""
CLEANUP = """
drop table if exists public.e2e_migrate;
delete from kilnbase.app_migrations where version like '2099%';
"""


def test_migrate_applies_once_and_rolls_back_failures(client, keys, tmp_path, capsys):
    psql(CLEANUP)
    env = ROOT / ".env"
    try:
        (tmp_path / "20990101000000_first.sql").write_text(FIRST, encoding="utf-8")
        assert run(env, tmp_path) == 0
        wait_for_schema(client, keys, "e2e_migrate")
        rows = client.get("/rest/v1/e2e_migrate", headers={"apikey": keys.anon}).json()
        assert rows == [{"id": 1, "body": "from a migration"}]
        assert capsys.readouterr().out == "applied 20990101000000_first\n"
        assert run(env, tmp_path) == 0
        assert capsys.readouterr().out == ""  # nothing pending

        # A failing file leaves nothing behind and is retried next time.
        bad = tmp_path / "20990102000000_bad.sql"
        bad.write_text("insert into public.e2e_migrate values (2, 'x');\nselect 1/0;\n")
        assert run(env, tmp_path) == 1
        rows = client.get("/rest/v1/e2e_migrate", headers={"apikey": keys.anon}).json()
        assert [r["id"] for r in rows] == [1]
        bad.write_text("insert into public.e2e_migrate values (2, 'fixed');\n")
        assert run(env, tmp_path) == 0
        rows = client.get("/rest/v1/e2e_migrate", headers={"apikey": keys.anon}).json()
        assert [r["id"] for r in rows] == [1, 2]

        # Editing an applied migration is refused.
        bad.write_text("select 1;\n")
        assert run(env, tmp_path) == 1
    finally:
        psql(CLEANUP)
