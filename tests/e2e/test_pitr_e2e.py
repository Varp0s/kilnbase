import re
import time

from conftest import ROOT, psql, wait_for_gateway, wait_for_schema
from kilnbase_cli import pitr
from kilnbase_cli.backup import EVENT_SEQUENCES_SQL
from kilnbase_cli.doctor import query_db

ENV = ROOT / ".env"
SETUP = """
drop table if exists public.e2e_pitr;
create table public.e2e_pitr (v text primary key);
alter table public.e2e_pitr enable row level security;
create policy read_all on public.e2e_pitr for select to anon using (true);
insert into public.e2e_pitr values ('A');
notify pgrst, 'reload schema';
"""


def rows(client, keys) -> list[str]:
    r = client.get("/rest/v1/e2e_pitr?order=v", headers={"apikey": keys.anon})
    return [row["v"] for row in r.json()]


def db_now() -> str:
    # The database's clock, never the host's: they can differ.
    return query_db(ROOT, "select to_json(clock_timestamp())")


def test_rewind_to_a_time_and_undo(client, keys, capsys):
    archiving = query_db(ROOT, "select to_json(current_setting('archive_mode') = 'on')")
    assert (pitr.backup(ENV) if archiving else pitr.enable(ENV)) == 0
    wait_for_gateway(client)
    psql(SETUP)
    try:
        wait_for_schema(client, keys, "e2e_pitr")
        time.sleep(1)
        target = db_now()
        time.sleep(1)
        psql("insert into public.e2e_pitr values ('B');")
        seen = query_db(ROOT, EVENT_SEQUENCES_SQL)
        capsys.readouterr()

        assert pitr.restore(ENV, target, None, True) == 0
        wait_for_gateway(client)
        wait_for_schema(client, keys, "e2e_pitr")
        assert rows(client, keys) == ["A"]
        # Ids that clients dedupe on did not go back with the data.
        after = query_db(ROOT, EVENT_SEQUENCES_SQL)
        assert all(after[k] >= v for k, v in seen.items())

        undo = re.search(r"--timeline (\d+)", capsys.readouterr().out)
        assert undo, "restore printed no undo command"
        assert pitr.restore(ENV, None, int(undo.group(1)), True) == 0
        wait_for_gateway(client)
        wait_for_schema(client, keys, "e2e_pitr")
        assert rows(client, keys) == ["A", "B"]
    finally:
        psql("drop table if exists public.e2e_pitr;")


def test_bad_targets_change_nothing(client):
    for bad in ("2999-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", "2026-01-01T00:00"):
        assert pitr.restore(ENV, bad, None, True) == 1
    assert client.get("/health").status_code == 200  # nothing was stopped
