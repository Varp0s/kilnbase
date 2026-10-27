from conftest import ROOT, psql, wait_for_schema
from kilnbase_cli.doctor import query_db

SETUP = """
create extension if not exists vector with schema extensions;
create extension if not exists pgmq;
create extension if not exists pg_cron;
drop table if exists public.e2e_vec;
create table public.e2e_vec (id int primary key, embedding extensions.vector(3) not null);
alter table public.e2e_vec enable row level security;
create policy read_all on public.e2e_vec for select to anon using (true);
insert into public.e2e_vec values (1, '[1,0,0]'), (2, '[0,1,0]');
notify pgrst, 'reload schema';
"""
CLEANUP = """
drop table if exists public.e2e_vec;
drop extension if exists vector, pgmq, pg_cron;
"""


def test_vector_queue_and_cron(client, keys):
    psql(SETUP)
    try:
        wait_for_schema(client, keys, "e2e_vec")
        r = client.get("/rest/v1/e2e_vec?order=id", headers={"apikey": keys.anon})
        assert r.json() == [{"id": 1, "embedding": "[1,0,0]"}, {"id": 2, "embedding": "[0,1,0]"}]
        # Extension functions are not served as RPC.
        r = client.post("/rest/v1/rpc/l2_distance", headers={"apikey": keys.anon}, json={})
        assert r.status_code == 404

        nearest = query_db(
            ROOT,
            "select json_agg(id) from (select id from public.e2e_vec"
            " order by embedding operator(extensions.<->) '[0.1,0.9,0]' limit 1) t",
        )
        assert nearest == [2]

        psql("""select pgmq.create('e2e_q'); select pgmq.send('e2e_q', '{"n": 1}');""")
        sent = query_db(ROOT, "select json_agg(message) from pgmq.read('e2e_q', 30, 1);")
        assert sent == [{"n": 1}]

        job = query_db(
            ROOT,
            "select json_build_object('id', cron.schedule('e2e', '* * * * *', 'select 1'));",
        )
        assert isinstance(job["id"], int)
    finally:
        psql(CLEANUP)
