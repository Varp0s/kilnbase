from conftest import ROOT, psql
from kilnbase_cli.doctor import check_db, query_db

BAD = """
drop view if exists public.e2e_doc_view;
drop table if exists public.e2e_doc_open, public.e2e_doc_safe;
create table public.e2e_doc_open (id int primary key);
-- The event trigger revoked access; an explicit grant afterwards re-exposes the table.
grant select on public.e2e_doc_open to anon;
create table public.e2e_doc_safe (id int primary key);
alter table public.e2e_doc_safe enable row level security;
create view public.e2e_doc_view as select * from public.e2e_doc_safe;
grant select on public.e2e_doc_view to authenticated;
"""


def names(level):
    return " ".join(f.message for f in check_db(query_db(ROOT)) if f.level == level)


def test_doctor_finds_reexposed_tables_and_definer_views():
    psql(BAD)
    try:
        fails = names("fail")
        assert "public.e2e_doc_open" in fails
        assert "public.e2e_doc_view" in fails
        assert "public.e2e_doc_safe has RLS but no policies" in names("info")
    finally:
        psql("drop view public.e2e_doc_view; drop table public.e2e_doc_open, public.e2e_doc_safe;")
    assert "e2e_doc" not in names("fail")
