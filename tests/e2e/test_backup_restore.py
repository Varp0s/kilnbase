from conftest import ROOT, psql, wait_for_gateway, wait_for_schema
from kilnbase_cli.backup import backup, restore

SCHEMA = """
drop table if exists public.e2e_backup;
create table public.e2e_backup (id int primary key, body text not null);
alter table public.e2e_backup enable row level security;
insert into public.e2e_backup values (1, 'keep me');
delete from storage.objects where bucket_id = 'e2e-backup';
delete from storage.buckets where id = 'e2e-backup';
notify pgrst, 'reload schema';
"""
FILE = "/storage/v1/object/e2e-backup/notes/a.txt"


def test_restore_brings_back_rows_and_files(client, keys, tmp_path):
    service = {"apikey": keys.service_role}
    psql(SCHEMA)
    try:
        wait_for_schema(client, keys, "e2e_backup")
        r = client.post("/storage/v1/bucket", headers=service, json={"id": "e2e-backup"})
        assert r.status_code == 201, r.text
        body = b"backed up \x00\xff bytes"
        r = client.post(FILE, headers=service | {"Content-Type": "text/plain"}, content=body)
        assert r.status_code in (200, 201), r.text

        archive = tmp_path / "kb.tar"
        assert backup(ROOT / ".env", archive) == 0

        psql("delete from public.e2e_backup;")
        assert client.delete(FILE, headers=service).status_code == 204
        assert client.get(FILE, headers=service).status_code == 404

        assert restore(ROOT / ".env", archive, yes=True) == 0
        wait_for_gateway(client)
        wait_for_schema(client, keys, "e2e_backup")

        rows = client.get("/rest/v1/e2e_backup", headers=service).json()
        assert rows == [{"id": 1, "body": "keep me"}]
        r = client.get(FILE, headers=service)
        assert r.status_code == 200
        assert r.content == body
    finally:
        psql(
            "drop table if exists public.e2e_backup;"
            "delete from storage.objects where bucket_id = 'e2e-backup';"
            "delete from storage.buckets where id = 'e2e-backup';"
        )
