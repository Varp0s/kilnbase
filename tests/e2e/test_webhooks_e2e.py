import hashlib
import hmac
import json
import time

import httpx2 as httpx
from conftest import ROOT, psql
from kilnbase_cli.doctor import query_db

MOCK = "http://localhost:9100"  # the auth worker reaches the same server as http://oauth-mock:9100

SETUP = """
drop table if exists public.e2e_hook, public.e2e_hook_fail;
create table public.e2e_hook (id int primary key, v text);
create table public.e2e_hook_fail (id int primary key);
alter table public.e2e_hook enable row level security;
alter table public.e2e_hook_fail enable row level security;
"""
CLEANUP = """
select kilnbase.drop_webhook(name) from kilnbase.webhooks where name like 'e2e-%';
drop table if exists public.e2e_hook, public.e2e_hook_fail;
"""


CREATE_SQL = """
select row_to_json(w) from kilnbase.create_webhook(
    :'name', :'target', array['INSERT', 'UPDATE', 'DELETE'], :'url') w
"""
DELIVERIES_SQL = """
select coalesce(json_agg(d order by d.id), '[]') from kilnbase.webhook_deliveries d
  join kilnbase.webhooks w on w.id = d.webhook_id where w.name = :'name'
"""


def create(name: str, table: str, hook: str) -> dict:
    url = f"http://oauth-mock:9100/hooks/{hook}"
    return query_db(ROOT, CREATE_SQL, name=name, target=f"public.{table}", url=url)


def received(hook: str, count: int, timeout: float = 20) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = httpx.get(f"{MOCK}/hooks/{hook}").json()["received"]
        if len(got) >= count:
            return got
        time.sleep(0.3)
    raise AssertionError(f"{hook}: expected {count} deliveries, got {len(got)}")


def deliveries(name: str) -> list[dict]:
    return query_db(ROOT, DELIVERIES_SQL, name=name)


def test_writes_are_delivered_signed_once_and_only_when_committed():
    hook = f"ok-{time.time_ns()}"
    psql(SETUP)
    try:
        webhook = create("e2e-ok", "e2e_hook", hook)
        psql(
            "insert into public.e2e_hook values (1, 'a');"
            "update public.e2e_hook set v = 'b' where id = 1;"
            "delete from public.e2e_hook where id = 1;"
            "begin; insert into public.e2e_hook values (99, 'rolled back'); rollback;"
        )
        got = received(hook, 3)
        payloads = {json.loads(g["body"])["type"]: json.loads(g["body"]) for g in got}
        assert payloads["INSERT"]["record"] == {"id": 1, "v": "a"}
        assert payloads["INSERT"]["old_record"] is None
        assert payloads["UPDATE"]["old_record"] == {"id": 1, "v": "a"}
        assert payloads["UPDATE"]["record"] == {"id": 1, "v": "b"}
        assert payloads["DELETE"]["record"] is None
        assert payloads["DELETE"]["table"] == "e2e_hook"

        for g in got:
            h = {k.lower(): v for k, v in g["headers"].items()}
            signed = f"{h['x-kilnbase-timestamp']}.{g['body']}".encode()
            mac = hmac.new(webhook["secret"].encode(), signed, hashlib.sha256).hexdigest()
            assert hmac.compare_digest(h["x-kilnbase-signature"], f"v1={mac}")

        # Two workers (auth and auth-mfa) run, yet nothing arrives twice; the rollback sent nothing.
        time.sleep(2)
        got = httpx.get(f"{MOCK}/hooks/{hook}").json()["received"]
        ids = [{k.lower(): v for k, v in g["headers"].items()}["x-kilnbase-delivery"] for g in got]
        assert len(ids) == 3 and len(set(ids)) == 3
        rows = deliveries("e2e-ok")
        assert [r["status"] for r in rows] == ["delivered"] * 3
        assert all(r["attempts"] == 1 and r["last_status"] == 200 for r in rows)
    finally:
        psql(CLEANUP)


def test_failures_are_retried_then_marked_failed():
    hook = f"fail-{time.time_ns()}"
    psql(SETUP)
    try:
        httpx.post(f"{MOCK}/hooks-status/{hook}", json={"status": 500})
        create("e2e-fail", "e2e_hook_fail", hook)
        psql("update kilnbase.webhooks set max_attempts = 2 where name = 'e2e-fail';")
        psql("insert into public.e2e_hook_fail values (1);")

        received(hook, 1)
        time.sleep(0.5)
        [row] = deliveries("e2e-fail")
        assert (row["status"], row["attempts"], row["last_status"]) == ("pending", 1, 500)
        assert row["last_error"] == "HTTP 500"

        # Skip the 10 s backoff instead of waiting for it.
        psql(
            "update kilnbase.webhook_deliveries set next_attempt_at = now()"
            " where status = 'pending';"
        )
        received(hook, 2)
        time.sleep(0.5)
        [row] = deliveries("e2e-fail")
        assert (row["status"], row["attempts"]) == ("failed", 2)
    finally:
        psql(CLEANUP)
