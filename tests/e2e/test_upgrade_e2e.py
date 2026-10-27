import contextlib
import json
import subprocess

import pytest
from conftest import ROOT, psql, wait_for_gateway, wait_for_schema
from kilnbase_cli import upgrade
from kilnbase_cli.backup import Stack, compose_args, docker

SCHEMA = """
drop table if exists public.e2e_upgrade;
create table public.e2e_upgrade (id int primary key);
alter table public.e2e_upgrade enable row level security;
create policy read_all on public.e2e_upgrade for select to anon using (true);
insert into public.e2e_upgrade values (1);
notify pgrst, 'reload schema';
"""


def rows(client, keys):
    return client.get("/rest/v1/e2e_upgrade", headers={"apikey": keys.anon}).json()


@pytest.fixture
def stack_files():
    stack = Stack(ROOT)
    seen = dict.fromkeys(f for _, _, paths in stack.containers() for f in paths)
    files = [f for f in seen if not f.endswith(upgrade.OVERRIDE)]
    # Start from containers that run the current images, as after any normal `up`.
    docker(*compose_args(stack.project, files), "up", "-d", "--wait", "--force-recreate")
    yield stack.project, files
    # Back to the normal images and files, whatever the test did.
    docker(*compose_args(stack.project, files), "up", "-d", "--wait")
    (ROOT / upgrade.OVERRIDE).unlink(missing_ok=True)
    for archive in ROOT.glob("kilnbase-pre-upgrade-*.tar"):
        archive.unlink()
    fmt = "{{.Repository}}:{{.Tag}}"
    tags = docker("images", "--format", fmt, "kilnbase-rollback/*", text=True)
    for name in tags.stdout.split():
        with contextlib.suppress(subprocess.CalledProcessError):  # still in use: harmless
            docker("image", "rm", name)
    psql("drop table if exists public.e2e_upgrade;")


def test_upgrade_keeps_data(client, keys, stack_files):
    psql(SCHEMA)
    wait_for_schema(client, keys, "e2e_upgrade")
    assert upgrade.run(ROOT / ".env") == 0
    wait_for_gateway(client)
    assert rows(client, keys) == [{"id": 1}]
    assert not (ROOT / upgrade.OVERRIDE).exists()
    assert list(ROOT.glob("kilnbase-pre-upgrade-*.tar"))


def test_failed_upgrade_rolls_back(client, keys, stack_files, monkeypatch):
    psql(SCHEMA)
    wait_for_schema(client, keys, "e2e_upgrade")
    monkeypatch.setattr(upgrade, "core_healthy", lambda compose: False)
    assert upgrade.run(ROOT / ".env") == 1

    pins = json.loads((ROOT / upgrade.OVERRIDE).read_text())["services"]
    project, _ = stack_files
    fmt = '{{.Label "com.docker.compose.service"}} {{.Image}}'
    label = f"label=com.docker.compose.project={project}"
    out = docker("ps", "--filter", label, "--format", fmt, text=True).stdout
    running = dict(line.split(" ", 1) for line in out.splitlines())
    assert running["core"] == pins["core"]["image"]
    assert running["db"] == pins["db"]["image"]
    wait_for_gateway(client)
    wait_for_schema(client, keys, "e2e_upgrade")
    assert rows(client, keys) == [{"id": 1}]
