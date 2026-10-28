"""Functions through the gateway, and escape attempts from inside one (tests/functions/probe)."""

import uuid

import pytest
from kilnbase_cli.backup import docker

PASSWORD = "correct horse battery staple"


@pytest.fixture(scope="module", autouse=True)
def running(client, keys):
    r = client.get("/functions/v1/whoami", headers={"apikey": keys.anon})
    if r.status_code == 404:
        pytest.skip("start the stack with docker-compose.test.yml (functions profile)")


def call(client, keys, name, token=None, **params):
    headers = {"apikey": keys.anon} | ({"Authorization": f"Bearer {token}"} if token else {})
    return client.get(f"/functions/v1/{name}", headers=headers, params=params, timeout=30)


def probe(client, keys, what, **params):
    r = call(client, keys, "probe", what=what, **params)
    assert r.status_code == 200, r.text
    return r.json()


def ip(service: str) -> str:
    fmt = "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"
    return docker("inspect", "-f", fmt, f"kilnbase-{service}-1", text=True).stdout.split()[0]


def test_callers_are_verified_and_passed_in(client, keys):
    assert client.get("/functions/v1/whoami").status_code == 401
    bad = {"apikey": keys.anon, "Authorization": "Bearer forged"}
    assert client.get("/functions/v1/whoami", headers=bad).status_code == 401

    r = client.post("/functions/v1/whoami", headers={"apikey": keys.anon}, content=b"ping")
    assert r.status_code == 201
    assert r.json() == {"role": "anon", "sub": None, "echo": "ping"}  # print() did not leak in

    body = {"email": f"fn-{uuid.uuid4().hex[:10]}@example.com", "password": PASSWORD}
    session = client.post("/auth/v1/signup", headers={"apikey": keys.anon}, json=body).json()
    r = call(client, keys, "whoami", session["access_token"])
    assert r.json()["sub"] == session["user"]["id"] and r.json()["role"] == "authenticated"


@pytest.mark.parametrize("name", ["..%2fwhoami", "Whoami", "no-such-function", "a.b"])
def test_unknown_and_invalid_names_are_not_found(client, keys, name):
    assert call(client, keys, name).status_code == 404


def test_errors_are_reported_without_details(client, keys):
    r = call(client, keys, "broken")
    assert r.status_code == 500 and "boom" not in r.text


def test_jail_holds_no_secrets_and_a_read_only_root(client, keys):
    env = probe(client, keys, "env")
    # SHARED is a `*.` entry from tests/functions/.secrets; nothing else leaks in.
    assert set(env) == {"KILNBASE_URL", "KILNBASE_ANON_KEY", "HOME", "LANG", "PATH", "SHARED"}
    files = probe(client, keys, "files")
    assert files == {"root_writable": False, "functions": [], "cwd": ["main.py"]}


def test_namespace_escapes_are_blocked(client, keys):
    calls = probe(client, keys, "syscalls")
    assert calls["unshare"] == {"rc": -1, "errno": 1}
    assert calls["clone_newuser"] == {"rc": -1, "errno": 1}
    assert calls["clone3"] == {"rc": -1, "errno": 38}
    assert calls["ptrace"]["rc"] == -1


def test_only_the_gateway_is_reachable(client, keys):
    targets = f"{ip('db')}:5432,{ip('auth')}:9999,{ip('postgrest')}:3000,core:8000"
    reachable = probe(client, keys, "network", targets=targets)
    assert [reachable[t] for t in targets.split(",")] == [False, False, False, True]


def test_runner_rejects_forged_tokens_sent_from_inside(client, keys):
    assert probe(client, keys, "forge") == {"none": 401, "garbage": 401}


@pytest.mark.parametrize(("what", "status"), [("loop", 504), ("fork", 504), ("memory", 500)])
def test_runaway_functions_are_contained(client, keys, what, status):
    assert call(client, keys, "probe", what=what).status_code == status
    assert call(client, keys, "whoami").status_code == 201  # the next call is unaffected


def test_typescript_functions(client, keys):
    r = client.post("/functions/v1/node", headers={"apikey": keys.anon}, content=b"ping")
    assert r.status_code == 201, r.text
    assert r.headers["x-runtime"] == "node"
    assert r.json() == {"role": "anon", "sub": None, "echo": "ping"}  # console.log did not leak in

    r = call(client, keys, "node", what="bytes")
    assert (r.status_code, r.content) == (200, b"\x00\x01\x02")
    assert r.headers["content-type"] == "application/octet-stream"
    r = call(client, keys, "node", what="throw")
    assert r.status_code == 500 and "boom" not in r.text

    env = call(client, keys, "node", what="env").json()
    assert set(env) == {"KILNBASE_URL", "KILNBASE_ANON_KEY", "HOME", "LANG", "PATH", "SHARED"}
    files = call(client, keys, "node", what="files").json()
    assert files == {"root_writable": False, "functions": [], "cwd": ["main.ts"]}


# Node takes seconds to exit once its heap is full, so the time limit is what ends that call.
@pytest.mark.parametrize(("what", "status"), [("loop", 504), ("memory", 500), ("heap", 504)])
def test_runaway_typescript_functions_are_contained(client, keys, what, status):
    assert call(client, keys, "node", what=what).status_code == status
    assert call(client, keys, "node").status_code == 201


def test_packages_from_requirements_are_importable(client, keys):
    r = call(client, keys, "deps")
    assert r.status_code == 200, r.text
    assert r.json() == {"six": "1.17.0", "path": "/opt/six.py"}


def test_secrets_reach_only_their_function(client, keys):
    r = call(client, keys, "secret")
    assert r.status_code == 200, r.text
    assert r.json() == {
        "API_TOKEN": "abc=123",
        "SHARED": "yes",
        "ONLY_WHOAMI": None,
        "PATH": "/usr/local/bin:/usr/bin:/bin",  # a secret cannot replace the jail's own variables
        "files": [],  # functions/.secrets itself is not visible
    }
