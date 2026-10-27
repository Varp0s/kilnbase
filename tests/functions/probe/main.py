"""Escape attempts for tests/e2e/test_functions_e2e.py; ?what= picks one."""

import base64
import ctypes
import json
import os
import socket
import urllib.error
import urllib.request


def reachable(host, port):
    try:
        socket.create_connection((host, port), timeout=0.5).close()
        return True
    except OSError:
        return False


def runner_status(token):
    headers = {"apikey": token}
    req = urllib.request.Request("http://127.0.0.1:9000/probe?what=env", headers=headers)
    try:
        return urllib.request.urlopen(req, timeout=5).status  # noqa: S310 - fixed http URL
    except urllib.error.HTTPError as e:
        return e.code


def b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def handler(request):
    what = request["query"]["what"]
    if what == "env":
        return dict(os.environ)
    if what == "files":
        try:
            open("/etc/kilnbase-test", "w")
            writable = True
        except OSError:
            writable = False
        others = os.listdir("/functions")
        return {"root_writable": writable, "functions": others, "cwd": os.listdir(".")}
    if what == "syscalls":
        libc = ctypes.CDLL(None, use_errno=True)
        out = {}
        for name, call in (
            ("unshare", lambda: libc.unshare(0x10000000)),
            ("clone3", lambda: libc.syscall(435, 0, 0)),
            ("clone_newuser", lambda: libc.syscall(56, 0x10000000 | 17, 0, 0, 0, 0)),
            ("ptrace", lambda: libc.ptrace(0, 0, 0, 0)),
        ):
            rc = call()
            out[name] = {"rc": rc, "errno": ctypes.get_errno()}
        return out
    if what == "network":
        # ?targets=host:port,... (IP addresses: unknown names only time out in Docker's DNS)
        targets = request["query"]["targets"].split(",")
        return {t: reachable(t.rsplit(":", 1)[0], int(t.rsplit(":", 1)[1])) for t in targets}
    if what == "forge":
        claims = {"role": "service_role", "exp": 9999999999}
        none = b64({"alg": "none", "typ": "JWT", "kid": "x"}) + "." + b64(claims) + "."
        return {"none": runner_status(none), "garbage": runner_status("not.a.token")}
    if what == "loop":
        while True:
            pass
    if what == "fork":
        while True:
            try:
                os.fork()
            except OSError:
                pass
    if what == "memory":
        return len(bytearray(2 * 1024 * 1024 * 1024))
    return {"unknown": what}, 400
