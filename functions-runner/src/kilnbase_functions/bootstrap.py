"""Runs inside the jail with the system Python: the request arrives as JSON on stdin and the
response leaves on the file descriptor named in argv[1], so print() output cannot corrupt it."""

import base64
import importlib.util
import json
import os
import sys


def encode(result) -> dict:
    status, headers = 200, {}
    if isinstance(result, tuple):
        body, status, *rest = result
        headers = rest[0] if rest else {}
    else:
        body = result
    if isinstance(body, bytes):
        content_type, data = "application/octet-stream", body
    elif isinstance(body, str):
        content_type, data = "text/plain; charset=utf-8", body.encode()
    else:
        content_type, data = "application/json", json.dumps(body).encode()
    return {
        "status": int(status),
        "headers": {"content-type": content_type} | {str(k): str(v) for k, v in headers.items()},
        "body_base64": base64.b64encode(data).decode(),
    }


def main() -> None:
    out = os.fdopen(int(sys.argv[1]), "w")
    request = json.load(sys.stdin)
    request["body"] = base64.b64decode(request.pop("body_base64"))
    sys.path.insert(0, os.getcwd())
    if len(sys.argv) > 2:  # packages from functions/requirements.txt
        sys.path.insert(1, sys.argv[2])
    spec = importlib.util.spec_from_file_location("main", os.path.join(os.getcwd(), "main.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    json.dump(encode(module.handler(request)), out)
    out.close()


if __name__ == "__main__":
    main()
