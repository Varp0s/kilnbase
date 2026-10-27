import asyncio
import base64
import json
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from kilnbase_auth.log import log

from . import jail
from .auth import Unauthorized, caller
from .config import Config

NAME = re.compile(r"[a-z0-9_-]{1,63}")
BODY_LIMIT = 1024 * 1024
# The function decides its own response, except for headers that belong to the transport.
DROPPED_HEADERS = {"content-length", "transfer-encoding", "connection", "keep-alive", "upgrade"}
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"code": code, "message": message}, status_code=status)


def create_app(config: Config) -> FastAPI:
    app = FastAPI(title="Kilnbase Functions", docs_url=None, redoc_url=None, openapi_url=None)
    slots = asyncio.Semaphore(config.concurrency)

    @app.get("/")
    async def health() -> dict:
        return {"status": "ok"}

    @app.api_route("/{name}", methods=METHODS)
    async def invoke(name: str, request: Request) -> Response:
        # Checked before touching the filesystem; the path is never built from anything else.
        function_dir = config.functions_dir / name
        if not NAME.fullmatch(name) or not (function_dir / "main.py").is_file():
            return error(404, "not_found", "no such function")
        try:
            claims = caller(
                config.keys, request.headers.get("apikey"), request.headers.get("authorization")
            )
        except Unauthorized as e:
            return error(401, "unauthorized", str(e))

        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > BODY_LIMIT:
                return error(413, "too_large", "request body is larger than 1 MiB")

        if slots.locked():
            return error(503, "busy", "too many function calls at once; retry shortly")
        async with slots:
            payload = {
                "method": request.method,
                "path": f"/{name}",
                "query": dict(request.query_params),
                "headers": dict(request.headers),
                "user": claims,
                "body_base64": base64.b64encode(body).decode(),
            }
            outcome = await jail.run(config, function_dir, json.dumps(payload).encode())

        if outcome.output:
            log.info("function %s output: %s", name, outcome.output)
        if outcome.timed_out:
            return error(504, "timeout", f"function ran longer than {config.timeout}s")
        if outcome.too_large:
            return error(502, "response_too_large", "function response is too large")
        try:
            result = json.loads(outcome.response)
            content = base64.b64decode(result["body_base64"])
            headers = {
                k: v for k, v in result["headers"].items() if k.lower() not in DROPPED_HEADERS
            }
            status = int(result["status"])
            if not 100 <= status <= 599:
                raise ValueError(status)
        except ValueError, KeyError, TypeError, AttributeError:
            log.warning("function %s failed (exit %s)", name, outcome.status)
            return error(500, "function_error", "the function raised an error; see the logs")
        return Response(content, status_code=status, headers=headers)

    return app
