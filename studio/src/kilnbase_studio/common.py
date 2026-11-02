import json
from pathlib import Path

from fastapi.responses import JSONResponse

# Studio shows rows that end users wrote, on a page that holds the service_role key: nothing may
# run except our own script, and the page may not be framed.
HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
SQL_MAX_CELL = 10_000


def cell(value):
    """JSON-safe, size-capped: timestamps, UUIDs, decimals and the like become their text."""
    if value is None or isinstance(value, bool | int | float):
        return value
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= SQL_MAX_CELL else text[:SQL_MAX_CELL] + "…"


def rows(records) -> list[dict]:
    """asyncpg records as JSON-safe dicts (arrays stay lists; dates and UUIDs become text)."""
    return [
        {k: [cell(x) for x in v] if isinstance(v, list) else cell(v) for k, v in r.items()}
        for r in records
    ]


def error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"code": code, "message": message}, status_code=status, headers=HEADERS)


LOG_DIR = Path("/logs")
# Fixed names only: a path is never built from the request.
LOG_FILES = {s: LOG_DIR / s / f"{s}.log" for s in ("core", "auth", "functions", "studio")}
LOG_TAIL_BYTES = 2 * 1024 * 1024
LEVELS = ("debug", "info", "warning", "error", "critical")


def read_log(path: Path) -> list[dict]:
    """The last LOG_TAIL_BYTES of the rotated and the current file, oldest first."""
    entries = []
    for file in (path.with_name(path.name + ".1"), path):
        try:
            with file.open("rb") as f:
                f.seek(max(0, f.seek(0, 2) - LOG_TAIL_BYTES))
                data = f.read()
        except OSError:
            continue
        for raw in data.splitlines():
            try:
                entry = json.loads(raw)
            except ValueError:
                continue  # a line cut by the tail offset, or one written mid-rotation
            if isinstance(entry, dict):
                entries.append(entry)
    return entries
