import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlencode

import httpx2 as httpx

from .errors import send

Primitive = str | int | float | bool | None


def _text(v: Primitive) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def list_value(v: Primitive) -> str:
    """Quotes a value for PostgREST list syntax when it contains reserved characters."""
    s = _text(v)
    if re.search(r'[,()"\\:\s]', s):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


class Query:
    """Chainable query against `/rest/v1/<table>`; `execute()` runs it."""

    def __init__(self, http: httpx.Client, url: str, table: str, headers: Callable[[], dict]):
        self._http = http
        self._url = url
        self._table = table
        self._headers = headers
        self._params: list[tuple[str, str]] = []
        self._method = "GET"
        self._body: Any = None
        self._single = False
        self._prefer: list[str] = []

    def select(self, columns: str = "*") -> Query:
        return self._set("select", columns)

    def insert(self, rows: dict | list[dict]) -> Query:
        return self._write("POST", rows)

    def upsert(self, rows: dict | list[dict]) -> Query:
        """Insert, or update rows whose primary key already exists."""
        self._prefer.append("resolution=merge-duplicates")
        return self._write("POST", rows)

    def update(self, values: dict) -> Query:
        return self._write("PATCH", values)

    def delete(self) -> Query:
        return self._write("DELETE", None)

    def eq(self, column: str, value: Primitive) -> Query:
        return self._filter(column, "eq", value)

    def neq(self, column: str, value: Primitive) -> Query:
        return self._filter(column, "neq", value)

    def gt(self, column: str, value: Primitive) -> Query:
        return self._filter(column, "gt", value)

    def gte(self, column: str, value: Primitive) -> Query:
        return self._filter(column, "gte", value)

    def lt(self, column: str, value: Primitive) -> Query:
        return self._filter(column, "lt", value)

    def lte(self, column: str, value: Primitive) -> Query:
        return self._filter(column, "lte", value)

    def like(self, column: str, pattern: str) -> Query:
        return self._filter(column, "like", pattern)

    def ilike(self, column: str, pattern: str) -> Query:
        return self._filter(column, "ilike", pattern)

    def is_(self, column: str, value: None | bool) -> Query:
        return self._filter(column, "is", value)

    def in_(self, column: str, values: list[Primitive]) -> Query:
        self._params.append((column, f"in.({','.join(list_value(v) for v in values)})"))
        return self

    def order(self, column: str, *, ascending: bool = True) -> Query:
        self._params.append(("order", f"{column}.{'asc' if ascending else 'desc'}"))
        return self

    def limit(self, count: int) -> Query:
        return self._set("limit", str(count))

    def range(self, start: int, end: int) -> Query:
        """Rows `start` to `end`, both inclusive and zero-based."""
        self._set("offset", str(start))
        return self._set("limit", str(end - start + 1))

    def single(self) -> Query:
        """`execute()` returns one row instead of a list; an error if zero or several match."""
        self._single = True
        return self

    def to_url(self) -> str:
        qs = urlencode(self._params)
        return f"{self._url}/rest/v1/{quote(self._table, safe='')}{'?' + qs if qs else ''}"

    def execute(self) -> Any:
        headers = self._headers()
        if self._single:
            # With this Accept header PostgREST returns one object instead of an array.
            headers["Accept"] = "application/vnd.pgrst.object+json"
        if self._method != "GET":
            # Writes return the affected rows, so callers see exactly what RLS let through.
            headers["Prefer"] = ",".join(["return=representation", *self._prefer])
        kwargs: dict[str, Any] = {"headers": headers}
        if self._body is not None:
            kwargs["json"] = self._body
        res = send(self._http, self._method, self.to_url(), **kwargs)
        return res.json() if res.content else []

    def _set(self, key: str, value: str) -> Query:
        self._params = [(k, v) for k, v in self._params if k != key] + [(key, value)]
        return self

    def _filter(self, column: str, op: str, value: Primitive) -> Query:
        self._params.append((column, f"{op}.{_text(value)}"))
        return self

    def _write(self, method: str, body: Any) -> Query:
        self._method, self._body = method, body
        return self
