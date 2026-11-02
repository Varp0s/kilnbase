import pytest
from kilnbase_studio.platform import percentile, request_report
from kilnbase_studio.rows import BadRequest, Table

COLUMNS = [
    {
        "name": "id",
        "type": "bigint",
        "nullable": False,
        "default": None,
        "primary_key": True,
        "read_only": True,
    },
    {
        "name": "title",
        "type": "text",
        "nullable": False,
        "default": None,
        "primary_key": False,
        "read_only": False,
    },
    {
        "name": "qty",
        "type": "numeric(10,2)",
        "nullable": True,
        "default": None,
        "primary_key": False,
        "read_only": False,
    },
]
TABLE = Table("orders", COLUMNS)


def test_filter_casts_the_value_to_the_column_type():
    assert TABLE.where("qty", "gte", "3") == ' where "qty" >= $3::text::numeric(10,2)'
    assert TABLE.where("title", "like", "x") == " where \"title\"::text ilike '%' || $3 || '%'"
    assert TABLE.where("qty", "is", "not null") == ' where "qty" is not null'
    assert TABLE.where("qty", "eq", "1", param=1) == ' where "qty" = $1::text::numeric(10,2)'
    assert TABLE.where("", "eq", "1") == ""


@pytest.mark.parametrize(
    ("column", "op", "value"),
    [("nope", "eq", "1"), ("qty", "between", "1"), ("qty", "is", "maybe"), ('x"; drop', "eq", "1")],
)
def test_filter_rejects_unknown_columns_and_operators(column, op, value):
    with pytest.raises(BadRequest):
        TABLE.where(column, op, value)


def test_select_sorts_by_a_known_column_then_the_key():
    sql = TABLE.select(' where "qty" > $3::text::numeric(10,2)', sort="title", desc=True)
    order = 'order by "title" desc nulls last, "id" limit $1 offset $2'
    assert sql.endswith(f'where "qty" > $3::text::numeric(10,2) {order}')
    with pytest.raises(BadRequest):
        TABLE.select(sort="nope")
    assert (
        TABLE.count(' where "qty" is null')
        == 'select count(*) from public."orders" t where "qty" is null'
    )


def test_insert_many_uses_the_union_of_columns():
    sql = TABLE.insert_many([{"title": "a"}, {"title": "b", "qty": 1}])
    assert sql.startswith('insert into public."orders" ("title", "qty") select "title", "qty"')
    assert "json_populate_recordset" in sql
    for bad in ([], [{"id": 1}], [{"nope": 1}], "x", [{}]):
        with pytest.raises(BadRequest):
            TABLE.insert_many(bad)


def test_request_report_buckets_by_hour_and_service():
    import time

    now = time.time()
    entries = [
        {"ts": now - 60, "msg": "request", "path": "/rest/v1/todos", "status": 200, "ms": 4.0},
        {"ts": now - 60, "msg": "request", "path": "/rest/v1/todos", "status": 500, "ms": 40.0},
        {"ts": now - 60, "msg": "request", "path": "/auth/v1/token", "status": 401, "ms": 2.0},
        {"ts": now - 48 * 3600, "msg": "request", "path": "/rest/v1/old", "status": 200},
        {"ts": now - 60, "msg": "listening", "path": "/x"},
    ]
    report = request_report(entries)
    assert len(report["hours"]) == 25
    assert sum(h["ok"] + h["client_error"] + h["server_error"] for h in report["hours"]) == 3
    rest = next(s for s in report["services"] if s["service"] == "rest")
    assert rest == {"service": "rest", "requests": 2, "errors": 1, "p50_ms": 40.0, "p95_ms": 40.0}
    assert percentile([], 0.5) is None and percentile([3, 1, 2], 0.5) == 2
