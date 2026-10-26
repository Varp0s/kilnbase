from kilnbase_cli.gen_types import render


def col(name, type="text", **flags):
    base = {"enum": False, "array": False, "nullable": False, "default": False, "generated": False}
    return {"name": name, "type": type, **base, **flags}


META = {
    "enums": {"mood": ["happy", 'say "hi"']},
    "relations": [
        {
            "name": "todos",
            "view": False,
            "columns": [
                col("id", "int8", default=True),
                col("title"),
                col("note", nullable=True),
                col("tags", array=True),
                col("mood", "mood", enum=True, nullable=True),
                col("moods", "mood", enum=True, array=True),
                col("meta", "jsonb"),
                col("slug", generated=True),
                col("my-col", "bool"),
            ],
        },
        {"name": "todo_view", "view": True, "columns": [col("id", "int4", nullable=True)]},
    ],
}


def test_renders_rows_inserts_and_updates():
    ts = render(META)
    assert '"id": number;' in ts
    assert '"id"?: number;' in ts  # default makes it optional on insert
    assert '"title": string;' in ts
    assert '"note": string | null;' in ts
    assert '"note"?: string | null;' in ts
    assert '"tags": string[];' in ts
    assert '"mood": "happy" | "say \\"hi\\"" | null;' in ts
    assert '"moods": ("happy" | "say \\"hi\\"")[];' in ts
    assert '"meta": Json;' in ts
    assert '"slug"?: never;' in ts
    assert '"my-col": boolean;' in ts
    assert '"mood": "happy" | "say \\"hi\\"";' in ts  # Enums block


def test_views_have_only_rows():
    view = render(META).split('"todo_view"')[1]
    assert "Row:" in view and "Insert:" not in view
