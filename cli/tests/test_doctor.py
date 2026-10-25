from kilnbase_cli.doctor import check_db, check_env, parse_env
from kilnbase_cli.init import generate_env


def levels(findings):
    return [f.level for f in findings]


def test_fresh_init_env_has_no_failures():
    env = parse_env(generate_env())
    assert "fail" not in levels(check_env(env, mode=0o100600))


def test_flags_placeholders_short_passwords_and_shared_keys():
    env = parse_env(generate_env())
    env["KILNBASE_JWKS"] = "change-me"
    env["POSTGRES_PASSWORD"] = "short"
    env["KILNBASE_SERVICE_ROLE_KEY"] = env["KILNBASE_ANON_KEY"]
    messages = " ".join(f.message for f in check_env(env, mode=None) if f.level == "fail")
    assert "KILNBASE_JWKS" in messages
    assert "POSTGRES_PASSWORD" in messages
    assert "identical" in messages


def test_world_readable_env_warns():
    env = parse_env(generate_env())
    assert "warn" in levels(check_env(env, mode=0o100644))


def test_cors_wildcard_is_informational():
    env = parse_env(generate_env())
    infos = [f.message for f in check_env(env, None) if f.level == "info"]
    assert any("CORS" in m for m in infos)
    env["KILNBASE_CORS_ORIGINS"] = "https://app.example.com"
    assert not any("CORS" in f.message for f in check_env(env, None))


def test_db_rows_map_to_levels():
    rows = [
        {"kind": "unprotected_table", "name": "public.t"},
        {"kind": "definer_function", "name": "public.f()"},
        {"kind": "public_bucket", "name": "avatars"},
    ]
    assert levels(check_db(rows)) == ["fail", "warn", "info"]
