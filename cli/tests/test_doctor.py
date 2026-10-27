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
        {"kind": "archive_failing", "name": "000000010000000000000003"},
    ]
    findings = check_db(rows)
    assert levels(findings) == ["fail", "warn", "info", "warn"]
    assert "000000010000000000000003" in findings[-1].message


def s3_findings(**values):
    env = parse_env(generate_env()) | values
    return [(f.level, f.message) for f in check_env(env, mode=None) if "S3" in f.message]


def test_init_s3_pair_passes():
    env = parse_env(generate_env())
    assert env["KILNBASE_S3_ACCESS_KEY_ID"].startswith("kb_")
    # core requires a secret of at least 32 characters that is not the placeholder
    assert len(env["KILNBASE_S3_SECRET_ACCESS_KEY"]) >= 32
    assert s3_findings() == []


def test_s3_pair_problems():
    assert s3_findings(KILNBASE_S3_SECRET_ACCESS_KEY="")[0][0] == "fail"
    assert s3_findings(KILNBASE_S3_ACCESS_KEY_ID="", KILNBASE_S3_SECRET_ACCESS_KEY="") == []
    assert s3_findings(KILNBASE_S3_SECRET_ACCESS_KEY="change-me")[0][0] == "fail"
    assert s3_findings(KILNBASE_S3_SECRET_ACCESS_KEY="x" * 31)[0][0] == "fail"
    shared = parse_env(generate_env())["KILNBASE_STORAGE_SIGNING_KEY"]
    env = parse_env(generate_env()) | {"KILNBASE_STORAGE_SIGNING_KEY": shared}
    env["KILNBASE_S3_SECRET_ACCESS_KEY"] = shared
    assert [f.level for f in check_env(env, mode=None) if "S3" in f.message] == ["warn"]
