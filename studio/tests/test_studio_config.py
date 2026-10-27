import jwt
import pytest
from kilnbase_studio.config import ConfigError, load


def key(role: str) -> str:
    return jwt.encode({"role": role, "iss": "kilnbase"}, "k" * 32, algorithm="HS256")


ENV = {
    "DATABASE_URL": "postgres://postgres:pw@db:5432/postgres",
    "KILNBASE_SERVICE_ROLE_KEY": key("service_role"),
    "KILNBASE_ANON_KEY": key("anon"),
}


def test_loads_and_keeps_the_anon_claims():
    config = load(ENV)
    assert config.anon_claims == {"role": "anon", "iss": "kilnbase"}
    assert config.port == 3001
    assert (
        config.anon_key == ENV["KILNBASE_ANON_KEY"] and config.public_url == "http://localhost:8000"
    )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"KILNBASE_SERVICE_ROLE_KEY": ""}, "missing"),
        ({"KILNBASE_ANON_KEY": "change-me"}, "example value"),
        ({"DATABASE_URL": "postgres://postgres@db/postgres"}, "no password"),
        ({"KILNBASE_SERVICE_ROLE_KEY": key("anon")}, "not a service_role key"),
        ({"KILNBASE_ANON_KEY": key("service_role")}, "not an anon key"),
        ({"KILNBASE_ANON_KEY": "not-a-jwt"}, "not a JWT"),
        ({"KILNBASE_STUDIO_PORT": "99999"}, "valid port"),
    ],
)
def test_refuses_unsafe_config(change, message):
    with pytest.raises(ConfigError, match=message):
        load(ENV | change)
