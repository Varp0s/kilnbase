"""The gateway's token rules (core/crates/gateway/src/auth.rs), applied again here.

Function code shares this service's network namespace and can call it on localhost directly, so
nothing the gateway sets in front of us can be trusted: the caller is re-derived from the tokens.
"""

import jwt

API_KEY_ROLES = ("anon", "service_role")
REQUEST_ROLES = ("anon", "authenticated", "service_role")


class Unauthorized(Exception):
    pass


def verify(keys: dict[str, jwt.PyJWK], token: str, roles: tuple[str, ...]) -> dict:
    try:
        # The algorithm is ours, never the token header's; kid must name one of our keys.
        key = keys.get(jwt.get_unverified_header(token).get("kid", ""))
        if key is None:
            raise Unauthorized("invalid token")
        claims = jwt.decode(
            token, key, algorithms=["ES256"], leeway=30, options={"require": ["exp"]}
        )
    except jwt.InvalidTokenError as e:
        raise Unauthorized("invalid token") from e
    if claims.get("role") not in roles:
        raise Unauthorized("invalid token")
    return claims


def caller(keys: dict[str, jwt.PyJWK], api_key: str | None, authorization: str | None) -> dict:
    """Claims of the bearer token if there is one, else of the API key (same as the gateway)."""
    if not api_key:
        raise Unauthorized("missing apikey")
    claims = verify(keys, api_key, API_KEY_ROLES)
    if authorization is None:
        return claims
    if not authorization.startswith("Bearer "):
        raise Unauthorized("authorization header must be a bearer token")
    return verify(keys, authorization.removeprefix("Bearer "), REQUEST_ROLES)
