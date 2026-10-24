import hashlib
import secrets
import time

import jwt

ACCESS_TOKEN_LIFETIME = 3600
REFRESH_TOKEN_LIFETIME = 30 * 24 * 3600


class Signer:
    """Issues and verifies access tokens; the only place the private key is used."""

    def __init__(self, private_jwk: dict):
        self._jwk = jwt.PyJWK.from_dict(private_jwk)
        self._kid = private_jwk["kid"]
        self._public = self._jwk.key.public_key()

    def access_token(self, user_id: str, email: str, session_id: str) -> tuple[str, int]:
        now = int(time.time())
        exp = now + ACCESS_TOKEN_LIFETIME
        claims = {
            "iss": "kilnbase",
            "sub": user_id,
            "role": "authenticated",
            "email": email,
            "sid": session_id,
            "iat": now,
            "exp": exp,
        }
        token = jwt.encode(claims, self._jwk.key, algorithm="ES256", headers={"kid": self._kid})
        return token, exp

    def verify(self, token: str) -> dict:
        """Raises jwt.InvalidTokenError on anything but a valid user access token."""
        claims = jwt.decode(
            token,
            self._public,
            algorithms=["ES256"],
            issuer="kilnbase",
            options={"require": ["exp", "sub", "sid"]},
            leeway=30,
        )
        if claims.get("role") != "authenticated":
            raise jwt.InvalidTokenError("not a user token")
        return claims


def new_refresh_token() -> tuple[str, bytes]:
    token = secrets.token_urlsafe(32)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()
