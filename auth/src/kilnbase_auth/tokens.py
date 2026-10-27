import hashlib
import secrets
import time

import jwt

ACCESS_TOKEN_LIFETIME = 3600
# "mfa_pending" is not an API role: the gateway rejects it everywhere except the auth service.
USER_ROLES = ("authenticated", "mfa_pending")
REFRESH_TOKEN_LIFETIME = 30 * 24 * 3600


def user_claims(
    user_id: str,
    email: str | None,
    session_id: str,
    aal: str,
    mfa_pending: bool,
    email_verified: bool = False,
    recovery: bool = False,
    is_anonymous: bool = False,
) -> dict:
    """A user's access-token claims minus iat/exp; Studio's "view as user" uses them too."""
    return {
        "iss": "kilnbase",
        "sub": user_id,
        "role": "mfa_pending" if mfa_pending else "authenticated",
        "email": email,
        "sid": session_id,
        "aal": aal,
        # RLS can require a confirmed address: (auth.jwt() ->> 'email_verified')::boolean
        "email_verified": email_verified,
        "amr": ["recovery"] if recovery else [],
        "is_anonymous": is_anonymous,
    }


class Signer:
    """Issues and verifies access tokens; the only place the private key is used."""

    def __init__(self, private_jwk: dict):
        self._jwk = jwt.PyJWK.from_dict(private_jwk)
        self._kid = private_jwk["kid"]
        self._public = self._jwk.key.public_key()

    def access_token(self, *args, **kwargs) -> tuple[str, int]:
        """Arguments as for `user_claims`."""
        now = int(time.time())
        exp = now + ACCESS_TOKEN_LIFETIME
        claims = user_claims(*args, **kwargs) | {"iat": now, "exp": exp}
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
        if claims.get("role") not in USER_ROLES:
            raise jwt.InvalidTokenError("not a user token")
        return claims


def new_refresh_token() -> tuple[str, bytes]:
    token = secrets.token_urlsafe(32)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()
