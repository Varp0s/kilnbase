import hmac
import time

import pyotp

STEP_SECONDS = 30


def matching_step(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Time step of a valid code, or None.

    Accepts one step of clock drift either way, and never a step at or before `last_step`, so each
    code works once.
    """
    totp = pyotp.TOTP(secret)
    current = int((time.time() if now is None else now) // STEP_SECONDS)
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(totp.at(step * STEP_SECONDS), code):
            return step
    return None
