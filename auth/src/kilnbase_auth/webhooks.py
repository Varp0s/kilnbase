"""Delivers queued database webhooks (migrations/0018_webhooks.sql): at least once, unordered."""

import asyncio
import hashlib
import hmac
import time

import asyncpg
import httpx2 as httpx

from .log import log

BATCH = 20
TIMEOUT = 10
# A claimed delivery is invisible to other workers this long. A batch is posted concurrently, so
# the lease only has to outlast one timeout; a crashed worker's claims come back after it.
LEASE = 6 * TIMEOUT
IDLE = 1.0
PRUNE_EVERY = 3600

CLAIM = """
update kilnbase.webhook_deliveries d
   set attempts = d.attempts + 1, next_attempt_at = now() + make_interval(secs => $2)
  from kilnbase.webhooks w
 where w.id = d.webhook_id
   and d.id in (select id from kilnbase.webhook_deliveries
                 where status = 'pending' and next_attempt_at <= now()
                 order by next_attempt_at limit $1 for update skip locked)
returning d.id, d.payload::text as body, d.attempts, w.id as webhook_id, w.url, w.secret,
          w.max_attempts
"""
DELIVERED = """
update kilnbase.webhook_deliveries
   set status = 'delivered', delivered_at = now(), last_status = $2, last_error = null
 where id = $1
"""
FAILED = """
update kilnbase.webhook_deliveries
   set status = case when attempts >= $4 then 'failed' else 'pending' end,
       next_attempt_at = now() + make_interval(secs => $5), last_status = $2, last_error = $3
 where id = $1
"""
PRUNE = """
delete from kilnbase.webhook_deliveries
 where status <> 'pending' and created_at < now() - interval '7 days'
"""


def sign(secret: str, timestamp: int, body: str) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.{body}".encode(), hashlib.sha256)
    return f"v1={mac.hexdigest()}"


def backoff(attempts: int) -> int:
    """Seconds before the next try: 10 s, 20 s, 40 s, ... capped at one hour."""
    return min(10 * 2 ** (attempts - 1), 3600)


async def deliver(pool: asyncpg.Pool, http: httpx.AsyncClient, row) -> None:
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Kilnbase-Webhooks",
        "X-Kilnbase-Delivery": str(row["id"]),
        "X-Kilnbase-Timestamp": str(timestamp),
        "X-Kilnbase-Signature": sign(row["secret"], timestamp, row["body"]),
    }
    status, error = None, None
    try:
        # Redirects are not followed: a receiver must not bounce the payload elsewhere.
        res = await http.post(
            row["url"], content=row["body"], headers=headers, timeout=TIMEOUT,
            follow_redirects=False,
        )  # fmt: skip
        status = res.status_code
        if 200 <= status < 300:
            await pool.execute(DELIVERED, row["id"], status)
            return
        error = f"HTTP {status}"
    except httpx.HTTPError as e:
        # The type only: messages can contain the URL, which may itself be a secret (chat webhooks).
        error = type(e).__name__
    await pool.execute(
        FAILED, row["id"], status, error, row["max_attempts"], backoff(row["attempts"])
    )
    log.warning(
        "webhook %s delivery %s failed (attempt %s): %s",
        row["webhook_id"],
        row["id"],
        row["attempts"],
        error,
    )


async def run(pool: asyncpg.Pool, http: httpx.AsyncClient) -> None:
    """Runs until cancelled; several instances (auth replicas) can run side by side."""
    pruned = 0.0
    while True:
        rows = []
        try:
            # The connection is only held for the claim, never while posting.
            rows = await pool.fetch(CLAIM, BATCH, LEASE)
            await asyncio.gather(*(deliver(pool, http, row) for row in rows))
            if time.monotonic() - pruned > PRUNE_EVERY:
                await pool.execute(PRUNE)
                pruned = time.monotonic()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("webhook worker error")
        if not rows:
            await asyncio.sleep(IDLE)
