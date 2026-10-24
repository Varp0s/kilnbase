import time
from collections import deque


class FailureLimiter:
    """Blocks a key after `limit` failures within `window` seconds.

    shortcut: in-process memory, so limits are per replica and reset on restart; move to Postgres
    or the gateway when auth runs with more than one replica.
    """

    def __init__(self, limit: int, window: float, clock=time.monotonic):
        self.limit = limit
        self.window = window
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}

    def retry_after(self, key: str) -> int:
        """Seconds until `key` may try again; 0 if not blocked."""
        hits = self._prune(key)
        if len(hits) < self.limit:
            return 0
        return max(1, int(hits[0] + self.window - self._clock()) + 1)

    def fail(self, key: str) -> None:
        self._prune(key)
        self._failures.setdefault(key, deque()).append(self._clock())

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)

    def _prune(self, key: str) -> deque[float]:
        hits = self._failures.get(key)
        if hits is None:
            return deque()
        cutoff = self._clock() - self.window
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if not hits:
            # Only keys that are currently failing stay in memory.
            del self._failures[key]
        return hits
