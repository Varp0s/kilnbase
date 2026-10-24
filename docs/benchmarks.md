# Benchmarks

Reproduce with the stack running:

```sh
scripts/bench.sh [VUS] [DURATION]   # defaults: 20 virtual users, 20 s per scenario
```

k6 runs inside the compose network and sends the same PostgREST query (`10 rows, ordered`) three ways:

- **direct** — straight to PostgREST, bypassing the gateway
- **gateway** — through `core` with the anon API key
- **gateway_user** — through `core` with the anon key plus a user access token (two ES256 verifications)

## Results

2026-10-25, Docker Desktop on Windows 11 (WSL2), all containers on one machine, 20 VUs, 20 s each.

| Target | median | p95 | p99 |
|---|---|---|---|
| direct | 1.59 ms | 2.85 ms | 3.83 ms |
| gateway | 1.67 ms | 2.83 ms | 3.93 ms |
| gateway_user | 1.96 ms | 3.20 ms | 4.24 ms |

Gateway overhead at p99: **+0.10 ms** with an API key, **+0.41 ms** with a user token — inside the < 1 ms goal.
Throughput across all scenarios: ~8,900 requests/s, 0 failures out of 621,110.

Idle memory after the run: `core` ≈ 6 MB.

These numbers come from a developer laptop and are only meaningful relative to each other; rerun on your own
hardware before drawing conclusions.
