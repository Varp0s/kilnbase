#!/usr/bin/env bash
# Runs bench/*.js with k6 inside the compose network against a running stack.
# Usage: bench/run.sh [VUS] [DURATION]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

env_value() { grep -E "^$1=" .env | head -n1 | cut -d= -f2- | sed "s/^'//; s/'\$//"; }

docker compose exec -T db psql -U postgres -v ON_ERROR_STOP=1 -q <<'SQL'
create table if not exists public.bench_items (id int primary key, name text not null);
alter table public.bench_items enable row level security;
drop policy if exists bench_read on public.bench_items;
create policy bench_read on public.bench_items for select to anon, authenticated using (true);
insert into public.bench_items select g, 'item ' || g from generate_series(1, 100) g on conflict do nothing;
notify pgrst, 'reload schema';
SQL
sleep 1

ANON_KEY=$(env_value KILNBASE_ANON_KEY)
EMAIL="bench-$(date +%s)@example.com"
USER_TOKEN=$(curl -fsS -X POST localhost:8000/auth/v1/signup -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\",\"password\":\"bench passphrase\"}" |
  python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

# MSYS_NO_PATHCONV keeps Git Bash on Windows from rewriting the container paths.
MSYS_NO_PATHCONV=1 docker run --rm --network kilnbase_default \
  -v "$ROOT/bench:/bench:ro" \
  -e ANON_KEY="$ANON_KEY" -e USER_TOKEN="$USER_TOKEN" \
  -e VUS="${1:-20}" -e DURATION="${2:-20s}" \
  grafana/k6:2.3.0 run --quiet /bench/rest.js
