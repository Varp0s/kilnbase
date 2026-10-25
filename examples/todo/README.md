# Todo example

A single HTML page using the Kilnbase JS client: sign-up/sign-in, row level security, and live updates.

```sh
docker compose up -d                                          # from the repo root
docker compose exec -T db psql -U postgres < examples/todo/schema.sql
(cd sdk/js && npm ci && npm run build)
python -m http.server 3000                                    # from the repo root
```

Open <http://localhost:3000/examples/todo/> and paste `KILNBASE_ANON_KEY` from `.env` when asked
(or pass it as `?key=...`). Open a second window signed in as the same user to watch changes arrive in real time;
a different user sees only their own todos.
