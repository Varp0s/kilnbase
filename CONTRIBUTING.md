# Contributing

- Rust code lives in `core/`: run `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test`.
- Python code lives in `auth/` and `cli/`: run `uv run ruff check .`, `uv run ruff format .` and `uv run pytest`.
- Studio's UI lives in `studio/web/` (TypeScript + Vite, no framework): `npm ci`, then `npm run dev` for live reload
  against a running Studio (`COMPOSE_PROFILES=studio docker compose up -d`) and `npm run build` before running it
  from source. Render with DOM APIs and `textContent` only, never `innerHTML`: the page holds the service_role key.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:` …).
- Every database access must go through the per-request role/claims helper; never query as a privileged role on behalf of a user.
- Security issues: see [SECURITY.md](SECURITY.md).
