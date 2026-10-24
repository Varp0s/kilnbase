# Contributing

- Rust code lives in `core/`: run `cargo fmt`, `cargo clippy -- -D warnings` and `cargo test`.
- Python code lives in `auth/` and `cli/`: run `uv run ruff check .`, `uv run ruff format .` and `uv run pytest`.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:` …).
- Every database access must go through the per-request role/claims helper; never query as a privileged role on behalf of a user.
- Security issues: see [SECURITY.md](SECURITY.md).
