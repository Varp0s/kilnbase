FROM python:3.15.1-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY auth ./auth
COPY migrations ./migrations
# uv needs every workspace member's manifest to validate the lock file.
COPY cli/pyproject.toml ./cli/pyproject.toml
COPY functions-runner/pyproject.toml ./functions-runner/pyproject.toml
COPY studio/pyproject.toml ./studio/pyproject.toml
RUN uv sync --locked --no-dev --package kilnbase-auth \
    && useradd --system --uid 10001 kilnbase
USER kilnbase
EXPOSE 9999
ENTRYPOINT ["/app/.venv/bin/python", "-m", "kilnbase_auth"]
