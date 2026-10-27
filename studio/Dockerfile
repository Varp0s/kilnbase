FROM node:24.11.1-trixie-slim AS web
WORKDIR /web
COPY studio/web/package.json studio/web/package-lock.json ./
RUN npm ci --ignore-scripts
COPY studio/web ./
RUN npx tsc -p . --outDir /out

FROM python:3.15.1-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
# Studio reuses the auth package's token claims and log format (never its key or migrations).
COPY auth ./auth
COPY studio ./studio
COPY --from=web /out/app.js ./studio/src/kilnbase_studio/web/app.js
# uv needs every workspace member's manifest to validate the lock file.
COPY cli/pyproject.toml ./cli/pyproject.toml
RUN uv sync --locked --no-dev --package kilnbase-studio \
    && useradd --system --uid 10001 kilnbase
USER kilnbase
EXPOSE 3001
ENTRYPOINT ["/app/.venv/bin/python", "-m", "kilnbase_studio"]
