FROM debian:trixie-slim AS nsjail
# Release tarballs pinned by checksum; kafel is nsjail's seccomp-policy submodule at the commit 3.6 uses.
ARG NSJAIL_VERSION=3.6
ARG KAFEL_COMMIT=76d0f41bf3eb5c4008713d64b9767b461a9129a3
ADD --checksum=sha256:9731a07dc9f019b01b67292a96a4dd879873f6456e0ef6d51b1cdb553aa7e1cd \
    https://github.com/google/nsjail/archive/refs/tags/${NSJAIL_VERSION}.tar.gz /nsjail.tar.gz
ADD --checksum=sha256:b9a99b91af7abc84664803709072ee7f6a787dd3f39686484503154d93ef8f33 \
    https://github.com/google/kafel/archive/${KAFEL_COMMIT}.tar.gz /kafel.tar.gz
RUN apt-get update \
 && apt-get install -y --no-install-recommends make g++ pkg-config bison flex protobuf-compiler \
    libprotobuf-dev libnl-route-3-dev \
 && rm -rf /var/lib/apt/lists/*
RUN tar -xzf /nsjail.tar.gz -C / && mv "/nsjail-${NSJAIL_VERSION}" /nsjail \
 && rm -rf /nsjail/kafel && tar -xzf /kafel.tar.gz -C / && mv "/kafel-${KAFEL_COMMIT}" /nsjail/kafel \
 && cd /nsjail && make -j2 && strip nsjail

FROM python:3.15.1-slim-trixie
RUN apt-get update \
 && apt-get install -y --no-install-recommends libprotobuf32t64 libnl-route-3-200 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=nsjail /nsjail/nsjail /usr/local/bin/nsjail
COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /usr/local/bin/uv
# Runs functions written in TypeScript (type stripping is built in).
COPY --from=node:24.22.1-trixie-slim /usr/local/bin/node /usr/local/bin/node
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock ./
# The auth package is only used for its log format; no key, no migrations.
COPY auth ./auth
COPY functions-runner ./functions-runner
# uv needs every workspace member's manifest to validate the lock file.
COPY cli/pyproject.toml ./cli/pyproject.toml
COPY studio/pyproject.toml ./studio/pyproject.toml
RUN uv sync --locked --no-dev --package kilnbase-functions \
    && useradd --system --uid 10001 kilnbase     && mkdir /deps /logs && chown kilnbase /deps /logs
USER kilnbase
EXPOSE 9000
ENTRYPOINT ["/app/.venv/bin/python", "-m", "kilnbase_functions"]
