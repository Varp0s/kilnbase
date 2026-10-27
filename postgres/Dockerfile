# Postgres with pgBackRest and the extensions Kilnbase ships: pgvector, pg_cron and pgmq. None is enabled by default;
# run `create extension` in a migration (`kilnbase migrate`) when a project needs one.
FROM postgres:18.6-trixie AS pgmq
# pgmq is plain SQL, so its files are copied as they are; nothing is compiled.
# shortcut: version and checksum are bumped by hand; add a Renovate regex manager if that gets missed.
ARG PGMQ_VERSION=1.13.1
ADD --checksum=sha256:67221f288f42f95c002a64df40f7d660e765e32df8ada0f2672ba915a14827f7 \
    https://github.com/pgmq/pgmq/archive/refs/tags/v${PGMQ_VERSION}.tar.gz /pgmq.tar.gz
RUN mkdir /out \
 && tar -xzf /pgmq.tar.gz -C /tmp "pgmq-${PGMQ_VERSION}/pgmq-extension" \
 && cd "/tmp/pgmq-${PGMQ_VERSION}/pgmq-extension" \
 && cp pgmq.control sql/pgmq--*--*.sql /out/ \
 && cp sql/pgmq.sql "/out/pgmq--${PGMQ_VERSION}.sql"

FROM postgres:18.6-trixie
# Unpinned on purpose: the PGDG repository only keeps the newest build, and the base image pins Postgres.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-18-pgvector postgresql-18-cron pgbackrest \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/lib/pgbackrest && chown postgres:postgres /var/lib/pgbackrest
# Point-in-time recovery, off until `kilnbase pitr enable` turns on WAL archiving.
COPY pgbackrest.conf /etc/pgbackrest/pgbackrest.conf
COPY --from=pgmq /out/ /usr/share/postgresql/18/extension/
CMD ["postgres", "-c", "shared_preload_libraries=pg_cron", "-c", "cron.database_name=postgres"]
