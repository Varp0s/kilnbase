-- History of the project's own migrations, applied by `kilnbase migrate`. Kept apart from
-- schema_migrations so app files can never shadow or reorder the platform's.
create table kilnbase.app_migrations (
    version text primary key,
    checksum text not null,
    applied_at timestamptz not null default now()
);
