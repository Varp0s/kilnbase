-- Passwordless sign-in: one active code + magic link per email. Only hashes are stored.
create table auth.one_time_tokens (
    email text primary key,
    code_hash bytea not null,
    link_hash bytea not null unique,
    create_user boolean not null,
    attempts int not null default 0,
    created_at timestamptz not null default now()
);
