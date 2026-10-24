-- Owned and used only by the auth service; no API role is granted anything here.
create table auth.users (
    id uuid primary key default gen_random_uuid(),
    email text not null,
    password_hash text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_sign_in_at timestamptz
);
create unique index users_email_key on auth.users (lower(email));

-- One row per sign-in; revoking it invalidates every refresh token issued for it.
create table auth.sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users on delete cascade,
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);
create index sessions_user_id_idx on auth.sessions (user_id);

-- Only SHA-256 hashes are stored; a used token presented again means it leaked.
create table auth.refresh_tokens (
    token_hash bytea primary key,
    session_id uuid not null references auth.sessions on delete cascade,
    created_at timestamptz not null default now(),
    used_at timestamptz
);
create index refresh_tokens_session_id_idx on auth.refresh_tokens (session_id);
