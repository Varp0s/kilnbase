-- shortcut: TOTP secrets are stored in plaintext, readable only by the auth service's database role;
-- encrypt them with a dedicated key before offering hosted or multi-tenant deployments.
create table auth.mfa_factors (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users on delete cascade,
    secret text not null,
    verified boolean not null default false,
    -- Highest accepted TOTP time step; a code at or below it is a replay.
    last_step bigint not null default 0,
    created_at timestamptz not null default now()
);
create index mfa_factors_user_id_idx on auth.mfa_factors (user_id);
-- At most one verified factor per user keeps enforcement unambiguous.
create unique index mfa_factors_one_verified on auth.mfa_factors (user_id) where verified;

-- Authenticator assurance level of a session: aal1 = password only, aal2 = password + TOTP.
alter table auth.sessions add column aal text not null default 'aal1' check (aal in ('aal1', 'aal2'));
