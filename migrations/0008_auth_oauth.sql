-- Users who only ever sign in through a provider have no password.
alter table auth.users alter column password_hash drop not null;

-- One row per external account linked to a user.
create table auth.identities (
    provider text not null,
    provider_user_id text not null,
    user_id uuid not null references auth.users on delete cascade,
    email text,
    created_at timestamptz not null default now(),
    primary key (provider, provider_user_id)
);
create index identities_user_id_idx on auth.identities (user_id);

-- In-flight provider redirects; single use, short-lived. Only hashes of the state are stored.
create table auth.oauth_states (
    state_hash bytea primary key,
    provider text not null,
    redirect_to text not null,
    provider_verifier text not null,
    client_challenge text not null,
    created_at timestamptz not null default now()
);

-- One-time codes handed to the app after a provider sign-in; redeemed with the app's PKCE verifier.
create table auth.auth_codes (
    code_hash bytea primary key,
    user_id uuid not null references auth.users on delete cascade,
    client_challenge text not null,
    created_at timestamptz not null default now()
);
