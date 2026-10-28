-- A pending phone number per user, set only after the code texted to it is entered from one of the
-- user's own sessions. Only a hash of the code is stored.
create table auth.phone_changes (
    user_id uuid primary key references auth.users on delete cascade,
    new_phone text not null,
    code_hash bytea not null,
    attempts int not null default 0,
    created_at timestamptz not null default now()
);
