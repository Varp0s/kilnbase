-- A pending email change per user, applied only after the code sent to the new address is entered
-- from one of the user's own sessions. Only a hash of the code is stored.
create table auth.email_changes (
    user_id uuid primary key references auth.users on delete cascade,
    new_email text not null,
    code_hash bytea not null,
    attempts int not null default 0,
    created_at timestamptz not null default now()
);
