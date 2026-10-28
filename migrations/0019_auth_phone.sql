-- Phone sign-in. A number is stored only once a code sent to it was entered, so it is always confirmed.
alter table auth.users add column phone text;
create unique index users_phone_key on auth.users (phone);
alter table auth.users drop constraint users_email_unless_anonymous;
alter table auth.users add constraint users_email_or_phone_unless_anonymous
    check (is_anonymous or email is not null or phone is not null);

-- One active sign-in code per number. Only the hash is stored.
create table auth.phone_codes (
    phone text primary key,
    code_hash bytea not null,
    create_user boolean not null,
    attempts int not null default 0,
    created_at timestamptz not null default now()
);
