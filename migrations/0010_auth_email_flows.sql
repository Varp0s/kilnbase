-- One active code per email *and purpose*, so a reset mail does not cancel a pending sign-in code.
alter table auth.one_time_tokens
    add column purpose text not null default 'signin'
        check (purpose in ('signin', 'confirm', 'recovery'));
alter table auth.one_time_tokens drop constraint one_time_tokens_pkey;
alter table auth.one_time_tokens add primary key (email, purpose);

alter table auth.users add column email_confirmed_at timestamptz;
-- Passwordless and provider users proved their address to get an account at all.
update auth.users set email_confirmed_at = created_at where password_hash is null;

-- Set by a password-reset sign-in; allows one password change without the current password.
alter table auth.sessions add column recovery boolean not null default false;
