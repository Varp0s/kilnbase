-- Anonymous users have no email until they upgrade to a permanent account.
alter table auth.users alter column email drop not null;
alter table auth.users add column is_anonymous boolean not null default false;
alter table auth.users add constraint users_email_unless_anonymous
    check (is_anonymous or email is not null);
