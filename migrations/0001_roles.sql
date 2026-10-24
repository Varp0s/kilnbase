-- API roles. Requests run as one of these via SET LOCAL ROLE; none can log in directly.
create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;

-- The only role services log in as. Its password is set by the migration runner from the environment.
create role authenticator login noinherit;
grant anon, authenticated, service_role to authenticator;

grant usage on schema public to anon, authenticated, service_role;

alter default privileges in schema public
    grant select, insert, update, delete on tables to anon, authenticated;
alter default privileges in schema public
    grant usage, select on sequences to anon, authenticated;
alter default privileges in schema public
    grant all on tables to service_role;
alter default privileges in schema public
    grant all on sequences to service_role;
