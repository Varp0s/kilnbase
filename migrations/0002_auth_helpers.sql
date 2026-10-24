create schema auth;

-- Policies call these as the requesting role, so the schema must be usable but holds no granted tables.
grant usage on schema auth to anon, authenticated, service_role;

create function auth.jwt() returns jsonb
    language sql stable
    as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;

create function auth.uid() returns uuid
    language sql stable
    as $$ select nullif(auth.jwt() ->> 'sub', '')::uuid $$;

create function auth.role() returns text
    language sql stable
    as $$ select auth.jwt() ->> 'role' $$;

revoke all on function auth.jwt(), auth.uid(), auth.role() from public;
grant execute on function auth.jwt(), auth.uid(), auth.role() to anon, authenticated, service_role;
