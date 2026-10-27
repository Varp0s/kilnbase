-- Home for extension objects (`create extension vector with schema extensions`). Functions installed
-- into public would be callable through /rest/v1/rpc; here API roles can use the types and operators
-- but PostgREST does not serve them.
create schema if not exists extensions;
grant usage on schema extensions to anon, authenticated, service_role;
