-- Broadcast/presence channels are closed until this function says otherwise. It runs as the calling
-- user (security invoker), so auth.uid() and auth.jwt() work. Replace it to open channels, e.g.:
--
--   create or replace function realtime.authorize(channel text, action text) returns boolean
--       language sql stable as $$
--       select channel like 'room:%' or channel = 'user:' || auth.uid()::text $$;
--
-- action is 'join' (receive broadcasts and presence) or 'broadcast' (send). service_role skips it.
create schema realtime;
grant usage on schema realtime to anon, authenticated, service_role;

create function realtime.authorize(channel text, action text) returns boolean
    language sql stable
    as $$ select false $$;

revoke all on function realtime.authorize(text, text) from public;
grant execute on function realtime.authorize(text, text) to anon, authenticated, service_role;
