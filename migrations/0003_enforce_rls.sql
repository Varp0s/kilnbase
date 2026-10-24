-- Relations in public are reachable by anon/authenticated only while row level security protects them:
-- tables need RLS enabled, views need security_invoker (otherwise they run as their owner and bypass RLS),
-- materialized views have no RLS at all and are never exposed.
-- shortcut: an explicit GRANT on an unprotected relation is not reverted, and any ALTER on a protected
-- table restores the default grants; `kilnbase doctor` will flag both once it exists.
create function kilnbase.enforce_rls() returns event_trigger
    language plpgsql
    as $$
declare
    obj record;
    exposed boolean;
begin
    for obj in
        select * from pg_event_trigger_ddl_commands()
        where schema_name = 'public'
          and object_type in ('table', 'view', 'materialized view')
    loop
        select case
                   when c.relkind in ('r', 'p') then c.relrowsecurity
                   when c.relkind = 'v' then coalesce(
                       c.reloptions && array['security_invoker=true', 'security_invoker=on',
                                             'security_invoker=1', 'security_invoker=yes'],
                       false)
                   else false
               end
          into exposed
          from pg_class c
         where c.oid = obj.objid;

        if exposed then
            execute format('grant select, insert, update, delete on %s to anon, authenticated',
                           obj.object_identity);
        else
            execute format('revoke all on %s from anon, authenticated', obj.object_identity);
        end if;
    end loop;
end
$$;

create event trigger kilnbase_enforce_rls on ddl_command_end
    when tag in ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'ALTER TABLE',
                 'CREATE VIEW', 'ALTER VIEW', 'CREATE MATERIALIZED VIEW')
    execute function kilnbase.enforce_rls();
