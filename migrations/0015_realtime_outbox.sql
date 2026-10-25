-- Short-lived outbox of row changes: lets the realtime service replay what it missed while its LISTEN
-- connection was down, and lets clients resume from their last event id. Rows hold only keys, never data.
-- shortcut: one extra insert per write on realtime-enabled tables; switch to logical replication
-- (pgoutput + a slot) if that write amplification ever matters.
create table kilnbase.realtime_events (
    id bigint generated always as identity primary key,
    schema_name text not null,
    table_name text not null,
    op text not null,
    pk jsonb not null,
    created_at timestamptz not null default now()
);
create index realtime_events_created_at_idx on kilnbase.realtime_events (created_at);

-- Read and pruned by the realtime service through service_role; API exposure stays off because the
-- kilnbase schema is never served by PostgREST.
grant usage on schema kilnbase to service_role;
grant select, delete on kilnbase.realtime_events to service_role;

-- Runs as its owner so writers need no grant on the outbox; search_path is pinned for that reason.
create or replace function kilnbase.notify_change() returns trigger
    language plpgsql
    security definer
    set search_path = pg_catalog, kilnbase
    as $$
declare
    rec jsonb := to_jsonb(case when tg_op = 'DELETE' then old else new end);
    pk jsonb := '{}';
    col text;
    event_id bigint;
    payload text;
begin
    foreach col in array tg_argv loop
        pk := pk || jsonb_build_object(col, rec -> col);
    end loop;
    if octet_length(pk::text) > 7000 then
        -- Failing here would abort the writer's transaction; dropping one event is the lesser harm.
        raise warning 'kilnbase realtime: primary key of %.% too large to publish',
            tg_table_schema, tg_table_name;
        return null;
    end if;
    insert into kilnbase.realtime_events (schema_name, table_name, op, pk)
        values (tg_table_schema, tg_table_name, tg_op, pk)
        returning id into event_id;
    payload := json_build_object('id', event_id, 'schema', tg_table_schema, 'table', tg_table_name,
                                 'op', tg_op, 'pk', pk)::text;
    perform pg_notify('kilnbase_realtime', payload);
    return null;
end
$$;
revoke all on function kilnbase.notify_change() from public;
