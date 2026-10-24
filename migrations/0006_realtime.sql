-- Change feed: a row trigger publishes only {schema, table, op, pk}; the realtime service re-reads
-- the row as each subscriber, so RLS decides who sees it and NOTIFY's ~8 KB payload limit never
-- applies to row data.
create function kilnbase.notify_change() returns trigger
    language plpgsql
    as $$
declare
    rec jsonb := to_jsonb(case when tg_op = 'DELETE' then old else new end);
    pk jsonb := '{}';
    col text;
    payload text;
begin
    foreach col in array tg_argv loop
        pk := pk || jsonb_build_object(col, rec -> col);
    end loop;
    payload := json_build_object(
        'schema', tg_table_schema, 'table', tg_table_name, 'op', tg_op, 'pk', pk)::text;
    -- Failing here would abort the writer's transaction; dropping one event is the lesser harm.
    if octet_length(payload) < 7900 then
        perform pg_notify('kilnbase_realtime', payload);
    else
        raise warning 'kilnbase realtime: primary key of %.% too large to publish',
            tg_table_schema, tg_table_name;
    end if;
    return null;
end
$$;

create function kilnbase.enable_realtime(target regclass) returns void
    language plpgsql
    as $$
declare
    cols text;
begin
    select string_agg(quote_literal(a.attname), ', ' order by array_position(i.indkey::int2[], a.attnum))
      into cols
      from pg_index i
      join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any(i.indkey)
     where i.indrelid = target and i.indisprimary;
    if cols is null then
        raise exception 'realtime needs a primary key on %', target;
    end if;
    execute format('drop trigger if exists kilnbase_realtime on %s', target);
    execute format(
        'create trigger kilnbase_realtime after insert or update or delete on %s'
        ' for each row execute function kilnbase.notify_change(%s)', target, cols);
end
$$;

create function kilnbase.disable_realtime(target regclass) returns void
    language plpgsql
    as $$
begin
    execute format('drop trigger if exists kilnbase_realtime on %s', target);
end
$$;

revoke all on function kilnbase.enable_realtime(regclass), kilnbase.disable_realtime(regclass)
    from public;
