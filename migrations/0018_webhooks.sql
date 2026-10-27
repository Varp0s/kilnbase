-- Database webhooks: a row trigger queues one delivery per matching webhook in the same transaction as
-- the write (a rolled-back write sends nothing), and the auth service's worker POSTs them with retries.
-- The deliveries table is both the queue and the delivery log. Only superusers manage webhooks; the
-- kilnbase schema is never served by the API.
create table kilnbase.webhooks (
    id bigint generated always as identity primary key,
    name text not null unique,
    table_name regclass not null,
    events text[] not null check (events <@ array['INSERT', 'UPDATE', 'DELETE'] and events <> '{}'),
    url text not null check (url ~ '^https?://'),
    -- HMAC-SHA256 key for the X-Kilnbase-Signature header.
    -- Two v4 UUIDs (pg_strong_random, 244 bits) hashed; pgcrypto is not needed.
    secret text not null default encode(sha256((gen_random_uuid()::text || gen_random_uuid()::text)::bytea), 'hex'),
    max_attempts int not null default 8 check (max_attempts between 1 and 50),
    enabled boolean not null default true,
    created_at timestamptz not null default now()
);

create table kilnbase.webhook_deliveries (
    id bigint generated always as identity primary key,
    webhook_id bigint not null references kilnbase.webhooks on delete cascade,
    payload jsonb not null,
    status text not null default 'pending' check (status in ('pending', 'delivered', 'failed')),
    attempts int not null default 0,
    next_attempt_at timestamptz not null default now(),
    last_status int,
    last_error text,
    created_at timestamptz not null default now(),
    delivered_at timestamptz
);
create index webhook_deliveries_due_idx on kilnbase.webhook_deliveries (next_attempt_at)
    where status = 'pending';

-- Runs as its owner so writers need no grant on the queue; search_path is pinned for that reason.
create function kilnbase.enqueue_webhooks() returns trigger
    language plpgsql security definer set search_path = pg_catalog, kilnbase
    as $$
begin
    insert into kilnbase.webhook_deliveries (webhook_id, payload)
    select w.id, jsonb_build_object(
               'type', tg_op,
               'schema', tg_table_schema,
               'table', tg_table_name,
               'record', case when tg_op = 'DELETE' then null else to_jsonb(new) end,
               'old_record', case when tg_op = 'INSERT' then null else to_jsonb(old) end)
      from kilnbase.webhooks w
     where w.table_name = tg_relid and w.enabled and tg_op = any (w.events);
    return null;
end
$$;

create function kilnbase.create_webhook(
    name text, target regclass, events text[], url text, secret text default null
) returns kilnbase.webhooks
    language plpgsql
    as $$
declare
    hook kilnbase.webhooks;
begin
    insert into kilnbase.webhooks (name, table_name, events, url, secret)
    values (name, target, events, url,
            coalesce(secret, encode(sha256((gen_random_uuid()::text || gen_random_uuid()::text)::bytea), 'hex')))
    returning * into hook;
    execute format('create or replace trigger kilnbase_webhooks after insert or update or delete '
                   'on %s for each row execute function kilnbase.enqueue_webhooks()', target);
    return hook;
end
$$;

create function kilnbase.drop_webhook(webhook_name text) returns void
    language plpgsql
    as $$
declare
    target regclass;
begin
    delete from kilnbase.webhooks where name = webhook_name returning table_name into target;
    if target is not null
       and not exists (select from kilnbase.webhooks where table_name = target) then
        execute format('drop trigger if exists kilnbase_webhooks on %s', target);
    end if;
end
$$;

revoke execute on function kilnbase.enqueue_webhooks(), kilnbase.create_webhook(text, regclass, text[], text, text),
    kilnbase.drop_webhook(text) from public;
