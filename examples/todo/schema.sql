-- Run once:  docker compose exec -T db psql -U postgres < examples/todo/schema.sql
create table if not exists public.todos (
    id bigint generated always as identity primary key,
    owner uuid not null default auth.uid(),
    title text not null check (length(title) between 1 and 200),
    done boolean not null default false,
    created_at timestamptz not null default now()
);

-- Without RLS the table would stay hidden from the API.
alter table public.todos enable row level security;

drop policy if exists own_todos on public.todos;
create policy own_todos on public.todos for all to authenticated
    using (owner = auth.uid())
    with check (owner = auth.uid());

select kilnbase.enable_realtime('public.todos');
notify pgrst, 'reload schema';
