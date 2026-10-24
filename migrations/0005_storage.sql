create schema storage;
grant usage on schema storage to anon, authenticated, service_role;

-- "public" and "sign" are path segments of the storage API, so they cannot be bucket names.
create table storage.buckets (
    id text primary key
        check (id ~ '^[a-z0-9][a-z0-9._-]{0,62}$' and id not in ('public', 'sign')),
    public boolean not null default false,
    file_size_limit bigint check (file_size_limit > 0),
    allowed_mime_types text[],
    created_at timestamptz not null default now()
);

-- Access to a file is exactly access to its row here: write policies on this table to share files.
create table storage.objects (
    id uuid primary key default gen_random_uuid(),
    bucket_id text not null references storage.buckets on delete restrict,
    name text not null check (length(name) between 1 and 1024),
    owner uuid default auth.uid(),
    size bigint not null check (size >= 0),
    mime_type text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (bucket_id, name)
);

alter table storage.buckets enable row level security;
alter table storage.objects enable row level security;

-- Grants only open the door; with no policies RLS still denies every row.
grant select on storage.buckets to anon, authenticated;
grant select, insert, update, delete on storage.objects to anon, authenticated;
grant all on storage.buckets, storage.objects to service_role;
