-- SYNTRIX: initial database schema for Supabase
-- Run once in Supabase Dashboard -> SQL Editor.
-- This migration is intentionally additive; it does not drop existing objects.

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  handle text not null unique
    check (handle ~ '^[a-z0-9_]{3,24}$'),
  display_name text not null
    check (char_length(display_name) between 1 and 60),
  created_at timestamptz not null default now()
);

create table if not exists public.contacts (
  owner_id uuid not null references public.profiles(id) on delete cascade,
  contact_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (owner_id, contact_id),
  constraint contacts_no_self check (owner_id <> contact_id)
);

create index if not exists contacts_contact_id_idx
  on public.contacts (contact_id);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles(id) on delete cascade,
  receiver_id uuid not null references public.profiles(id) on delete cascade,
  payload_bits text not null
    check (
      char_length(payload_bits) between 10 and 5000
      and payload_bits ~ '^[01]+$'
      and mod(char_length(payload_bits), 10) = 0
    ),
  created_at timestamptz not null default now(),
  read_at timestamptz,
  constraint messages_no_self check (sender_id <> receiver_id)
);

create index if not exists messages_sender_created_idx
  on public.messages (sender_id, created_at desc);

create index if not exists messages_receiver_created_idx
  on public.messages (receiver_id, created_at desc);

create index if not exists messages_unread_idx
  on public.messages (receiver_id, sender_id, created_at desc)
  where read_at is null;

create table if not exists private.user_security (
  user_id uuid primary key references auth.users(id) on delete cascade,
  unlock_key_hash text,
  failed_attempts smallint not null default 0
    check (failed_attempts between 0 and 5),
  locked_until timestamptz
);

-- The private schema is not exposed through the Supabase Data API.
revoke all on all tables in schema private from public, anon, authenticated;
revoke all on all sequences in schema private from public, anon, authenticated;

create or replace function public.handle_new_syntrix_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_handle text;
  v_display_name text;
begin
  v_handle := lower(trim(coalesce(new.raw_user_meta_data ->> 'handle', '')));
  v_display_name := trim(coalesce(new.raw_user_meta_data ->> 'display_name', ''));

  if v_handle !~ '^[a-z0-9_]{3,24}$' then
    v_handle := 'user_' || replace(substr(new.id::text, 1, 10), '-', '');
  end if;

  if v_display_name = '' then
    v_display_name := coalesce(nullif(split_part(coalesce(new.email, ''), '@', 1), ''), 'SYNTRIX User');
  end if;

  insert into public.profiles (id, handle, display_name)
  values (new.id, v_handle, left(v_display_name, 60));

  insert into private.user_security (user_id)
  values (new.id)
  on conflict (user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created_syntrix on auth.users;
create trigger on_auth_user_created_syntrix
  after insert on auth.users
  for each row execute function public.handle_new_syntrix_user();

alter table public.profiles enable row level security;
alter table public.contacts enable row level security;
alter table public.messages enable row level security;

-- Explicit grants are required when Data API table exposure is restricted.
grant usage on schema public to authenticated;
revoke all on public.profiles from anon, authenticated;
grant select (id, handle, display_name, created_at)
  on public.profiles to authenticated;

revoke all on public.contacts from anon, authenticated;
grant select (owner_id, contact_id, created_at),
      insert (owner_id, contact_id),
      delete
  on public.contacts to authenticated;

revoke all on public.messages from anon, authenticated;
grant select (id, sender_id, receiver_id, payload_bits, created_at, read_at),
      insert (sender_id, receiver_id, payload_bits),
      update (read_at)
  on public.messages to authenticated;

drop policy if exists "Signed-in users can discover public profile cards" on public.profiles;
create policy "Signed-in users can discover public profile cards"
  on public.profiles for select
  to authenticated
  using ((select auth.uid()) is not null);

drop policy if exists "Users can read their own contacts" on public.contacts;
create policy "Users can read their own contacts"
  on public.contacts for select
  to authenticated
  using ((select auth.uid()) = owner_id);

drop policy if exists "Users can add their own contacts" on public.contacts;
create policy "Users can add their own contacts"
  on public.contacts for insert
  to authenticated
  with check (
    (select auth.uid()) = owner_id
    and contact_id <> (select auth.uid())
  );

drop policy if exists "Users can remove their own contacts" on public.contacts;
create policy "Users can remove their own contacts"
  on public.contacts for delete
  to authenticated
  using ((select auth.uid()) = owner_id);

drop policy if exists "Participants can read their messages" on public.messages;
create policy "Participants can read their messages"
  on public.messages for select
  to authenticated
  using (
    (select auth.uid()) = sender_id
    or (select auth.uid()) = receiver_id
  );

drop policy if exists "A user can send to a contact" on public.messages;
create policy "A user can send to a contact"
  on public.messages for insert
  to authenticated
  with check (
    (select auth.uid()) = sender_id
    and receiver_id <> (select auth.uid())
    and exists (
      select 1
      from public.contacts c
      where c.owner_id = (select auth.uid())
        and c.contact_id = receiver_id
    )
  );

drop policy if exists "Only the receiver can mark a message as read" on public.messages;
create policy "Only the receiver can mark a message as read"
  on public.messages for update
  to authenticated
  using (
    (select auth.uid()) = receiver_id
    and read_at is null
  )
  with check (
    (select auth.uid()) = receiver_id
    and read_at is not null
  );

-- Unlock keys are bcrypt hashes held in a private schema. They are not
-- message encryption keys; they are a separate per-account viewing check.
create or replace function public.set_message_unlock_key(p_key text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  if p_key is null or char_length(p_key) < 6 or octet_length(p_key) > 72 then
    raise exception 'Kunci harus minimal 6 karakter dan maksimal 72 byte';
  end if;

  insert into private.user_security (user_id, unlock_key_hash, failed_attempts, locked_until)
  values (v_user_id, extensions.crypt(p_key, extensions.gen_salt('bf', 12)), 0, null)
  on conflict (user_id) do update
    set unlock_key_hash = excluded.unlock_key_hash,
        failed_attempts = 0,
        locked_until = null;
end;
$$;

create or replace function public.has_message_unlock_key()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from private.user_security s
    where s.user_id = auth.uid()
      and s.unlock_key_hash is not null
  );
$$;

create or replace function public.verify_message_unlock_key(p_key text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_hash text;
  v_failed smallint;
  v_locked_until timestamptz;
  v_new_failed integer;
begin
  if v_user_id is null or p_key is null then
    return false;
  end if;

  select s.unlock_key_hash, s.failed_attempts, s.locked_until
    into v_hash, v_failed, v_locked_until
  from private.user_security s
  where s.user_id = v_user_id
  for update;

  if not found or v_hash is null then
    return false;
  end if;

  if v_locked_until is not null and v_locked_until > now() then
    return false;
  end if;

  if octet_length(p_key) > 72 then
    v_new_failed := 5;
  elsif extensions.crypt(p_key, v_hash) = v_hash then
    update private.user_security
      set failed_attempts = 0, locked_until = null
      where user_id = v_user_id;
    return true;
  else
    v_new_failed := coalesce(v_failed, 0) + 1;
  end if;

  update private.user_security
    set failed_attempts = case when v_new_failed >= 5 then 0 else v_new_failed end,
        locked_until = case
          when v_new_failed >= 5 then now() + interval '5 minutes'
          else null
        end
    where user_id = v_user_id;

  return false;
end;
$$;

revoke all on function public.handle_new_syntrix_user() from public, anon, authenticated;
revoke all on function public.set_message_unlock_key(text) from public, anon;
revoke all on function public.has_message_unlock_key() from public, anon;
revoke all on function public.verify_message_unlock_key(text) from public, anon;

grant execute on function public.set_message_unlock_key(text) to authenticated;
grant execute on function public.has_message_unlock_key() to authenticated;
grant execute on function public.verify_message_unlock_key(text) to authenticated;

-- Private Presence topic for the app-wide online user list.
-- Also disable "Allow public access" in Supabase Dashboard -> Realtime -> Settings.
drop policy if exists "Authenticated users can read SYNTRIX presence" on realtime.messages;
create policy "Authenticated users can read SYNTRIX presence"
  on realtime.messages for select
  to authenticated
  using (
    realtime.topic() = 'syntrix:live'
    and extension = 'presence'
  );

drop policy if exists "Authenticated users can publish SYNTRIX presence" on realtime.messages;
create policy "Authenticated users can publish SYNTRIX presence"
  on realtime.messages for insert
  to authenticated
  with check (
    realtime.topic() = 'syntrix:live'
    and extension = 'presence'
  );

-- Ensure message INSERT/UPDATE changes are available to Supabase Realtime.
do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;
end;
$$;
