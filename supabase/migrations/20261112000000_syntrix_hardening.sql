-- SYNTRIX hardening migration (additive). Run once in Supabase SQL Editor,
-- AFTER 20261111122920_syntrix_initial_schema.sql.

-- ---------------------------------------------------------------------
-- 0. Private helpers: escalating lockout state + generic rate limiter
-- ---------------------------------------------------------------------
alter table private.user_security
  add column if not exists lockouts smallint not null default 0;

create table if not exists private.rate_events (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  kind text not null,
  created_at timestamptz not null default now()
);
create index if not exists rate_events_lookup_idx
  on private.rate_events (user_id, kind, created_at desc);
revoke all on private.rate_events from public, anon, authenticated;
revoke all on all sequences in schema private from public, anon, authenticated;

create or replace function private.enforce_rate_limit(
  p_user uuid, p_kind text, p_max integer, p_window interval
) returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_count integer;
begin
  select count(*) into v_count
  from private.rate_events
  where user_id = p_user and kind = p_kind and created_at > now() - p_window;

  if v_count >= p_max then
    raise exception 'rate_limited' using errcode = 'P0001';
  end if;

  insert into private.rate_events (user_id, kind) values (p_user, p_kind);
  delete from private.rate_events
  where user_id = p_user and kind = p_kind and created_at < now() - interval '1 day';
end;
$$;
revoke all on function private.enforce_rate_limit(uuid, text, integer, interval) from public, anon, authenticated;

-- ---------------------------------------------------------------------
-- 1. Server-side validation of message frames (start/stop/parity/printable)
-- ---------------------------------------------------------------------
create or replace function public.is_valid_syntrix_bits(p_bits text)
returns boolean
language plpgsql
immutable
set search_path = ''
as $$
declare
  i integer;
  v_frame text;
  v_data text;
  v_code integer;
begin
  if p_bits is null or p_bits !~ '^[01]+$' or length(p_bits) % 10 <> 0 then
    return false;
  end if;

  for i in 0 .. (length(p_bits) / 10 - 1) loop
    v_frame := substr(p_bits, i * 10 + 1, 10);
    if substr(v_frame, 1, 1) <> '0' or substr(v_frame, 10, 1) <> '1' then
      return false;
    end if;
    v_data := substr(v_frame, 2, 7);
    if (length(v_data) - length(replace(v_data, '1', ''))) % 2 <> substr(v_frame, 9, 1)::integer then
      return false;
    end if;
    v_code := v_data::bit(7)::integer;
    if v_code < 32 or v_code > 126 then
      return false;
    end if;
  end loop;
  return true;
end;
$$;
revoke all on function public.is_valid_syntrix_bits(text) from public, anon;
grant execute on function public.is_valid_syntrix_bits(text) to authenticated;

alter table public.messages drop constraint if exists messages_valid_frames;
alter table public.messages
  add constraint messages_valid_frames
  check (public.is_valid_syntrix_bits(payload_bits)) not valid;

-- ---------------------------------------------------------------------
-- 2. payload_bits is no longer readable through the Data API / Realtime.
--    It is only returned by get_message_bits() after the unlock key passes.
-- ---------------------------------------------------------------------
alter table public.messages
  add column if not exists frame_count integer
  generated always as (char_length(payload_bits) / 10) stored;

revoke select (payload_bits) on public.messages from authenticated;
grant select (id, sender_id, receiver_id, frame_count, created_at, read_at)
  on public.messages to authenticated;

do $$
begin
  if exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages'
  ) then
    alter publication supabase_realtime drop table public.messages;
  end if;
  alter publication supabase_realtime
    add table public.messages (id, sender_id, receiver_id, created_at, read_at);
end;
$$;

-- ---------------------------------------------------------------------
-- 3. Rate limits and server-controlled read receipts
-- ---------------------------------------------------------------------
create or replace function private.messages_before_insert()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.enforce_rate_limit(new.sender_id, 'message', 30, interval '1 minute');
  return new;
end;
$$;

drop trigger if exists messages_rate_limit on public.messages;
create trigger messages_rate_limit
  before insert on public.messages
  for each row execute function private.messages_before_insert();

create or replace function private.contacts_before_insert()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  -- Re-saving an existing contact is harmless and must not consume quota.
  if exists (
    select 1 from public.contacts c
    where c.owner_id = new.owner_id and c.contact_id = new.contact_id
  ) then
    return new;
  end if;
  perform private.enforce_rate_limit(new.owner_id, 'contact', 100, interval '1 hour');
  return new;
end;
$$;

drop trigger if exists contacts_rate_limit on public.contacts;
create trigger contacts_rate_limit
  before insert on public.contacts
  for each row execute function private.contacts_before_insert();

create or replace function private.messages_before_update()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.read_at is null and new.read_at is not null then
    new.read_at := now();
  end if;
  return new;
end;
$$;

drop trigger if exists messages_read_receipt on public.messages;
create trigger messages_read_receipt
  before update on public.messages
  for each row execute function private.messages_before_update();

-- ---------------------------------------------------------------------
-- 4. Profiles: no more open directory
-- ---------------------------------------------------------------------
drop policy if exists "Signed-in users can discover public profile cards" on public.profiles;
drop policy if exists "Users can read own and related profiles" on public.profiles;
create policy "Users can read own and related profiles"
  on public.profiles for select
  to authenticated
  using (
    id = (select auth.uid())
    or exists (
      select 1 from public.contacts c
      where c.owner_id = (select auth.uid()) and c.contact_id = profiles.id
    )
    or exists (
      select 1 from public.messages m
      where m.receiver_id = (select auth.uid()) and m.sender_id = profiles.id
    )
  );

create or replace function public.find_profile_by_handle(p_handle text)
returns table (id uuid, handle text, display_name text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_handle text := lower(trim(coalesce(p_handle, '')));
begin
  if v_uid is null then
    raise exception 'Authentication required';
  end if;
  if v_handle !~ '^[a-z0-9_]{3,24}$' then
    return;
  end if;
  perform private.enforce_rate_limit(v_uid, 'lookup', 20, interval '1 minute');
  return query
    select p.id, p.handle, p.display_name
    from public.profiles p
    where p.handle = v_handle;
end;
$$;

-- ---------------------------------------------------------------------
-- 5. Unlock key: escalating lockout, old key required to change,
--    and the key now gates access to payload_bits on the server.
-- ---------------------------------------------------------------------
create or replace function private.check_unlock_key(p_user uuid, p_key text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_hash text;
  v_failed smallint;
  v_locked timestamptz;
  v_lockouts smallint;
  v_new_failed integer;
  v_minutes integer;
begin
  if p_user is null or p_key is null then
    return false;
  end if;

  select s.unlock_key_hash, s.failed_attempts, s.locked_until, s.lockouts
    into v_hash, v_failed, v_locked, v_lockouts
  from private.user_security s
  where s.user_id = p_user
  for update;

  if not found or v_hash is null then
    return false;
  end if;
  if v_locked is not null and v_locked > now() then
    return false;
  end if;

  if octet_length(p_key) <= 72 and extensions.crypt(p_key, v_hash) = v_hash then
    update private.user_security
      set failed_attempts = 0, lockouts = 0, locked_until = null
      where user_id = p_user;
    return true;
  end if;

  v_new_failed := coalesce(v_failed, 0) + 1;
  if v_new_failed >= 5 then
    -- 5, 10, 20, 40 ... minutes, capped at 24 hours.
    v_minutes := least(5 * (2 ^ least(coalesce(v_lockouts, 0), 8))::integer, 1440);
    update private.user_security
      set failed_attempts = 0,
          lockouts = least(coalesce(v_lockouts, 0) + 1, 10),
          locked_until = now() + make_interval(mins => v_minutes)
      where user_id = p_user;
  else
    update private.user_security
      set failed_attempts = v_new_failed
      where user_id = p_user;
  end if;
  return false;
end;
$$;
revoke all on function private.check_unlock_key(uuid, text) from public, anon, authenticated;

create or replace function public.verify_message_unlock_key(p_key text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  return private.check_unlock_key(auth.uid(), p_key);
end;
$$;

-- First-time setup only. Changing an existing key needs the old key.
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
  if exists (
    select 1 from private.user_security s
    where s.user_id = v_user_id and s.unlock_key_hash is not null
  ) then
    raise exception 'Kunci sudah ada. Gunakan fitur ganti kunci.';
  end if;

  insert into private.user_security (user_id, unlock_key_hash, failed_attempts, lockouts, locked_until)
  values (v_user_id, extensions.crypt(p_key, extensions.gen_salt('bf', 12)), 0, 0, null)
  on conflict (user_id) do update
    set unlock_key_hash = excluded.unlock_key_hash,
        failed_attempts = 0, lockouts = 0, locked_until = null;
end;
$$;

create or replace function public.change_message_unlock_key(p_old_key text, p_new_key text)
returns boolean
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
  if p_new_key is null or char_length(p_new_key) < 6 or octet_length(p_new_key) > 72 then
    raise exception 'Kunci harus minimal 6 karakter dan maksimal 72 byte';
  end if;
  if not private.check_unlock_key(v_user_id, p_old_key) then
    return false;
  end if;

  update private.user_security
    set unlock_key_hash = extensions.crypt(p_new_key, extensions.gen_salt('bf', 12)),
        failed_attempts = 0, lockouts = 0, locked_until = null
    where user_id = v_user_id;
  return true;
end;
$$;

-- Returns the stored bitstream only to a participant who proves the key.
create or replace function public.get_message_bits(p_message_id uuid, p_key text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_bits text;
begin
  if v_user_id is null then
    return null;
  end if;

  select m.payload_bits into v_bits
  from public.messages m
  where m.id = p_message_id
    and (m.sender_id = v_user_id or m.receiver_id = v_user_id);
  if not found then
    return null;
  end if;

  if not private.check_unlock_key(v_user_id, p_key) then
    return null;
  end if;
  return v_bits;
end;
$$;

revoke all on function public.find_profile_by_handle(text) from public, anon;
revoke all on function public.change_message_unlock_key(text, text) from public, anon;
revoke all on function public.get_message_bits(uuid, text) from public, anon;
revoke all on function public.verify_message_unlock_key(text) from public, anon;
revoke all on function public.set_message_unlock_key(text) from public, anon;
grant execute on function public.find_profile_by_handle(text) to authenticated;
grant execute on function public.change_message_unlock_key(text, text) to authenticated;
grant execute on function public.get_message_bits(uuid, text) to authenticated;
grant execute on function public.verify_message_unlock_key(text) to authenticated;
grant execute on function public.set_message_unlock_key(text) to authenticated;

-- ---------------------------------------------------------------------
-- 6. Reserved handles cannot be claimed at signup
-- ---------------------------------------------------------------------
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

  if v_handle !~ '^[a-z0-9_]{3,24}$'
     or v_handle = any (array[
       'admin', 'administrator', 'root', 'support', 'syntrix', 'system',
       'official', 'moderator', 'staff', 'help', 'security', 'null', 'undefined'
     ]) then
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
revoke all on function public.handle_new_syntrix_user() from public, anon, authenticated;
