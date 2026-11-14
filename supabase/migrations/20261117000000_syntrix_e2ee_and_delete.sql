-- SYNTRIX: end-to-end encryption + message deletion (additive).
-- Run once in the Supabase SQL Editor, AFTER 20261116000000_syntrix_device_security_v2.sql.
--
-- E2EE model
--   * Every user has an ECDH P-256 key pair made in the browser. The public key is
--     stored in profiles.public_key. The private key never leaves the browser in
--     clear text; only an AES-GCM wrapped backup is stored (private.user_security).
--   * The user's passphrase never reaches the server. The browser derives two
--     independent values from it: an "auth token" (sent here, bcrypt-hashed, rate
--     limited with the existing lockout logic) and a wrap key (stays in the browser).
--   * payload_bits of an E2EE message is the framed bitstream of a base64 AES-GCM
--     envelope, so the server only ever stores ciphertext.
--
-- Deletion model (private 1:1 chats, like Telegram)
--   * "Hapus untuk saya"   -> row in message_hidden (only hides it for that user).
--   * "Hapus untuk semua"  -> payload wiped + deleted_at set; either participant may do
--                             it, for their own messages and for the other person's.

-- ---------------------------------------------------------------------
-- 1. E2EE storage
-- ---------------------------------------------------------------------
alter table public.profiles add column if not exists public_key text;

alter table public.profiles drop constraint if exists profiles_public_key_format;
alter table public.profiles
  add constraint profiles_public_key_format
  check (
    public_key is null
    or (char_length(public_key) between 80 and 200 and public_key ~ '^[A-Za-z0-9+/]+={0,2}$')
  );

grant select (public_key) on public.profiles to authenticated;

alter table private.user_security
  add column if not exists e2ee_salt text,
  add column if not exists e2ee_wrapped_key text,
  add column if not exists e2ee_iterations integer,
  add column if not exists e2ee_enabled_at timestamptz;

-- ---------------------------------------------------------------------
-- 2. Messages: encryption version, tombstone columns, relaxed payload checks
-- ---------------------------------------------------------------------
alter table public.messages
  add column if not exists enc_version smallint not null default 0,
  add column if not exists deleted_at timestamptz,
  add column if not exists deleted_by uuid references public.profiles(id) on delete set null;

alter table public.messages drop constraint if exists messages_enc_version_check;
alter table public.messages
  add constraint messages_enc_version_check check (enc_version in (0, 1));

-- A deleted message keeps its row (so Realtime can tell the other side) but loses its payload.
alter table public.messages alter column payload_bits drop not null;

-- Drop the old size check (<= 5000 bits), whatever it is named, and replace it.
do $$
declare
  r record;
begin
  for r in
    select c.conname
    from pg_constraint c
    where c.conrelid = 'public.messages'::regclass
      and c.contype = 'c'
      and pg_get_constraintdef(c.oid) ilike '%5000%'
  loop
    execute format('alter table public.messages drop constraint %I', r.conname);
  end loop;
end;
$$;

-- E2EE envelopes are base64 and longer than plain ASCII frames: up to 1500 frames.
alter table public.messages drop constraint if exists messages_payload_size_check;
alter table public.messages
  add constraint messages_payload_size_check
  check (
    payload_bits is null
    or (
      char_length(payload_bits) between 10 and 15000
      and payload_bits ~ '^[01]+$'
      and mod(char_length(payload_bits), 10) = 0
    )
  );

alter table public.messages drop constraint if exists messages_valid_frames;
alter table public.messages
  add constraint messages_valid_frames
  check (payload_bits is null or public.is_valid_syntrix_bits(payload_bits)) not valid;

grant select (enc_version, deleted_at) on public.messages to authenticated;
grant insert (enc_version) on public.messages to authenticated;

-- From now on every new message must be end-to-end encrypted, and both people
-- must have published a public key. (The server cannot verify the ciphertext
-- itself; this only stops plaintext framing from being used by accident.)
create or replace function private.messages_require_e2ee()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.enc_version is distinct from 1 then
    raise exception 'e2ee_required';
  end if;
  if new.payload_bits is null then
    raise exception 'empty_payload';
  end if;
  if (
    select count(*) from public.profiles p
    where p.id in (new.sender_id, new.receiver_id) and p.public_key is not null
  ) < 2 then
    raise exception 'e2ee_not_ready';
  end if;
  return new;
end;
$$;
revoke all on function private.messages_require_e2ee() from public, anon, authenticated;

drop trigger if exists messages_require_e2ee on public.messages;
create trigger messages_require_e2ee
  before insert on public.messages
  for each row execute function private.messages_require_e2ee();

-- ---------------------------------------------------------------------
-- 3. E2EE functions
-- ---------------------------------------------------------------------
create or replace function public.get_e2ee_state()
returns table (
  enabled boolean,
  has_legacy_key boolean,
  salt text,
  iterations integer,
  public_key text
)
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.assert_active_session();
  return query
    select (s.e2ee_wrapped_key is not null),
           (s.unlock_key_hash is not null and s.e2ee_wrapped_key is null),
           s.e2ee_salt,
           s.e2ee_iterations,
           p.public_key
      from private.user_security s
      join public.profiles p on p.id = s.user_id
     where s.user_id = auth.uid();
end;
$$;

-- First-time activation. A user who still has an old (pre-E2EE) unlock key must prove it,
-- so a stolen login cannot simply replace the key that protects old messages.
create or replace function public.enable_e2ee(
  p_old_key text,
  p_auth text,
  p_public_key text,
  p_wrapped text,
  p_salt text,
  p_iterations integer
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_row private.user_security%rowtype;
begin
  perform private.assert_active_session();

  if p_auth is null or char_length(p_auth) < 20 or octet_length(p_auth) > 72
     or p_public_key is null or char_length(p_public_key) not between 80 and 200
     or p_public_key !~ '^[A-Za-z0-9+/]+={0,2}$'
     or p_wrapped is null or char_length(p_wrapped) not between 60 and 4096
     or p_wrapped !~ '^[A-Za-z0-9+/]+={0,2}$'
     or p_salt is null or char_length(p_salt) not between 20 and 64
     or p_salt !~ '^[A-Za-z0-9+/]+={0,2}$'
     or p_iterations is null or p_iterations not between 100000 and 5000000 then
    raise exception 'invalid_e2ee_payload';
  end if;

  insert into private.user_security (user_id) values (v_uid)
  on conflict (user_id) do nothing;

  select * into v_row from private.user_security where user_id = v_uid for update;

  if v_row.e2ee_wrapped_key is not null then
    raise exception 'e2ee_already_enabled';
  end if;

  if v_row.unlock_key_hash is not null and not private.check_unlock_key(v_uid, p_old_key) then
    return false;
  end if;

  update private.user_security
     set unlock_key_hash = extensions.crypt(p_auth, extensions.gen_salt('bf', 12)),
         failed_attempts = 0, lockouts = 0, locked_until = null,
         e2ee_salt = p_salt, e2ee_wrapped_key = p_wrapped,
         e2ee_iterations = p_iterations, e2ee_enabled_at = now()
   where user_id = v_uid;

  update public.profiles set public_key = p_public_key where id = v_uid;
  return true;
end;
$$;

-- Releases the wrapped private key only after the auth token passes the lockout check.
create or replace function public.get_e2ee_backup(p_auth text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_wrapped text;
begin
  perform private.assert_active_session();
  if not private.check_unlock_key(v_uid, p_auth) then
    return null;
  end if;
  select s.e2ee_wrapped_key into v_wrapped
    from private.user_security s where s.user_id = v_uid;
  return v_wrapped;
end;
$$;

-- Changing the passphrase re-wraps the same private key; the public key stays the same.
create or replace function public.change_e2ee_passphrase(
  p_old_auth text,
  p_new_auth text,
  p_new_wrapped text,
  p_new_salt text,
  p_iterations integer
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  perform private.assert_active_session();

  if p_new_auth is null or char_length(p_new_auth) < 20 or octet_length(p_new_auth) > 72
     or p_new_wrapped is null or char_length(p_new_wrapped) not between 60 and 4096
     or p_new_wrapped !~ '^[A-Za-z0-9+/]+={0,2}$'
     or p_new_salt is null or char_length(p_new_salt) not between 20 and 64
     or p_new_salt !~ '^[A-Za-z0-9+/]+={0,2}$'
     or p_iterations is null or p_iterations not between 100000 and 5000000 then
    raise exception 'invalid_e2ee_payload';
  end if;

  if not exists (
    select 1 from private.user_security s
    where s.user_id = v_uid and s.e2ee_wrapped_key is not null
  ) then
    raise exception 'e2ee_not_enabled';
  end if;

  if not private.check_unlock_key(v_uid, p_old_auth) then
    return false;
  end if;

  update private.user_security
     set unlock_key_hash = extensions.crypt(p_new_auth, extensions.gen_salt('bf', 12)),
         e2ee_salt = p_new_salt, e2ee_wrapped_key = p_new_wrapped,
         e2ee_iterations = p_iterations,
         failed_attempts = 0, lockouts = 0, locked_until = null
   where user_id = v_uid;
  return true;
end;
$$;

-- Ciphertext of E2EE messages needs no key check: it is useless without the private key.
-- Legacy (enc_version = 0) messages still go through get_message_bits() and its key check.
create or replace function public.get_message_payloads(p_ids uuid[])
returns table (id uuid, payload_bits text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  perform private.assert_active_session();
  if p_ids is null or cardinality(p_ids) > 500 then
    raise exception 'too_many_ids';
  end if;
  return query
    select m.id, m.payload_bits
      from public.messages m
     where m.id = any (p_ids)
       and m.enc_version = 1
       and m.deleted_at is null
       and (m.sender_id = v_uid or m.receiver_id = v_uid);
end;
$$;

-- The profile lookup now also returns the public key.
drop function if exists public.find_profile_by_handle(text);
create function public.find_profile_by_handle(p_handle text)
returns table (id uuid, handle text, display_name text, public_key text)
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
    select p.id, p.handle, p.display_name, p.public_key
    from public.profiles p
    where p.handle = v_handle;
end;
$$;

-- The old raw-key functions would desynchronise the key from the wrapped private key.
-- Activation and passphrase changes now go through enable_e2ee / change_e2ee_passphrase.
revoke execute on function public.set_message_unlock_key(text) from authenticated;
revoke execute on function public.change_message_unlock_key(text, text) from authenticated;

-- ---------------------------------------------------------------------
-- 4. Message deletion
-- ---------------------------------------------------------------------
create table if not exists public.message_hidden (
  user_id uuid not null references public.profiles(id) on delete cascade,
  message_id uuid not null references public.messages(id) on delete cascade,
  hidden_at timestamptz not null default now(),
  primary key (user_id, message_id)
);
create index if not exists message_hidden_message_idx on public.message_hidden (message_id);

alter table public.message_hidden enable row level security;
revoke all on public.message_hidden from anon, authenticated;
grant select (user_id, message_id, hidden_at) on public.message_hidden to authenticated;

drop policy if exists "Users can read their own hidden messages" on public.message_hidden;
create policy "Users can read their own hidden messages"
  on public.message_hidden for select
  to authenticated
  using ((select auth.uid()) = user_id);

-- "Hapus untuk saya"
create or replace function public.hide_message_for_me(p_message_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_count integer;
begin
  perform private.assert_active_session();
  perform private.enforce_rate_limit(v_uid, 'delete', 60, interval '1 minute');

  insert into public.message_hidden (user_id, message_id)
  select v_uid, m.id
    from public.messages m
   where m.id = p_message_id
     and (m.sender_id = v_uid or m.receiver_id = v_uid)
  on conflict do nothing;
  get diagnostics v_count = row_count;
  return v_count > 0;
end;
$$;

-- "Hapus untuk semua": either participant, own or the other person's message.
create or replace function public.delete_message_for_everyone(p_message_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_count integer;
begin
  perform private.assert_active_session();
  perform private.enforce_rate_limit(v_uid, 'delete', 60, interval '1 minute');

  update public.messages
     set payload_bits = null, deleted_at = now(), deleted_by = v_uid
   where id = p_message_id
     and deleted_at is null
     and (sender_id = v_uid or receiver_id = v_uid);
  get diagnostics v_count = row_count;
  return v_count > 0;
end;
$$;

revoke all on function
  public.get_e2ee_state(),
  public.enable_e2ee(text, text, text, text, text, integer),
  public.get_e2ee_backup(text),
  public.change_e2ee_passphrase(text, text, text, text, integer),
  public.get_message_payloads(uuid[]),
  public.find_profile_by_handle(text),
  public.hide_message_for_me(uuid),
  public.delete_message_for_everyone(uuid)
  from public, anon;
grant execute on function
  public.get_e2ee_state(),
  public.enable_e2ee(text, text, text, text, text, integer),
  public.get_e2ee_backup(text),
  public.change_e2ee_passphrase(text, text, text, text, integer),
  public.get_message_payloads(uuid[]),
  public.find_profile_by_handle(text),
  public.hide_message_for_me(uuid),
  public.delete_message_for_everyone(uuid)
  to authenticated;

-- ---------------------------------------------------------------------
-- 5. Realtime: publish deleted_at / enc_version, and the per-user hidden list
--    (the other participant gets deleted_at as an UPDATE, which RLS lets through).
-- ---------------------------------------------------------------------
do $$
begin
  if exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages'
  ) then
    alter publication supabase_realtime drop table public.messages;
  end if;
  alter publication supabase_realtime
    add table public.messages (id, sender_id, receiver_id, created_at, read_at, deleted_at, enc_version);

  if exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'message_hidden'
  ) then
    alter publication supabase_realtime drop table public.message_hidden;
  end if;
  alter publication supabase_realtime
    add table public.message_hidden (user_id, message_id);
end;
$$;