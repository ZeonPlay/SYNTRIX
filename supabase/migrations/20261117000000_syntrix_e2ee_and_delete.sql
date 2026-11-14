-- SYNTRIX end-to-end encryption + message deletion.
-- Run once in the Supabase SQL Editor, AFTER 20261116000000_syntrix_device_security_v2.sql.
--
-- What changes:
-- 1. Every existing message is DELETED. Old messages were stored without E2EE
--    and cannot be decrypted by the new client, so they are removed.
-- 2. Each user has a public key (profiles.public_key) and a wrapped private key
--    (private.user_keys). The private key is encrypted in the browser with the
--    unlock key; the server never receives the unlock key or the plain key.
-- 3. payload_bits now holds ciphertext, so participants may read it directly
--    (RLS still limits it to sender and receiver). The old server-side
--    bcrypt unlock-key check is removed because it cannot protect E2EE data.
-- 4. Either participant can delete any message in their conversation. The row
--    is removed for good, and Realtime tells the other browser.

-- ---------------------------------------------------------------------
-- 1. Wipe old plaintext-era messages
-- ---------------------------------------------------------------------
delete from public.messages;

-- ---------------------------------------------------------------------
-- 2. Key storage
-- ---------------------------------------------------------------------
alter table public.profiles
  add column if not exists public_key text;

alter table public.profiles drop constraint if exists profiles_public_key_format;
alter table public.profiles
  add constraint profiles_public_key_format
  check (public_key is null or public_key ~ '^B[A-Za-z0-9+/]{86}=$');

create table if not exists private.user_keys (
  user_id uuid primary key references auth.users(id) on delete cascade,
  wrapped_private_key text not null
    check (char_length(wrapped_private_key) between 100 and 400
           and wrapped_private_key ~ '^[A-Za-z0-9+/]+={0,2}$'),
  kdf_salt text not null
    check (kdf_salt ~ '^[A-Za-z0-9+/]{22}==$'),
  kdf_iterations integer not null
    check (kdf_iterations between 100000 and 5000000),
  updated_at timestamptz not null default now()
);
revoke all on private.user_keys from public, anon, authenticated;

-- The public key is public by design; the wrapped key is not exposed here.
grant select (public_key) on public.profiles to authenticated;

-- ---------------------------------------------------------------------
-- 3. Messages: ciphertext is longer than plain text
--    ("e1." + base64(IV + ciphertext + tag): 800 characters -> 8000 bits).
-- ---------------------------------------------------------------------
do $$
declare
  v_name text;
begin
  for v_name in
    select c.conname
    from pg_constraint c
    where c.conrelid = 'public.messages'::regclass
      and c.contype = 'c'
      and pg_get_constraintdef(c.oid) like '%5000%'
  loop
    execute format('alter table public.messages drop constraint %I', v_name);
  end loop;
end $$;

alter table public.messages drop constraint if exists messages_payload_size;
alter table public.messages
  add constraint messages_payload_size
  check (char_length(payload_bits) between 10 and 8000);

-- Ciphertext only: safe to return to the two participants again.
grant select (payload_bits) on public.messages to authenticated;

-- A message may only be sent when both sides have published a public key.
drop policy if exists "A user can send to a contact" on public.messages;
create policy "A user can send to a contact"
  on public.messages for insert
  to authenticated
  with check (
    (select auth.uid()) = sender_id
    and receiver_id <> (select auth.uid())
    and exists (
      select 1 from public.contacts c
      where c.owner_id = (select auth.uid())
        and c.contact_id = receiver_id
    )
    and exists (
      select 1 from public.profiles p
      where p.id = (select auth.uid()) and p.public_key is not null
    )
    and exists (
      select 1 from public.profiles p
      where p.id = receiver_id and p.public_key is not null
    )
  );

-- ---------------------------------------------------------------------
-- 4. Deleting messages (both participants, permanent)
-- ---------------------------------------------------------------------
grant delete on public.messages to authenticated;

drop policy if exists "Participants can delete messages" on public.messages;
create policy "Participants can delete messages"
  on public.messages for delete
  to authenticated
  using (
    (select auth.uid()) = sender_id
    or (select auth.uid()) = receiver_id
  );

-- Realtime DELETE events carry only the primary key (id), which is already in
-- the publication's column list. Nothing else about the message is exposed.

-- ---------------------------------------------------------------------
-- 5. Remove the obsolete bcrypt unlock-key flow
-- ---------------------------------------------------------------------
drop function if exists public.get_message_bits(uuid, text);
drop function if exists public.verify_message_unlock_key(text);
drop function if exists public.set_message_unlock_key(text);
drop function if exists public.change_message_unlock_key(text, text);
drop function if exists public.has_message_unlock_key();
drop function if exists private.check_unlock_key(uuid, text);

-- ---------------------------------------------------------------------
-- 6. Profile lookup now also returns the public key
-- ---------------------------------------------------------------------
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
revoke all on function public.find_profile_by_handle(text) from public, anon;
grant execute on function public.find_profile_by_handle(text) to authenticated;

-- ---------------------------------------------------------------------
-- 7. Key bundle functions
-- ---------------------------------------------------------------------
create or replace function public.get_my_key_bundle()
returns table (
  public_key text,
  wrapped_private_key text,
  kdf_salt text,
  kdf_iterations integer
)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'Authentication required';
  end if;
  return query
    select p.public_key, k.wrapped_private_key, k.kdf_salt, k.kdf_iterations
    from public.profiles p
    join private.user_keys k on k.user_id = p.id
    where p.id = v_uid and p.public_key is not null;
end;
$$;

-- First-time setup only.
create or replace function public.set_my_key_bundle(
  p_public_key text, p_wrapped text, p_salt text, p_iterations integer
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'Authentication required';
  end if;
  perform private.enforce_rate_limit(v_uid, 'keys_set', 10, interval '1 hour');
  if exists (select 1 from private.user_keys k where k.user_id = v_uid) then
    raise exception 'keys_exist';
  end if;

  insert into private.user_keys (user_id, wrapped_private_key, kdf_salt, kdf_iterations)
  values (v_uid, p_wrapped, p_salt, p_iterations);

  update public.profiles set public_key = p_public_key where id = v_uid;
end;
$$;

-- Same key pair, new unlock key. Compare-and-swap on the old wrapped copy so a
-- stale tab cannot overwrite a change made elsewhere. The public key stays.
create or replace function public.rewrap_my_key_bundle(
  p_old_wrapped text, p_wrapped text, p_salt text, p_iterations integer
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_count integer;
begin
  if v_uid is null then
    raise exception 'Authentication required';
  end if;
  perform private.enforce_rate_limit(v_uid, 'keys_rewrap', 10, interval '1 hour');

  update private.user_keys
     set wrapped_private_key = p_wrapped,
         kdf_salt = p_salt,
         kdf_iterations = p_iterations,
         updated_at = now()
   where user_id = v_uid and wrapped_private_key = p_old_wrapped;
  get diagnostics v_count = row_count;
  return v_count > 0;
end;
$$;

-- Forgotten unlock key: new key pair. Old messages can never be read again,
-- so every message this user sent or received is deleted.
create or replace function public.reset_my_key_bundle(
  p_public_key text, p_wrapped text, p_salt text, p_iterations integer
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'Authentication required';
  end if;
  perform private.enforce_rate_limit(v_uid, 'keys_reset', 5, interval '1 hour');

  delete from public.messages m
   where m.sender_id = v_uid or m.receiver_id = v_uid;

  insert into private.user_keys (user_id, wrapped_private_key, kdf_salt, kdf_iterations)
  values (v_uid, p_wrapped, p_salt, p_iterations)
  on conflict (user_id) do update
    set wrapped_private_key = excluded.wrapped_private_key,
        kdf_salt = excluded.kdf_salt,
        kdf_iterations = excluded.kdf_iterations,
        updated_at = now();

  update public.profiles set public_key = p_public_key where id = v_uid;
end;
$$;

revoke all on function
  public.get_my_key_bundle(),
  public.set_my_key_bundle(text, text, text, integer),
  public.rewrap_my_key_bundle(text, text, text, integer),
  public.reset_my_key_bundle(text, text, text, integer)
  from public, anon;
grant execute on function
  public.get_my_key_bundle(),
  public.set_my_key_bundle(text, text, text, integer),
  public.rewrap_my_key_bundle(text, text, text, integer),
  public.reset_my_key_bundle(text, text, text, integer)
  to authenticated;
