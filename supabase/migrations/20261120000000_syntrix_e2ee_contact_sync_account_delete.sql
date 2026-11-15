-- SYNTRIX: enforce E2EE identities, reliable incoming contacts, and account deletion.
-- Run once AFTER 20261119000000_syntrix_security_hardening.sql.

-- ---------------------------------------------------------------------
-- 1. Every conversation participant must have an E2EE identity.
--    Enforced in PostgreSQL so direct API calls cannot bypass the browser UI.
-- ---------------------------------------------------------------------
create or replace function private.messages_require_e2ee_keys()
returns trigger
language plpgsql
security definer
set search_path = ''
as $fn$
begin
  if not exists (
    select 1
      from private.user_keys k
      join public.profiles p on p.id = k.user_id
     where k.user_id = new.sender_id
       and p.public_key is not null
  ) then
    raise exception 'sender_e2ee_required'
      using errcode = 'PT403',
            hint = 'Aktifkan E2EE sebelum mengirim pesan.';
  end if;

  if not exists (
    select 1
      from private.user_keys k
      join public.profiles p on p.id = k.user_id
     where k.user_id = new.receiver_id
       and p.public_key is not null
  ) then
    raise exception 'receiver_e2ee_required'
      using errcode = 'PT403',
            hint = 'Penerima harus mengaktifkan E2EE sebelum percakapan dimulai.';
  end if;

  return new;
end;
$fn$;

revoke all on function private.messages_require_e2ee_keys() from public, anon, authenticated;

drop trigger if exists messages_require_e2ee_keys on public.messages;
create trigger messages_require_e2ee_keys
  before insert on public.messages
  for each row execute function private.messages_require_e2ee_keys();

-- ---------------------------------------------------------------------
-- 2. Server-side contact reconciliation.
--    Include both incoming and outgoing conversations, even if a contact
--    row was never created by the receiving client.
-- ---------------------------------------------------------------------
create or replace function public.sync_my_conversation_contacts()
returns table (
  id uuid,
  handle text,
  display_name text,
  public_key text
)
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  v_uid uuid := auth.uid();
begin
  perform private.assert_active_session();
  if v_uid is null then
    raise exception 'Authentication required';
  end if;

  insert into public.contacts (owner_id, contact_id)
  select v_uid, partner_id
    from (
      select m.sender_id as partner_id
        from public.messages m
       where m.receiver_id = v_uid
      union
      select m.receiver_id as partner_id
        from public.messages m
       where m.sender_id = v_uid
      union
      select c.contact_id as partner_id
        from public.contacts c
       where c.owner_id = v_uid
    ) partners
   where partner_id <> v_uid
  on conflict (owner_id, contact_id) do nothing;

  return query
    select p.id, p.handle, p.display_name, p.public_key
      from public.contacts c
      join public.profiles p on p.id = c.contact_id
     where c.owner_id = v_uid
     order by (
       select max(m.created_at)
         from public.messages m
        where (m.sender_id = v_uid and m.receiver_id = p.id)
           or (m.sender_id = p.id and m.receiver_id = v_uid)
     ) desc nulls last, p.display_name;
end;
$fn$;

revoke all on function public.sync_my_conversation_contacts() from public, anon;
grant execute on function public.sync_my_conversation_contacts() to authenticated;

-- ---------------------------------------------------------------------
-- 3. Permanently delete the authenticated account.
--    FK cascades remove profile, contacts, messages, key bundle, and devices.
--    Rate-limit rows have no FK, so remove them explicitly.
-- ---------------------------------------------------------------------
create or replace function public.delete_my_account()
returns boolean
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  v_uid uuid := auth.uid();
  v_deleted integer;
begin
  perform private.assert_active_session();
  if v_uid is null then
    raise exception 'Authentication required';
  end if;

  delete from private.rate_events where user_id = v_uid;
  delete from auth.users where id = v_uid;
  get diagnostics v_deleted = row_count;

  return v_deleted = 1;
end;
$fn$;

revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;

select pg_notify('pgrst', 'reload schema');
