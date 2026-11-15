-- SYNTRIX: make contact creation atomic and fully clean account data before reuse.
-- Run after 20261120000000_syntrix_e2ee_contact_sync_account_delete.sql.

create or replace function public.add_contact_by_handle(p_handle text)
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
  v_handle text := lower(btrim(regexp_replace(coalesce(p_handle, ''), '^@', '')));
  v_contact_id uuid;
begin
  perform private.assert_active_session();
  if v_uid is null then
    raise exception 'not_authenticated' using errcode = 'PT401';
  end if;
  if v_handle !~ '^[a-z0-9_]{3,24}$' then
    raise exception 'invalid_handle' using errcode = 'PT400';
  end if;

  perform private.enforce_rate_limit(v_uid, 'lookup', 20, interval '1 minute');

  select p.id into v_contact_id
    from public.profiles p
   where lower(p.handle) = v_handle
   limit 1;

  if v_contact_id is null then
    raise exception 'contact_not_found' using errcode = 'PT404';
  end if;
  if v_contact_id = v_uid then
    raise exception 'contact_self' using errcode = 'PT400';
  end if;

  insert into public.contacts (owner_id, contact_id)
  values (v_uid, v_contact_id)
  on conflict (owner_id, contact_id) do nothing;

  return query
    select p.id, p.handle, p.display_name, p.public_key
      from public.profiles p
     where p.id = v_contact_id;
end;
$fn$;

revoke all on function public.add_contact_by_handle(text) from public, anon;
grant execute on function public.add_contact_by_handle(text) to authenticated;

-- A removed account must leave no stale profile/contact/message rows behind.
-- Explicit cleanup makes re-registration with the same email/handle predictable
-- even if an older deployment had incomplete foreign-key cascade rules.
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
    raise exception 'not_authenticated' using errcode = 'PT401';
  end if;

  delete from public.contacts
   where owner_id = v_uid or contact_id = v_uid;

  delete from public.messages
   where sender_id = v_uid or receiver_id = v_uid;

  delete from public.user_devices where user_id = v_uid;
  delete from private.user_keys where user_id = v_uid;
  delete from private.rate_events where user_id = v_uid;
  delete from public.profiles where id = v_uid;

  delete from auth.users where id = v_uid;
  get diagnostics v_deleted = row_count;

  return v_deleted = 1;
end;
$fn$;

revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;

select pg_notify('pgrst', 'reload schema');
