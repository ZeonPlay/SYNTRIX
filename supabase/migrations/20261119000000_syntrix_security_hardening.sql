-- SYNTRIX security hardening (consolidating and idempotent).
-- Run in the Supabase SQL Editor AFTER every earlier migration. Safe to run again.
--
-- Why this exists
--   * 20261116_device_security_v2 replaced the strict, JWT-session-bound approval
--     helpers with device_id-based ones that do not check trust. Pending sessions
--     could then call SECURITY DEFINER RPCs (for example get_my_key_bundle).
--   * reset_my_key_bundle and the legacy E2EE / unlock-key RPCs are unused by the
--     client but still replace keys or delete messages with only a session check.
--   * register_device auto-trusted the next login once no trusted device was left
--     (including after the 90-day cleanup deleted the owner's trusted device).
--
-- After this migration
--   * Trust is derived from the signed JWT session_id, never from a browser value.
--   * Only a user with NO device rows at all gets an auto-trusted first device.
--   * Trusted devices are never deleted by inactivity.
--   * At most 5 pending devices per user.
--   * Recovery when every trusted device is lost is manual: an operator must set
--     acknowledged_at on a user_devices row, or delete the user's rows, in SQL.

-- ---------------------------------------------------------------------
-- 1. Remove unused and dangerous RPCs
-- ---------------------------------------------------------------------
drop function if exists public.reset_my_key_bundle(text, text, text, integer);
drop function if exists public.enable_e2ee(text, text, text, text, text, integer);
drop function if exists public.get_e2ee_state();
drop function if exists public.get_e2ee_backup(text);
drop function if exists public.change_e2ee_passphrase(text, text, text, text, integer);
drop function if exists public.get_message_bits(uuid, text);
drop function if exists public.set_message_unlock_key(text);
drop function if exists public.change_message_unlock_key(text, text);
drop function if exists public.verify_message_unlock_key(text);
drop function if exists public.has_message_unlock_key();
drop function if exists private.check_unlock_key(uuid, text);

-- ---------------------------------------------------------------------
-- 2. Strict, session-bound trust helpers
-- ---------------------------------------------------------------------
create unique index if not exists user_devices_session_id_unique
  on public.user_devices (session_id) where session_id is not null;

create or replace function private.assert_auth_session()
returns void language plpgsql security definer set search_path = '' as $fn$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := nullif(auth.jwt() ->> 'session_id', '')::uuid;
begin
  if v_uid is null or v_sid is null then
    raise exception 'not_authenticated' using errcode = 'PT401';
  end if;
  if not exists (select 1 from auth.sessions s where s.id = v_sid and s.user_id = v_uid) then
    raise exception 'session_revoked' using errcode = 'PT401';
  end if;
end;
$fn$;

create or replace function private.current_session_is_trusted(p_device_id text default null)
returns boolean language sql stable security definer set search_path = '' as $fn$
  select auth.uid() is not null
     and nullif(auth.jwt() ->> 'session_id', '') is not null
     and exists (
       select 1
         from auth.sessions s
         join public.user_devices d on d.user_id = s.user_id and d.session_id = s.id
        where s.id = nullif(auth.jwt() ->> 'session_id', '')::uuid
          and s.user_id = auth.uid()
          and d.acknowledged_at is not null
          and d.revoked_at is null
          and (p_device_id is null or d.device_id = p_device_id)
     );
$fn$;

create or replace function private.current_session_is_revoked()
returns boolean language sql stable security definer set search_path = '' as $fn$
  select auth.uid() is not null
     and nullif(auth.jwt() ->> 'session_id', '') is not null
     and exists (
       select 1 from public.user_devices d
        where d.user_id = auth.uid()
          and d.session_id = nullif(auth.jwt() ->> 'session_id', '')::uuid
          and d.revoked_at is not null
     );
$fn$;

create or replace function private.assert_active_session()
returns void language plpgsql security definer set search_path = '' as $fn$
begin
  perform private.assert_auth_session();
  if not private.current_session_is_trusted() then
    raise exception 'device_not_approved' using errcode = 'PT403';
  end if;
end;
$fn$;

create or replace function private.is_trusted_device(p_uid uuid, p_device_id text)
returns boolean language sql stable security definer set search_path = '' as $fn$
  select p_uid = auth.uid() and private.current_session_is_trusted(p_device_id);
$fn$;

revoke all on function private.assert_auth_session() from public, anon, authenticated;
revoke all on function private.assert_active_session() from public, anon, authenticated;
revoke all on function private.current_session_is_trusted(text) from public, anon, authenticated;
revoke all on function private.current_session_is_revoked() from public, anon, authenticated;
revoke all on function private.is_trusted_device(uuid, text) from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.current_session_is_trusted(text) to authenticated;
grant execute on function private.current_session_is_revoked() to authenticated;

-- ---------------------------------------------------------------------
-- 3. register_device: no auto-trust after the first device, no trusted-row
--    cleanup by inactivity, bounded number of pending devices
-- ---------------------------------------------------------------------
create or replace function public.register_device(
  p_device_id text, p_label text, p_info jsonb default '{}'::jsonb
)
returns uuid language plpgsql security definer set search_path = '' as $fn$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := nullif(auth.jwt() ->> 'session_id', '')::uuid;
  v_row public.user_devices%rowtype;
  v_id uuid;
  v_label text := left(btrim(coalesce(p_label, '')), 80);
  v_info jsonb := case when jsonb_typeof(p_info) = 'object' then p_info else '{}'::jsonb end;
  v_browser text := left(nullif(btrim(coalesce(v_info ->> 'browser', '')), ''), 40);
  v_os text := left(nullif(btrim(coalesce(v_info ->> 'os', '')), ''), 40);
  v_type text := nullif(btrim(coalesce(v_info ->> 'device_type', '')), '');
  v_lang text := left(nullif(btrim(coalesce(v_info ->> 'language', '')), ''), 20);
  v_tz text := left(nullif(btrim(coalesce(v_info ->> 'timezone', '')), ''), 64);
  v_headers json;
  v_ip text;
  v_country text;
  v_region text;
  v_city text;
  v_started timestamptz;
  v_login_ip text;
begin
  perform private.assert_auth_session();
  if p_device_id is null or char_length(p_device_id) not between 8 and 64 then
    raise exception 'invalid_device';
  end if;
  if v_label = '' then v_label := 'Perangkat tidak dikenal'; end if;
  if v_type is not null and v_type not in ('desktop', 'mobile', 'tablet') then v_type := null; end if;

  if exists (
    select 1 from public.user_devices d
     where d.user_id = v_uid and d.session_id = v_sid
       and d.device_id <> p_device_id and d.revoked_at is null
  ) then
    raise exception 'device_identity_mismatch';
  end if;

  select s.created_at into v_started
    from auth.sessions s where s.id = v_sid and s.user_id = v_uid;
  if not found then raise exception 'session_revoked' using errcode = 'PT401'; end if;

  begin
    execute 'select host(ip::inet) from auth.sessions where id = $1' into v_login_ip using v_sid;
  exception when others then
    v_login_ip := null;
  end;

  begin
    v_headers := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::json;
  exception when others then
    v_headers := '{}'::json;
  end;

  -- cf-connecting-ip is set by Cloudflare and cannot be chosen by the client.
  -- The fallbacks below can be client-controlled on some paths: treat them as hints.
  v_ip := left(btrim(coalesce(
    nullif(btrim(v_headers ->> 'cf-connecting-ip'), ''),
    nullif(btrim(v_headers ->> 'x-real-ip'), ''),
    nullif(btrim(split_part(coalesce(v_headers ->> 'x-forwarded-for', ''), ',', 1)), ''),
    ''
  )), 64);
  v_ip := coalesce(nullif(v_ip, ''), left(v_login_ip, 64));
  v_country := upper(nullif(btrim(v_headers ->> 'cf-ipcountry'), ''));
  if v_country is null or v_country !~ '^[A-Z]{2}$' or v_country in ('XX', 'T1') then
    v_country := null;
  end if;
  v_region := left(nullif(btrim(coalesce(v_headers ->> 'cf-region', v_headers ->> 'cf-region-code')), ''), 80);
  v_city := left(nullif(btrim(v_headers ->> 'cf-ipcity'), ''), 80);

  select * into v_row from public.user_devices
   where user_id = v_uid and device_id = p_device_id
   for update;

  if found then
    if v_row.revoked_at is not null then
      if v_sid = v_row.session_id then
        raise exception 'session_revoked' using errcode = 'PT401';
      end if;
      -- A new login from a rejected browser is a new alert, never auto-trusted.
      update public.user_devices
         set revoked_at = null, acknowledged_at = null,
             first_seen_at = now(), last_seen_at = now(),
             label = v_label, session_id = v_sid, session_started_at = v_started,
             ip_address = v_ip, country = v_country, region = v_region, city = v_city,
             browser = v_browser, os = v_os, device_type = v_type, language = v_lang, timezone = v_tz
       where id = v_row.id;
      return v_row.id;
    end if;

    update public.user_devices
       set last_seen_at = now(), label = v_label, session_id = v_sid,
           session_started_at = coalesce(v_started, session_started_at),
           ip_address = v_ip, country = v_country, region = v_region, city = v_city,
           browser = v_browser, os = v_os, device_type = v_type, language = v_lang, timezone = v_tz
     where id = v_row.id;
    return v_row.id;
  end if;

  perform pg_advisory_xact_lock(hashtextextended(v_uid::text, 42));

  -- Never delete a trusted device because it was idle. Only stale pending rows go,
  -- and old revoked rows go only while another trusted device still exists.
  delete from public.user_devices d
   where d.user_id = v_uid
     and (
       (d.acknowledged_at is null and d.revoked_at is null
         and d.last_seen_at < now() - interval '90 days')
       or (d.revoked_at is not null and d.revoked_at < now() - interval '30 days'
         and exists (
           select 1 from public.user_devices t
            where t.user_id = v_uid and t.acknowledged_at is not null and t.revoked_at is null
         ))
     );

  if (select count(*) from public.user_devices where user_id = v_uid and revoked_at is null) >= 25
     or (select count(*) from public.user_devices
          where user_id = v_uid and revoked_at is null and acknowledged_at is null) >= 5 then
    raise exception 'device_limit';
  end if;

  -- Only an account that has never registered any device gets an auto-trusted
  -- first device. Every later device waits for a trusted device to approve it.
  insert into public.user_devices (
    user_id, device_id, label, acknowledged_at,
    session_id, session_started_at, ip_address, country, region, city,
    browser, os, device_type, language, timezone
  )
  values (
    v_uid, p_device_id, v_label,
    case when not exists (select 1 from public.user_devices where user_id = v_uid)
      then now() else null end,
    v_sid, v_started, v_ip, v_country, v_region, v_city,
    v_browser, v_os, v_type, v_lang, v_tz
  )
  returning id into v_id;
  return v_id;
end;
$fn$;

-- ---------------------------------------------------------------------
-- 4. Device list / approve / reject, bound to the signed session
-- ---------------------------------------------------------------------
create or replace function public.list_devices(p_device_id text)
returns table (
  id uuid, label text, is_current boolean, status text,
  first_seen_at timestamptz, last_seen_at timestamptz, session_started_at timestamptz,
  ip_address text, country text, region text, city text,
  browser text, os text, device_type text, language text, timezone text
)
language plpgsql security definer set search_path = '' as $fn$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := nullif(auth.jwt() ->> 'session_id', '')::uuid;
  v_trusted boolean;
begin
  perform private.assert_auth_session();
  v_trusted := private.current_session_is_trusted();
  return query
    select d.id, d.label, (d.session_id = v_sid),
           case when d.acknowledged_at is not null then 'trusted' else 'pending' end,
           d.first_seen_at, d.last_seen_at, coalesce(d.session_started_at, d.first_seen_at),
           case when v_trusted then d.ip_address end,
           case when v_trusted then d.country end,
           case when v_trusted then d.region end,
           case when v_trusted then d.city end,
           d.browser, d.os, d.device_type, d.language, d.timezone
      from public.user_devices d
     where d.user_id = v_uid and d.revoked_at is null
       and (v_trusted or d.session_id = v_sid)
     order by (d.session_id = v_sid) desc,
              (d.acknowledged_at is null) desc,
              coalesce(d.session_started_at, d.first_seen_at) desc;
end;
$fn$;

create or replace function public.acknowledge_device(p_device_id text, p_target uuid)
returns boolean language plpgsql security definer set search_path = '' as $fn$
declare
  v_uid uuid := auth.uid();
  v_count integer;
begin
  perform private.assert_active_session();
  if not private.current_session_is_trusted(p_device_id) then
    raise exception 'device_not_trusted';
  end if;
  update public.user_devices set acknowledged_at = now()
   where id = p_target and user_id = v_uid
     and acknowledged_at is null and revoked_at is null;
  get diagnostics v_count = row_count;
  return v_count > 0;
end;
$fn$;

create or replace function public.reject_device(p_device_id text, p_target uuid)
returns jsonb language plpgsql security definer set search_path = '' as $fn$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := nullif(auth.jwt() ->> 'session_id', '')::uuid;
  v_current_device_id text;
  v_target public.user_devices%rowtype;
  v_revoked integer := 0;
  v_unmapped integer := 0;
begin
  perform private.assert_active_session();
  if not private.current_session_is_trusted(p_device_id) then
    raise exception 'device_not_trusted';
  end if;

  select d.device_id into v_current_device_id
    from public.user_devices d
   where d.user_id = v_uid and d.session_id = v_sid
     and d.acknowledged_at is not null and d.revoked_at is null;

  select * into v_target from public.user_devices
   where id = p_target and user_id = v_uid and revoked_at is null
   for update;
  if not found then
    return jsonb_build_object('removed', 0, 'revoked', 0, 'unmapped', 0);
  end if;
  if v_target.session_id = v_sid or v_target.device_id = v_current_device_id then
    raise exception 'cannot_reject_self';
  end if;

  update public.user_devices set revoked_at = now(), acknowledged_at = null
   where id = v_target.id;

  if v_target.session_id is null then
    v_unmapped := 1;
  else
    delete from auth.sessions where id = v_target.session_id and user_id = v_uid;
    get diagnostics v_revoked = row_count;
  end if;
  return jsonb_build_object('removed', 1, 'revoked', v_revoked, 'unmapped', v_unmapped);
end;
$fn$;

-- ---------------------------------------------------------------------
-- 5. Profile lookup now requires an approved session
-- ---------------------------------------------------------------------
create or replace function public.find_profile_by_handle(p_handle text)
returns table (id uuid, handle text, display_name text, public_key text)
language plpgsql security definer set search_path = '' as $fn$
declare
  v_uid uuid := auth.uid();
  v_handle text := lower(trim(coalesce(p_handle, '')));
begin
  perform private.assert_active_session();
  if v_uid is null then raise exception 'Authentication required'; end if;
  if v_handle !~ '^[a-z0-9_]{3,24}$' then return; end if;
  perform private.enforce_rate_limit(v_uid, 'lookup', 20, interval '1 minute');
  return query
    select p.id, p.handle, p.display_name, p.public_key
      from public.profiles p
     where p.handle = v_handle;
end;
$fn$;

-- ---------------------------------------------------------------------
-- 6. Restrictive RLS gates: every workspace table needs an approved session
-- ---------------------------------------------------------------------
drop policy if exists syntrix_approved_session_gate on public.profiles;
create policy syntrix_approved_session_gate on public.profiles
  as restrictive for all to authenticated
  using (private.current_session_is_trusted())
  with check (private.current_session_is_trusted());

drop policy if exists syntrix_approved_session_gate on public.contacts;
create policy syntrix_approved_session_gate on public.contacts
  as restrictive for all to authenticated
  using (private.current_session_is_trusted())
  with check (private.current_session_is_trusted());

drop policy if exists syntrix_approved_session_gate on public.messages;
create policy syntrix_approved_session_gate on public.messages
  as restrictive for all to authenticated
  using (private.current_session_is_trusted())
  with check (private.current_session_is_trusted());

-- A rejected browser may see only its own revoked row, so it can sign itself out.
drop policy if exists syntrix_approved_session_gate on public.user_devices;
create policy syntrix_approved_session_gate on public.user_devices
  as restrictive for all to authenticated
  using (
    private.current_session_is_trusted()
    or (
      private.current_session_is_revoked()
      and user_id = (select auth.uid())
      and session_id = nullif(auth.jwt() ->> 'session_id', '')::uuid
      and revoked_at is not null
    )
  )
  with check (private.current_session_is_trusted());

drop policy if exists syntrix_approved_session_gate on realtime.messages;
create policy syntrix_approved_session_gate on realtime.messages
  as restrictive for select to authenticated
  using (private.current_session_is_trusted());

drop policy if exists syntrix_approved_session_gate_insert on realtime.messages;
create policy syntrix_approved_session_gate_insert on realtime.messages
  as restrictive for insert to authenticated
  with check (private.current_session_is_trusted());

-- ---------------------------------------------------------------------
-- 7. Data API pre-request guard: pending sessions may call only
--    register_device and list_devices
-- ---------------------------------------------------------------------
create or replace function public.syntrix_check_session()
returns void language plpgsql security definer set search_path = '' as $fn$
declare
  v_claims jsonb;
  v_uid uuid;
  v_sid uuid;
  v_path text;
begin
  begin
    v_claims := nullif(current_setting('request.jwt.claims', true), '')::jsonb;
  exception when others then
    return;
  end;

  if coalesce(v_claims ->> 'role', '') <> 'authenticated' then return; end if;

  v_uid := nullif(v_claims ->> 'sub', '')::uuid;
  v_sid := nullif(v_claims ->> 'session_id', '')::uuid;
  if v_uid is null or v_sid is null then
    raise exception 'not_authenticated' using errcode = 'PT401';
  end if;
  if not exists (select 1 from auth.sessions s where s.id = v_sid and s.user_id = v_uid) then
    raise exception 'session_revoked' using errcode = 'PT401';
  end if;

  v_path := trim(both '/' from coalesce(current_setting('request.path', true), ''));
  v_path := regexp_replace(v_path, '^.*/(rpc/)', 'rpc/');
  if v_path in ('rpc/register_device', 'rpc/list_devices') then return; end if;

  if not private.current_session_is_trusted() then
    raise exception 'device_not_approved' using errcode = 'PT403';
  end if;
end;
$fn$;

revoke all on function public.syntrix_check_session() from public, anon, authenticated;
grant execute on function public.syntrix_check_session() to authenticated, authenticator, service_role;

do $do$
begin
  alter role authenticator set pgrst.db_pre_request = 'public.syntrix_check_session';
  perform pg_notify('pgrst', 'reload config');
exception when others then
  raise warning 'Could not enable db_pre_request (%). Set it manually: alter role authenticator set pgrst.db_pre_request = ''public.syntrix_check_session'';', sqlerrm;
end
$do$;

-- ---------------------------------------------------------------------
-- 8. Grants for every public function this migration (re)defines
-- ---------------------------------------------------------------------
revoke all on function
  public.register_device(text, text, jsonb),
  public.list_devices(text),
  public.acknowledge_device(text, uuid),
  public.reject_device(text, uuid),
  public.find_profile_by_handle(text)
  from public, anon;
grant execute on function
  public.register_device(text, text, jsonb),
  public.list_devices(text),
  public.acknowledge_device(text, uuid),
  public.reject_device(text, uuid),
  public.find_profile_by_handle(text)
  to authenticated;
