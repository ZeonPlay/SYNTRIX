-- SYNTRIX device security v2 (additive). Run once in the Supabase SQL Editor,
-- AFTER 20261115000000_syntrix_device_tracking.sql.
--
-- What changes:
-- 1. "Ini aku" / "Bukan aku" work per device instead of for every pending device.
-- 2. A rejected device is marked revoked (not deleted). The UPDATE reaches the
--    rejected browser through Realtime, so it signs itself out at once.
--    (Realtime cannot filter DELETE events, which is why the old delete-based
--    flow never reached any other browser.)
-- 3. The server now refuses API calls from a revoked session straight away,
--    instead of letting its access token live on until it expires.
-- 4. Devices record when the session was started, plus browser, OS, device type,
--    language and time zone, so the Security page can show readable details.
--
-- IP and location are still never granted to the Data API. They are returned
-- only by list_devices(), and only to a device that is already trusted.

-- ---------------------------------------------------------------------
-- 1. Columns
-- ---------------------------------------------------------------------
alter table public.user_devices
  add column if not exists revoked_at timestamptz,
  add column if not exists session_started_at timestamptz,
  add column if not exists browser text,
  add column if not exists os text,
  add column if not exists device_type text,
  add column if not exists language text,
  add column if not exists timezone text;

-- Needed so the rejected browser can see its own row being revoked in Realtime.
grant select (revoked_at) on public.user_devices to authenticated;

-- ---------------------------------------------------------------------
-- 2. Private helpers
-- ---------------------------------------------------------------------
create or replace function private.assert_active_session()
returns void language plpgsql security definer set search_path = '' as $$
declare
  v_sid uuid := nullif(auth.jwt() ->> 'session_id', '')::uuid;
begin
  if auth.uid() is null then raise exception 'not_authenticated'; end if;
  if v_sid is not null and not exists (select 1 from auth.sessions s where s.id = v_sid) then
    raise exception 'session_revoked';
  end if;
end $$;

create or replace function private.is_trusted_device(p_uid uuid, p_device_id text)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.user_devices d
     where d.user_id = p_uid and d.device_id = p_device_id
       and d.acknowledged_at is not null and d.revoked_at is null
  );
$$;

revoke all on function private.assert_active_session(), private.is_trusted_device(uuid, text)
  from public, anon, authenticated;

-- ---------------------------------------------------------------------
-- 3. register_device: also the heartbeat. Stores the session start time and
--    client details; a rejected device that logs in again becomes pending again.
-- ---------------------------------------------------------------------
create or replace function public.register_device(
  p_device_id text, p_label text, p_info jsonb default '{}'::jsonb
)
returns uuid language plpgsql security definer set search_path = '' as $$
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
  if v_uid is null then raise exception 'not_authenticated'; end if;
  if p_device_id is null or char_length(p_device_id) not between 8 and 64 then
    raise exception 'invalid_device';
  end if;
  if v_label = '' then v_label := 'Perangkat tidak dikenal'; end if;
  if v_type is not null and v_type not in ('desktop', 'mobile', 'tablet') then v_type := null; end if;

  -- A session removed by "Bukan aku" may still hold an unexpired access token.
  if v_sid is not null then
    select s.created_at into v_started from auth.sessions s where s.id = v_sid;
    if not found then raise exception 'session_revoked'; end if;
    -- IP recorded by Auth when the session was created; only a fallback.
    begin
      execute 'select host(ip::inet) from auth.sessions where id = $1' into v_login_ip using v_sid;
    exception when others then
      v_login_ip := null;
    end;
  end if;

  -- Request metadata added by the edge, not by the browser.
  begin
    v_headers := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::json;
  exception when others then
    v_headers := '{}'::json;
  end;

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
      -- Same session as the one that was rejected: keep it out.
      if v_sid is null or v_row.session_id is null or v_sid = v_row.session_id then
        raise exception 'session_revoked';
      end if;
      -- A brand new login from a rejected device is a new alert, never auto-trusted.
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

  -- Serialise first-time registrations per user so two simultaneous logins cannot
  -- both be trusted as "the first device".
  perform pg_advisory_xact_lock(hashtextextended(v_uid::text, 42));

  delete from public.user_devices
   where user_id = v_uid
     and (last_seen_at < now() - interval '90 days'
          or (revoked_at is not null and revoked_at < now() - interval '30 days'));
  if (select count(*) from public.user_devices where user_id = v_uid and revoked_at is null) >= 25 then
    raise exception 'device_limit';
  end if;

  -- The first device (or the first once no trusted one is left) is trusted at once;
  -- every later device waits for a trusted device to acknowledge it.
  insert into public.user_devices (
    user_id, device_id, label, acknowledged_at,
    session_id, session_started_at, ip_address, country, region, city,
    browser, os, device_type, language, timezone
  )
  values (
    v_uid, p_device_id, v_label,
    case when exists (
      select 1 from public.user_devices
       where user_id = v_uid and acknowledged_at is not null and revoked_at is null
    ) then null else now() end,
    v_sid, v_started, v_ip, v_country, v_region, v_city,
    v_browser, v_os, v_type, v_lang, v_tz
  )
  returning id into v_id;
  return v_id;
end $$;

-- ---------------------------------------------------------------------
-- 4. list_devices: every active device for a trusted caller. An untrusted
--    caller only gets its own row, without IP or location.
-- ---------------------------------------------------------------------
create or replace function public.list_devices(p_device_id text)
returns table (
  id uuid,
  label text,
  is_current boolean,
  status text,
  first_seen_at timestamptz,
  last_seen_at timestamptz,
  session_started_at timestamptz,
  ip_address text,
  country text,
  region text,
  city text,
  browser text,
  os text,
  device_type text,
  language text,
  timezone text
) language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_trusted boolean;
begin
  perform private.assert_active_session();
  v_trusted := private.is_trusted_device(v_uid, p_device_id);

  return query
    select d.id,
           d.label,
           (d.device_id = p_device_id),
           case when d.acknowledged_at is not null then 'trusted' else 'pending' end,
           d.first_seen_at,
           d.last_seen_at,
           coalesce(d.session_started_at, d.first_seen_at),
           case when v_trusted then d.ip_address end,
           case when v_trusted then d.country end,
           case when v_trusted then d.region end,
           case when v_trusted then d.city end,
           d.browser,
           d.os,
           d.device_type,
           d.language,
           d.timezone
      from public.user_devices d
     where d.user_id = v_uid
       and d.revoked_at is null
       and (v_trusted or d.device_id = p_device_id)
     order by (d.device_id = p_device_id) desc,
              (d.acknowledged_at is null) desc,
              coalesce(d.session_started_at, d.first_seen_at) desc;
end $$;

-- ---------------------------------------------------------------------
-- 5. "Ini aku" for one device
-- ---------------------------------------------------------------------
create or replace function public.acknowledge_device(p_device_id text, p_target uuid)
returns boolean language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_count integer;
begin
  perform private.assert_active_session();
  if not private.is_trusted_device(v_uid, p_device_id) then
    raise exception 'device_not_trusted';
  end if;

  update public.user_devices set acknowledged_at = now()
   where id = p_target and user_id = v_uid
     and acknowledged_at is null and revoked_at is null;
  get diagnostics v_count = row_count;
  return v_count > 0;
end $$;

-- ---------------------------------------------------------------------
-- 6. "Bukan aku" / "Keluarkan" for one device: mark it revoked and delete its
--    auth session (which also removes its refresh tokens).
-- ---------------------------------------------------------------------
create or replace function public.reject_device(p_device_id text, p_target uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := nullif(auth.jwt() ->> 'session_id', '')::uuid;
  v_target public.user_devices%rowtype;
  v_revoked integer := 0;
  v_unmapped integer := 0;
begin
  perform private.assert_active_session();
  if not private.is_trusted_device(v_uid, p_device_id) then
    raise exception 'device_not_trusted';
  end if;

  select * into v_target from public.user_devices
   where id = p_target and user_id = v_uid and revoked_at is null
   for update;
  if not found then
    return jsonb_build_object('removed', 0, 'revoked', 0, 'unmapped', 0);
  end if;
  if v_target.device_id = p_device_id then
    raise exception 'cannot_reject_self';
  end if;

  update public.user_devices
     set revoked_at = now(), acknowledged_at = null
   where id = v_target.id;

  if v_target.session_id is null then
    -- Row from before session tracking: its session cannot be matched.
    v_unmapped := 1;
  elsif v_target.session_id is distinct from v_sid then
    delete from auth.sessions where id = v_target.session_id and user_id = v_uid;
    get diagnostics v_revoked = row_count;
  end if;

  return jsonb_build_object('removed', 1, 'revoked', v_revoked, 'unmapped', v_unmapped);
end $$;

-- The bulk functions are replaced by the per-device ones above.
drop function if exists public.register_device(text, text);
drop function if exists public.list_pending_devices(text);
drop function if exists public.acknowledge_devices(text);
drop function if exists public.reject_devices(text);

revoke all on function
  public.register_device(text, text, jsonb),
  public.list_devices(text),
  public.acknowledge_device(text, uuid),
  public.reject_device(text, uuid)
  from public, anon;
grant execute on function
  public.register_device(text, text, jsonb),
  public.list_devices(text),
  public.acknowledge_device(text, uuid),
  public.reject_device(text, uuid)
  to authenticated;

-- ---------------------------------------------------------------------
-- 7. Realtime: publish revoked_at so a rejected browser learns it was kicked.
--    last_seen_at is left out on purpose; heartbeats should not wake every device.
-- ---------------------------------------------------------------------
do $$ begin
  alter publication supabase_realtime drop table public.user_devices;
exception when undefined_object then null;
end $$;
alter publication supabase_realtime add table public.user_devices
  (id, user_id, label, first_seen_at, acknowledged_at, revoked_at);

-- ---------------------------------------------------------------------
-- 8. Server-side enforcement for EVERY Data API request.
--    PostgREST runs this before each request; a revoked session gets HTTP 401
--    "session_revoked", so a kicked browser cannot keep reading data with the
--    access token it still holds.
--
--    This replaces any db_pre_request function you already configured.
--    To undo:  alter role authenticator reset pgrst.db_pre_request;
--              notify pgrst, 'reload config';
-- ---------------------------------------------------------------------
create or replace function public.syntrix_check_session()
returns void language plpgsql security definer set search_path = '' as $$
declare
  v_sid uuid;
begin
  begin
    v_sid := nullif(current_setting('request.jwt.claims', true)::jsonb ->> 'session_id', '')::uuid;
  exception when others then
    return; -- no JWT (anon), or no session_id claim
  end;

  if v_sid is not null and not exists (select 1 from auth.sessions s where s.id = v_sid) then
    raise exception 'session_revoked' using errcode = 'PT401';
  end if;
end $$;

do $$
begin
  alter role authenticator set pgrst.db_pre_request = 'public.syntrix_check_session';
  perform pg_notify('pgrst', 'reload config');
exception when others then
  raise warning 'Could not enable db_pre_request (%). Revoked sessions are still blocked in the device functions, but not in every API call.', sqlerrm;
end $$;
