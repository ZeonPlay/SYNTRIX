-- SYNTRIX server-side per-device approval gate.
-- Pending sessions can only register/heartbeat and read their own status.
-- Every workspace table, private key RPC and Realtime presence requires a
-- current JWT session bound to an acknowledged, non-revoked device row.

-- 1. Helpers. Device trust is derived from the signed JWT session_id, never
--    from a device_id supplied by the browser.
create or replace function private.assert_auth_session()
returns void language plpgsql security definer set search_path = '' as $$
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
$$;

create or replace function private.current_session_is_trusted(p_device_id text default null)
returns boolean language sql stable security definer set search_path = '' as $$
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
$$;

create or replace function private.current_session_is_revoked()
returns boolean language sql stable security definer set search_path = '' as $$
  select auth.uid() is not null
     and nullif(auth.jwt() ->> 'session_id', '') is not null
     and exists (
       select 1 from public.user_devices d
        where d.user_id = auth.uid()
          and d.session_id = nullif(auth.jwt() ->> 'session_id', '')::uuid
          and d.revoked_at is not null
     );
$$;

create or replace function private.assert_active_session()
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.assert_auth_session();
  if not private.current_session_is_trusted() then
    raise exception 'device_not_approved' using errcode = 'PT403';
  end if;
end;
$$;

create or replace function private.is_trusted_device(p_uid uuid, p_device_id text)
returns boolean language sql stable security definer set search_path = '' as $$
  select p_uid = auth.uid() and private.current_session_is_trusted(p_device_id);
$$;

revoke all on function private.assert_auth_session() from public, anon, authenticated;
revoke all on function private.assert_active_session() from public, anon, authenticated;
revoke all on function private.current_session_is_trusted(text) from public, anon, authenticated;
revoke all on function private.current_session_is_revoked() from public, anon, authenticated;
revoke all on function private.is_trusted_device(uuid, text) from public, anon, authenticated;
grant usage on schema private to authenticated;
grant execute on function private.current_session_is_trusted(text) to authenticated;
grant execute on function private.current_session_is_revoked() to authenticated;

create unique index if not exists user_devices_session_id_unique
  on public.user_devices (session_id) where session_id is not null;

-- 2. Device registration is permitted before approval, but cannot reuse a
--    session already attached to a different browser identity. A new login
--    from a rejected browser is re-registered as pending, never auto-trusted.
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
  delete from public.user_devices
   where user_id = v_uid
     and (last_seen_at < now() - interval '90 days'
          or (revoked_at is not null and revoked_at < now() - interval '30 days'));
  if (select count(*) from public.user_devices where user_id = v_uid and revoked_at is null) >= 25 then
    raise exception 'device_limit';
  end if;

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
end;
$$;

-- 3. Pending sessions only receive their own device row/status. Trusted sessions
--    receive the active device list and may see IP/location details.
create or replace function public.list_devices(p_device_id text)
returns table (
  id uuid, label text, is_current boolean, status text,
  first_seen_at timestamptz, last_seen_at timestamptz, session_started_at timestamptz,
  ip_address text, country text, region text, city text,
  browser text, os text, device_type text, language text, timezone text
)
language plpgsql security definer set search_path = '' as $$
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
$$;

-- 4. Approval/rejection can only be performed by the currently trusted session.
create or replace function public.acknowledge_device(p_device_id text, p_target uuid)
returns boolean language plpgsql security definer set search_path = '' as $$
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
$$;

create or replace function public.reject_device(p_device_id text, p_target uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
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
$$;

-- 5. Restrictive RLS policies AND with the existing ownership/participant rules.
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

drop policy if exists syntrix_approved_session_gate on private.user_security;
create policy syntrix_approved_session_gate on private.user_security
  as restrictive for all to authenticated
  using (private.current_session_is_trusted())
  with check (private.current_session_is_trusted());

drop policy if exists syntrix_approved_session_gate on private.user_keys;
create policy syntrix_approved_session_gate on private.user_keys
  as restrictive for all to authenticated
  using (private.current_session_is_trusted())
  with check (private.current_session_is_trusted());

drop policy if exists syntrix_approved_session_gate on realtime.messages;
create policy syntrix_approved_session_gate on realtime.messages
  as restrictive for select to authenticated
  using (private.current_session_is_trusted());

drop policy if exists syntrix_approved_session_gate_insert on realtime.messages;
create policy syntrix_approved_session_gate_insert on realtime.messages
  as restrictive for insert to authenticated
  with check (private.current_session_is_trusted());

-- 6. Apply a trusted-session check before every Data API request. The only
--    pending-session exception is register_device/list_devices, each of which
--    independently verifies auth.sessions and returns no workspace data.
create or replace function public.syntrix_check_session()
returns void language plpgsql security definer set search_path = '' as $$
declare
  v_claims jsonb;
  v_uid uuid;
  v_sid uuid;
  v_role text;
  v_path text;
begin
  begin
    v_claims := nullif(current_setting('request.jwt.claims', true), '')::jsonb;
  exception when others then
    return;
  end;

  v_role := coalesce(v_claims ->> 'role', '');
  if v_role <> 'authenticated' then return; end if;

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
$$;

revoke all on function public.syntrix_check_session() from public, anon, authenticated;
grant execute on function public.syntrix_check_session() to authenticated, authenticator, service_role;
alter role authenticator set pgrst.db_pre_request = 'public.syntrix_check_session';
notify pgrst, 'reload config';

-- Existing SECURITY DEFINER RPCs that call private.assert_active_session now
-- inherit the new approval check. These two previously lacked that assertion.
create or replace function public.find_profile_by_handle(p_handle text)
returns table (id uuid, handle text, display_name text, public_key text)
language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_handle text := lower(trim(coalesce(p_handle, '')));
begin
  perform private.assert_active_session();
  if v_uid is null then raise exception 'Authentication required'; end if;
  if v_handle !~ '^[a-z0-9_]{3,24}$' then return; end if;
  perform private.enforce_rate_limit(v_uid, 'lookup', 20, interval '1 minute');
  return query select p.id, p.handle, p.display_name, p.public_key
    from public.profiles p where p.handle = v_handle;
end;
$$;

create or replace function public.reset_my_key_bundle(
  p_public_key text, p_wrapped text, p_salt text, p_iterations integer
)
returns void language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
begin
  perform private.assert_active_session();
  if v_uid is null then raise exception 'Authentication required'; end if;
  perform private.enforce_rate_limit(v_uid, 'keys_reset', 5, interval '1 hour');

  delete from public.messages m where m.sender_id = v_uid or m.receiver_id = v_uid;
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
