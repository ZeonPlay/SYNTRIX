-- Device tracking, part 2 (additive). Run once in the Supabase SQL Editor,
-- AFTER 20261114000000_syntrix_device_alerts.sql.
--
-- 1. "Bukan aku" now revokes the unknown session on the server instead of only
--    deleting the row, so the unknown device cannot simply register again.
-- 2. Each device records when it connected and an approximate location.
--
-- IP and location columns are deliberately NOT granted to the Data API. An
-- attacker session belongs to the same user, so a plain SELECT would reveal
-- where the real owner is. They are only returned by list_pending_devices(),
-- and only to a device that is already trusted.

alter table public.user_devices
  add column if not exists session_id uuid,
  add column if not exists ip_address text,
  add column if not exists country text,
  add column if not exists region text,
  add column if not exists city text;

-- ---------------------------------------------------------------------
-- register_device: also stores session, IP and approximate location.
-- It doubles as the heartbeat, so it fails once the session was revoked.
-- ---------------------------------------------------------------------
create or replace function public.register_device(p_device_id text, p_label text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := nullif(auth.jwt() ->> 'session_id', '')::uuid;
  v_id uuid;
  v_label text := left(btrim(coalesce(p_label, '')), 80);
  v_headers json;
  v_ip text;
  v_country text;
  v_region text;
  v_city text;
begin
  if v_uid is null then raise exception 'not_authenticated'; end if;
  if p_device_id is null or char_length(p_device_id) not between 8 and 64 then
    raise exception 'invalid_device';
  end if;
  if v_label = '' then v_label := 'Perangkat tidak dikenal'; end if;

  -- A session removed by "Bukan aku" may still hold an unexpired access token.
  if v_sid is not null and not exists (select 1 from auth.sessions s where s.id = v_sid) then
    raise exception 'session_revoked';
  end if;

  -- Request metadata added by the edge, not by the browser. Any header that is
  -- missing simply stays null.
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
  v_ip := nullif(v_ip, '');

  v_country := upper(nullif(btrim(v_headers ->> 'cf-ipcountry'), ''));
  if v_country is null or v_country !~ '^[A-Z]{2}$' or v_country in ('XX', 'T1') then
    v_country := null;
  end if;
  v_region := left(nullif(btrim(coalesce(v_headers ->> 'cf-region', v_headers ->> 'cf-region-code')), ''), 80);
  v_city := left(nullif(btrim(v_headers ->> 'cf-ipcity'), ''), 80);

  select id into v_id from public.user_devices where user_id = v_uid and device_id = p_device_id;
  if found then
    update public.user_devices
       set last_seen_at = now(), label = v_label, session_id = v_sid,
           ip_address = v_ip, country = v_country, region = v_region, city = v_city
     where id = v_id;
    return v_id;
  end if;

  delete from public.user_devices where user_id = v_uid and last_seen_at < now() - interval '90 days';
  if (select count(*) from public.user_devices where user_id = v_uid) >= 25 then
    raise exception 'device_limit';
  end if;

  -- The first device (or the first once no trusted one is left) is trusted at once;
  -- every later device waits for a trusted device to acknowledge it.
  insert into public.user_devices (
    user_id, device_id, label, acknowledged_at,
    session_id, ip_address, country, region, city
  )
  values (
    v_uid, p_device_id, v_label,
    case when exists (select 1 from public.user_devices where user_id = v_uid and acknowledged_at is not null)
      then null else now() end,
    v_sid, v_ip, v_country, v_region, v_city
  )
  returning id into v_id;
  return v_id;
end $$;

-- ---------------------------------------------------------------------
-- list_pending_devices: unknown devices with location and times, returned
-- only to a trusted device.
-- ---------------------------------------------------------------------
create or replace function public.list_pending_devices(p_device_id text)
returns table (
  id uuid,
  label text,
  first_seen_at timestamptz,
  last_seen_at timestamptz,
  ip_address text,
  country text,
  region text,
  city text
) language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then raise exception 'not_authenticated'; end if;
  if not exists (
    select 1 from public.user_devices t
     where t.user_id = v_uid and t.device_id = p_device_id and t.acknowledged_at is not null
  ) then
    return;
  end if;

  return query
    select d.id, d.label, d.first_seen_at, d.last_seen_at,
           d.ip_address, d.country, d.region, d.city
      from public.user_devices d
     where d.user_id = v_uid and d.acknowledged_at is null
     order by d.first_seen_at desc;
end $$;

-- ---------------------------------------------------------------------
-- reject_devices: remove unknown devices AND revoke their sessions.
-- The return type changes from integer to jsonb, so drop the old one first.
-- ---------------------------------------------------------------------
drop function if exists public.reject_devices(text);

create function public.reject_devices(p_device_id text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_sid uuid := nullif(auth.jwt() ->> 'session_id', '')::uuid;
  v_sessions uuid[];
  v_unmapped integer;
  v_removed integer;
  v_revoked integer;
begin
  if v_uid is null then raise exception 'not_authenticated'; end if;
  if not exists (select 1 from public.user_devices
                 where user_id = v_uid and device_id = p_device_id and acknowledged_at is not null) then
    raise exception 'device_not_trusted';
  end if;

  select coalesce(array_agg(session_id) filter (where session_id is not null), '{}'),
         count(*) filter (where session_id is null)
    into v_sessions, v_unmapped
    from public.user_devices
   where user_id = v_uid and acknowledged_at is null;

  delete from public.user_devices where user_id = v_uid and acknowledged_at is null;
  get diagnostics v_removed = row_count;

  -- Deleting the session also removes its refresh tokens, so it cannot renew.
  delete from auth.sessions
   where user_id = v_uid and id = any (v_sessions) and id is distinct from v_sid;
  get diagnostics v_revoked = row_count;

  -- "unmapped" counts unknown devices from before session tracking existed;
  -- the client signs out other sessions as a fallback when it is above zero.
  return jsonb_build_object('removed', v_removed, 'revoked', v_revoked, 'unmapped', v_unmapped);
end $$;

revoke all on function
  public.register_device(text, text),
  public.list_pending_devices(text),
  public.reject_devices(text)
  from public, anon;
grant execute on function
  public.register_device(text, text),
  public.list_pending_devices(text),
  public.reject_devices(text)
  to authenticated;
