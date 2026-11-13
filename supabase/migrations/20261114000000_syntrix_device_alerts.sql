-- Device alerts: tell the original device when the account logs in elsewhere.
-- device_id stays server-side only (not selectable), so a new session cannot
-- impersonate a trusted device to dismiss the alert.

create table if not exists public.user_devices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  device_id text not null,
  label text not null,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  unique (user_id, device_id),
  constraint user_devices_device_id_len check (char_length(device_id) between 8 and 64),
  constraint user_devices_label_len check (char_length(label) between 1 and 80)
);

alter table public.user_devices enable row level security;

drop policy if exists user_devices_select_own on public.user_devices;
create policy user_devices_select_own on public.user_devices
  for select to authenticated using (user_id = (select auth.uid()));

revoke all on public.user_devices from anon, authenticated;
grant select (id, user_id, label, first_seen_at, last_seen_at, acknowledged_at)
  on public.user_devices to authenticated;

create or replace function public.register_device(p_device_id text, p_label text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  v_uid uuid := auth.uid();
  v_id uuid;
  v_label text := left(btrim(coalesce(p_label, '')), 80);
begin
  if v_uid is null then raise exception 'not_authenticated'; end if;
  if p_device_id is null or char_length(p_device_id) not between 8 and 64 then
    raise exception 'invalid_device';
  end if;
  if v_label = '' then v_label := 'Perangkat tidak dikenal'; end if;

  select id into v_id from public.user_devices where user_id = v_uid and device_id = p_device_id;
  if found then
    update public.user_devices set last_seen_at = now(), label = v_label where id = v_id;
    return v_id;
  end if;

  delete from public.user_devices where user_id = v_uid and last_seen_at < now() - interval '90 days';
  if (select count(*) from public.user_devices where user_id = v_uid) >= 25 then
    raise exception 'device_limit';
  end if;

  -- The first device (or the first once no trusted one is left) is trusted at once;
  -- every later device waits for a trusted device to acknowledge it.
  insert into public.user_devices (user_id, device_id, label, acknowledged_at)
  values (
    v_uid, p_device_id, v_label,
    case when exists (select 1 from public.user_devices where user_id = v_uid and acknowledged_at is not null)
      then null else now() end
  )
  returning id into v_id;
  return v_id;
end $$;

create or replace function public.acknowledge_devices(p_device_id text)
returns integer language plpgsql security definer set search_path = '' as $$
declare v_uid uuid := auth.uid(); v_count integer;
begin
  if v_uid is null then raise exception 'not_authenticated'; end if;
  if not exists (select 1 from public.user_devices
                 where user_id = v_uid and device_id = p_device_id and acknowledged_at is not null) then
    raise exception 'device_not_trusted';
  end if;
  update public.user_devices set acknowledged_at = now()
   where user_id = v_uid and acknowledged_at is null;
  get diagnostics v_count = row_count;
  return v_count;
end $$;

create or replace function public.reject_devices(p_device_id text)
returns integer language plpgsql security definer set search_path = '' as $$
declare v_uid uuid := auth.uid(); v_count integer;
begin
  if v_uid is null then raise exception 'not_authenticated'; end if;
  if not exists (select 1 from public.user_devices
                 where user_id = v_uid and device_id = p_device_id and acknowledged_at is not null) then
    raise exception 'device_not_trusted';
  end if;
  delete from public.user_devices where user_id = v_uid and acknowledged_at is null;
  get diagnostics v_count = row_count;
  return v_count;
end $$;

revoke all on function public.register_device(text, text), public.acknowledge_devices(text), public.reject_devices(text) from public, anon;
grant execute on function public.register_device(text, text), public.acknowledge_devices(text), public.reject_devices(text) to authenticated;

do $$ begin
  alter publication supabase_realtime drop table public.user_devices;
exception when undefined_object then null;
end $$;
alter publication supabase_realtime add table public.user_devices (id, user_id, label, first_seen_at, last_seen_at, acknowledged_at);
