-- Ensure the two legacy SECURITY DEFINER RPCs cannot bypass device approval.
create or replace function public.find_profile_by_handle(p_handle text)
returns table (id uuid, handle text, display_name text, public_key text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_handle text := lower(trim(coalesce(p_handle, '')));
begin
  perform private.assert_active_session();
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

create or replace function public.reset_my_key_bundle(
  p_public_key text,
  p_wrapped text,
  p_salt text,
  p_iterations integer
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
begin
  perform private.assert_active_session();
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

  update public.profiles
     set public_key = p_public_key
   where id = v_uid;
end;
$$;
