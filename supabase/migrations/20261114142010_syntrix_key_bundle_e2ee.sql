-- SYNTRIX: use the existing wrapped-key bundle as the single E2EE key store.
-- The passphrase is used only in the browser. Supabase stores the wrapped
-- PKCS#8 private key, public P-256 point, salt and PBKDF2 work factor.

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

alter table private.user_keys enable row level security;
revoke all on private.user_keys from public, anon, authenticated;

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
as $syntrix$
declare
  v_uid uuid := auth.uid();
begin
  perform private.assert_active_session();
  if v_uid is null then
    raise exception 'Authentication required';
  end if;

  return query
    select p.public_key, k.wrapped_private_key, k.kdf_salt, k.kdf_iterations
      from public.profiles p
      join private.user_keys k on k.user_id = p.id
     where p.id = v_uid and p.public_key is not null;
end;
$syntrix$;

create or replace function public.set_my_key_bundle(
  p_public_key text,
  p_wrapped text,
  p_salt text,
  p_iterations integer
)
returns void
language plpgsql
security definer
set search_path = ''
as $syntrix$
declare
  v_uid uuid := auth.uid();
begin
  perform private.assert_active_session();
  if v_uid is null then
    raise exception 'Authentication required';
  end if;
  perform private.enforce_rate_limit(v_uid, 'keys_set', 10, interval '1 hour');

  if p_public_key is null or p_public_key !~ '^B[A-Za-z0-9+/]{86}=$'
     or p_wrapped is null or char_length(p_wrapped) not between 100 and 400
     or p_wrapped !~ '^[A-Za-z0-9+/]+={0,2}$'
     or p_salt is null or p_salt !~ '^[A-Za-z0-9+/]{22}==$'
     or p_iterations is null or p_iterations not between 100000 and 5000000 then
    raise exception 'invalid_key_bundle';
  end if;

  if exists (select 1 from private.user_keys k where k.user_id = v_uid) then
    raise exception 'keys_exist';
  end if;

  insert into private.user_keys (user_id, wrapped_private_key, kdf_salt, kdf_iterations)
  values (v_uid, p_wrapped, p_salt, p_iterations);

  update public.profiles set public_key = p_public_key where id = v_uid;
end;
$syntrix$;

create or replace function public.rewrap_my_key_bundle(
  p_old_wrapped text,
  p_wrapped text,
  p_salt text,
  p_iterations integer
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $syntrix$
declare
  v_uid uuid := auth.uid();
  v_count integer;
begin
  perform private.assert_active_session();
  if v_uid is null then
    raise exception 'Authentication required';
  end if;
  perform private.enforce_rate_limit(v_uid, 'keys_rewrap', 10, interval '1 hour');

  if p_old_wrapped is null
     or p_wrapped is null or char_length(p_wrapped) not between 100 and 400
     or p_wrapped !~ '^[A-Za-z0-9+/]+={0,2}$'
     or p_salt is null or p_salt !~ '^[A-Za-z0-9+/]{22}==$'
     or p_iterations is null or p_iterations not between 100000 and 5000000 then
    raise exception 'invalid_key_bundle';
  end if;

  update private.user_keys
     set wrapped_private_key = p_wrapped,
         kdf_salt = p_salt,
         kdf_iterations = p_iterations,
         updated_at = now()
   where user_id = v_uid and wrapped_private_key = p_old_wrapped;
  get diagnostics v_count = row_count;
  return v_count > 0;
end;
$syntrix$;

revoke all on function public.get_my_key_bundle() from public, anon;
revoke all on function public.set_my_key_bundle(text, text, text, integer) from public, anon;
revoke all on function public.rewrap_my_key_bundle(text, text, text, integer) from public, anon;
grant execute on function public.get_my_key_bundle() to authenticated;
grant execute on function public.set_my_key_bundle(text, text, text, integer) to authenticated;
grant execute on function public.rewrap_my_key_bundle(text, text, text, integer) to authenticated;

-- Remove the alternate E2EE API that sent a derived passphrase verifier to
-- Supabase. New clients only retrieve/store the encrypted key bundle.
drop function if exists public.get_e2ee_state();
drop function if exists public.enable_e2ee(text, text, text, text, text, integer);
drop function if exists public.get_e2ee_backup(text);
drop function if exists public.change_e2ee_passphrase(text, text, text, text, integer);
drop function if exists private.check_unlock_key(uuid, text);

alter table private.user_security
  drop column if exists e2ee_salt,
  drop column if exists e2ee_wrapped_key,
  drop column if exists e2ee_iterations,
  drop column if exists e2ee_enabled_at;
