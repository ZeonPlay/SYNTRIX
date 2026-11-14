-- Reapply the final user_devices RLS rule after the base approval policy.
-- A rejected browser may receive only its own revoked row over an already-open
-- Realtime subscription. HTTP/Data API access is still denied by the pre-request
-- guard because its Auth session has been deleted.
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
revoke all on function private.current_session_is_revoked() from public, anon, authenticated;
grant execute on function private.current_session_is_revoked() to authenticated;

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
