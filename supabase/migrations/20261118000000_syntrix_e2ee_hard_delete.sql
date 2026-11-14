-- SYNTRIX corrective migration 20261118000000
-- Aligns the previously-applied E2EE migration with permanent Telegram-style deletion.
-- Run once, AFTER 20261117000000_syntrix_e2ee_and_delete.sql.

-- Old messages were stored as reversible plaintext bitstreams (enc_version = 0).
-- The product decision is to discard them, not to expose a legacy decrypt path.
delete from public.messages
 where enc_version <> 1
    or payload_bits is null
    or deleted_at is not null;

-- Per-user soft hiding is not part of the chosen deletion behaviour.
drop function if exists public.hide_message_for_me(uuid);
drop table if exists public.message_hidden;

-- Either participant may permanently remove any message in their 1:1 conversation.
-- The participant check is inside this SECURITY DEFINER function; clients do not
-- receive direct DELETE privileges on the messages table.
create or replace function public.delete_message_for_everyone(p_message_id uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_count integer;
begin
  perform private.assert_active_session();
  perform private.enforce_rate_limit(v_uid, 'delete', 60, interval '1 minute');

  delete from public.messages m
   where m.id = p_message_id
     and (m.sender_id = v_uid or m.receiver_id = v_uid);
  get diagnostics v_count = row_count;
  return v_count > 0;
end;
$$;

revoke all on function public.delete_message_for_everyone(uuid) from public, anon;
grant execute on function public.delete_message_for_everyone(uuid) to authenticated;

-- Publish hard-delete events so the other participant's client can remove the
-- message immediately. DELETE filters use sender_id / receiver_id; replica identity
-- FULL ensures those fields are available to the publication's change stream.
alter table public.messages replica identity full;

do $$
begin
  if exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'messages'
  ) then
    alter publication supabase_realtime drop table public.messages;
  end if;

  -- REPLICA IDENTITY FULL requires the publication to include all columns.
  -- Realtime filters sender_id / receiver_id for each participant.
  alter publication supabase_realtime
    add table public.messages;

  if exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'message_hidden'
  ) then
    alter publication supabase_realtime drop table public.message_hidden;
  end if;
end;
$$;

-- Private key backups remain wrapped by an AES-GCM key derived locally from the
-- user's passphrase. No raw private key or plaintext passphrase is stored here.
