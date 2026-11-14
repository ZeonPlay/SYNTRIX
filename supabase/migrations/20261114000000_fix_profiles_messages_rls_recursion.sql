-- Fix recursive RLS evaluation between profiles and messages.
--
-- The old profiles SELECT policy queried public.messages to discover senders.
-- The messages INSERT policy queries public.profiles to verify public keys.
-- That creates an RLS cycle:
--   profiles -> messages -> profiles
--
-- Contacts already represent the allowed relationship for profile discovery,
-- so the messages lookup is redundant and must not be part of this policy.

drop policy if exists "Users can read own and related profiles" on public.profiles;

create policy "Users can read own and related profiles"
  on public.profiles
  for select
  to authenticated
  using (
    id = (select auth.uid())
    or exists (
      select 1
      from public.contacts c
      where c.owner_id = (select auth.uid())
        and c.contact_id = profiles.id
    )
  );
