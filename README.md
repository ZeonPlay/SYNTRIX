# SYNTRIX

**SYNTRIX** is a browser-based 1:1 chat and data-communication learning project. It demonstrates ECDH-based end-to-end encryption, AES-GCM message envelopes, ASCII framing, parity checking, NRZ-I line encoding, and real-time message exchange.

## Features

- Email/password authentication through Supabase Auth.
- Public SYNTRIX handles and contacts.
- One-to-one real-time messaging and online presence.
- End-to-end encrypted messages: encryption and decryption happen in the browser.
- ECDH P-256 identity keys; the private key is wrapped locally with AES-GCM using a PBKDF2-derived key.
- Encrypted private-key backup stored in the protected `private.user_keys` table. The plaintext passphrase and private key are never uploaded.
- The passphrase is never sent to Supabase; only the encrypted key bundle, public key, salt, and KDF iteration count are stored.
- A fresh AES-GCM message key for each message, wrapped separately for sender and recipient.
- Messages stored as a base64 ciphertext envelope, never as plaintext. The framed bitstream is used for transmission and display.
- NRZ-I waveform preview and transmission inspector.
- Telegram-style permanent deletion: either participant can delete any message in their 1:1 conversation; the database row is deleted and Realtime notifies both clients.
- Device tracking, trusted-device approval, and revoked-session blocking.

## Stack

- HTML, CSS, and native JavaScript ES modules.
- Supabase Auth, PostgreSQL, Row Level Security, RPC functions, and Realtime.
- Cloudflare Pages for static hosting.
- `@supabase/supabase-js` pinned through the ESM CDN; no application server is required.

## Local setup

1. Create or use a Supabase project.
2. In **Supabase Dashboard → SQL Editor**, run the migrations in this exact order, once each:
   1. `20261111122920_syntrix_initial_schema.sql`
   2. `20261112000000_syntrix_hardening.sql`
   3. `20261114000000_syntrix_device_alerts.sql`
   4. `20261114000001_fix_profiles_messages_rls_recursion.sql`
   5. `20261114142010_syntrix_key_bundle_e2ee.sql`
   6. `20261115000000_syntrix_device_tracking.sql`
   7. `20261116000000_syntrix_device_security_v2.sql`
   8. `20261116000001_syntrix_server_side_device_approval.sql`
   9. `20261116000002_syntrix_device_revocation_signal.sql`
   10. `20261116000003_syntrix_guard_legacy_workspace_rpcs.sql`
   11. `20261117000000_syntrix_e2ee_and_delete.sql`
   12. `20261118000000_syntrix_e2ee_hard_delete.sql`
   13. `20261119000000_syntrix_security_hardening.sql`

   The hard-delete migration permanently removes existing non-E2EE messages, removes per-user soft hiding, changes `delete_message_for_everyone` to physically delete rows, and configures Realtime DELETE events. It is intentionally destructive.
3. Confirm that `profiles`, `contacts`, and `messages` appear in Table Editor. Wrapped private-key backups are stored in the unexposed `private.user_keys` table.
4. In **Project Settings → API**, copy the Project URL and publishable key.
5. Put those public values in `src/config.js`. Never put a `service_role` or secret API key in browser code.
6. In **Authentication → URL Configuration**, add the local development URL and Cloudflare Pages domain to allowed redirect URLs.
7. In **Project Settings → API → Exposed schemas**, expose the `public` schema and the tables/RPC functions used by the app. Keep the grants and RLS policies from the migrations intact.
8. Under **Realtime → Settings**, disable public access so the private Presence channel requires authenticated authorization.

Do not open `index.html` directly as a `file://` URL. Serve the directory over HTTP, for example:

```bash
python -m http.server 8000
