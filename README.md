# SYNTRIX

**SYNTRIX** is a browser-based 1:1 chat and data-communication learning project. It demonstrates ECDH-based end-to-end encryption, AES-GCM message envelopes, ASCII framing, parity checking, NRZ-I line encoding, and real-time message exchange.

## Features

- Email/password authentication through Supabase Auth.
- Public SYNTRIX handles and contacts.
- One-to-one real-time messaging and online presence.
- End-to-end encrypted messages: encryption and decryption happen in the browser.
- ECDH P-256 identity keys; the private key is wrapped locally with AES-GCM using a PBKDF2-derived key.
- Encrypted private-key backup stored in the protected `private.user_keys` table. The plaintext passphrase and private key are never uploaded.
- A fresh AES-GCM message key for each message, wrapped separately for sender and recipient.
- Messages stored as a framed bitstream of a base64 ciphertext envelope, never as plaintext.
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

   | #  | Migration |
   |----|-----------|
   | 1  | `20261111122920_syntrix_initial_schema.sql` |
   | 2  | `20261112000000_syntrix_hardening.sql` |
   | 3  | `20261114000000_syntrix_device_alerts.sql` |
   | 4  | `20261114000001_fix_profiles_messages_rls_recursion.sql` |
   | 5  | `20261114142010_syntrix_key_bundle_e2ee.sql` |
   | 6  | `20261115000000_syntrix_device_tracking.sql` |
   | 7  | `20261116000000_syntrix_device_security_v2.sql` |
   | 8  | `20261116000001_syntrix_server_side_device_approval.sql` |
   | 9  | `20261116000002_syntrix_device_revocation_signal.sql` |
   | 10 | `20261116000003_syntrix_guard_legacy_workspace_rpcs.sql` |
   | 11 | `20261117000000_syntrix_e2ee_and_delete.sql` |
   | 12 | `20261118000000_syntrix_e2ee_hard_delete.sql` |
   | 13 | `20261119000000_syntrix_security_hardening.sql` |

   The list is sorted by file name, so it is also the order `supabase db reset` applies. Migration 12 permanently removes existing non-E2EE messages, removes per-user soft hiding, changes `delete_message_for_everyone` to physically delete rows, and configures Realtime DELETE events. It is intentionally destructive. Migration 13 is idempotent and is the final security layer (see [Security model](#security-model)).

3. Confirm that `profiles`, `contacts`, and `messages` appear in Table Editor. Wrapped private-key backups are stored in the unexposed `private.user_keys` table.
4. In **Project Settings → API**, copy the Project URL and publishable key.
5. Put those public values in `src/config.js`. Never put a `service_role` or secret key in browser code.
6. In **Authentication → URL Configuration**, add the local development URL and Cloudflare Pages domain to allowed redirect URLs.
7. In **Integrations → Data API**, expose the `public` schema and the tables/RPC functions used by the app. Keep the grants and RLS policies from the migrations intact.
8. Under **Realtime → Settings**, disable public access so the private Presence channel requires authenticated authorization.

Do not open `index.html` directly as a `file://` URL. Serve the directory over HTTP, for example:

```bash
python -m http.server 8000
```

Open `http://localhost:8000`.

Run the tests with Node.js 20 or newer:

```bash
npm test
```

## First-time E2EE setup

1. Create and sign in to an account.
2. Open E2EE settings and choose a passphrase of at least 12 characters (at least 6 distinct characters).
3. The browser generates an ECDH P-256 key pair. The public key is published in `profiles.public_key`; the private key is exported and encrypted locally with AES-GCM using a PBKDF2-derived wrapping key.
4. Only the wrapped private key, salt, and iteration count are saved in `private.user_keys`. The passphrase and plaintext private key never leave the browser.
5. Sign in to the second participant and activate E2EE there too.
6. Unlock E2EE on each device with that account's passphrase. The browser retrieves the wrapped backup and decrypts it locally.
7. Send a message. The browser encrypts it before framing/transmission. The recipient must have activated E2EE and unlocked their own private key to read it.

Keep the E2EE passphrase safe. The server cannot recover it. Losing it means the wrapped private key cannot be opened, and existing ciphertext cannot be decrypted.

## Message format and security scope

The browser encrypts each plaintext message with AES-GCM using a fresh random content key. That content key is separately wrapped for the sender and recipient using ECDH P-256 plus HKDF. The ciphertext envelope is base64-encoded and then converted to SYNTRIX's 10-bit printable-ASCII frames (start bit, seven data bits, even parity, stop bit). The resulting bits are visualized with NRZ-I.

The server stores ciphertext and public keys, not plaintext messages or plaintext private keys. This implementation uses persistent account ECDH identity keys; it does not implement forward secrecy or key transparency against a malicious server.

## Security model

- **Device approval is enforced on the server.** Trust is derived from the signed JWT `session_id`, never from a value the browser sends. A pending session can call only `register_device` and `list_devices`; workspace tables, private-key RPCs, and Presence are closed to it.
- **Only the first device is auto-trusted.** An account with no device rows gets a trusted first device. Every later device waits for a trusted device to approve it. Trusted devices are never deleted for inactivity, and each account may have at most 5 pending devices.
- **Manual recovery.** If every trusted device is lost, recovery is manual in SQL (set `acknowledged_at` on one `user_devices` row).
- **The private key cannot be exported from memory.** An unlocked key is kept non-extractable. It is cached in local IndexedDB for at most 7 days, after which the passphrase is requested again. Signing out clears it.
- **Changing the passphrase verifies the current one** by actually decrypting the stored backup with it.
- **Legacy RPCs are removed:** `reset_my_key_bundle`, `enable_e2ee`, `get_e2ee_backup`, `get_message_bits`, and the old unlock-key functions.

### Known limitations

- `@supabase/supabase-js` is loaded from `esm.sh`. Whoever serves the JavaScript can reach keys in the browser, so a web E2EE app has an inherent ceiling. Planned mitigation: bundle and self-host the library.
- Presence can be spoofed by an authenticated user, and the online-user list is visible to every trusted user.
- There is no fingerprint or warning when a contact's public key changes.
- There is no contact blocking: anyone who knows a handle can add it and send messages.
- The security of the private-key backup depends on passphrase strength if the encrypted blob leaks.

## Permanent message deletion

The **Hapus pesan** action is available on every message in a 1:1 conversation. Either participant may remove their own message or the other participant's message. The server checks that the caller is a participant, physically deletes the row, and the Realtime DELETE event causes both clients to animate the message out of the conversation. There is no "hide for me" mode or recoverable tombstone in the application.

## Deploy to Cloudflare Pages

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## License

See [`LICENSE`](LICENSE).