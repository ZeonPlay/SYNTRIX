# SYNTRIX

**SYNTRIX** is a browser-based 1:1 chat and data-communication learning project. It demonstrates ECDH-based end-to-end encryption, AES-GCM message envelopes, ASCII framing, parity checking, NRZ-I line encoding, and real-time message exchange.

## Features

- Email/password authentication through Supabase Auth.
- Public SYNTRIX handles and contacts.
- One-to-one real-time messaging and online presence.
- End-to-end encrypted messages: encryption and decryption happen in the browser.
- ECDH P-256 identity keys; the private key is wrapped locally with AES-GCM using a PBKDF2-derived key.
- Encrypted private-key backup stored in \`private.user_security\`; the plaintext passphrase and private key are never uploaded.
- A fresh AES-GCM message key for each message, wrapped separately for sender and recipient.
- Messages stored as a framed bitstream of a base64 ciphertext envelope, never as plaintext.
- NRZ-I waveform preview and transmission inspector.
- Telegram-style permanent deletion: either participant can delete any message in their 1:1 conversation; the database row is deleted and Realtime notifies both clients.
- Device tracking, trusted-device approval, and revoked-session blocking.

## Stack

- HTML, CSS, and native JavaScript ES modules.
- Supabase Auth, PostgreSQL, Row Level Security, RPC functions, and Realtime.
- Cloudflare Pages for static hosting.
- \`@supabase/supabase-js\` pinned through the ESM CDN; no application server is required.

## Local setup

1. Create or use a Supabase project.
2. In **Supabase Dashboard → SQL Editor**, run the migrations in this exact order, once each:
   1. \`20261111122920_syntrix_initial_schema.sql\`
   2. \`20261112000000_syntrix_hardening.sql\`
   3. \`20261114000000_syntrix_device_alerts.sql\`
   4. \`20261115000000_syntrix_device_tracking.sql\`
   5. \`20261116000000_syntrix_device_security_v2.sql\`
   6. \`20261117000000_syntrix_e2ee_and_delete.sql\`
   7. \`20261118000000_syntrix_e2ee_hard_delete.sql\`
   
   The last migration is intentionally destructive: it permanently removes existing non-E2EE messages and replaces the earlier soft-delete behaviour with hard deletion. Do not skip it when using this frontend.
3. Confirm that \`profiles\`, \`contacts\`, and \`messages\` appear in the Table Editor. The \`private\` schema is used for protected key backup and security data.
4. In **Project Settings → API**, copy the Project URL and publishable key.
5. Put those public values in \`src/config.js\`. Never put a \`service_role\` or secret API key in browser code.
6. In **Authentication → URL Configuration**, add the local development URL and Cloudflare Pages domain to allowed redirect URLs.
7. In **Integrations → Data API**, expose the \`public\` schema and the tables/RPC functions used by the app. Keep the grants and RLS policies from the migrations intact.
8. Under **Realtime → Settings**, disable public access so the private Presence channel requires authenticated authorization.

Do not open \`index.html\` directly as a \`file://\` URL. Serve the directory over HTTP, for example:

\`\`\`bash
python -m http.server 8000
\`\`\`

Open \`http://localhost:8000\`.

Run the tests with Node.js 20 or newer:

\`\`\`bash
npm test
\`\`\`

## First-time E2EE setup

1. Create and sign in to an account.
2. Set a new E2EE passphrase (at least 10 characters). If the account already had the old message unlock key, enter that old key once to prove account ownership during migration.
3. The browser generates an ECDH P-256 key pair. The public key is published in \`profiles.public_key\`; the private key is encrypted locally and only its wrapped backup is stored in \`private.user_security.e2ee_wrapped_key\`.
4. Sign in to the second participant and activate E2EE there too.
5. Unlock E2EE on the current device with the passphrase. The passphrase is used locally to derive a wrapping key and an authentication token; only the derived token is sent to the server for rate-limited bcrypt verification.
6. Send a message. The browser encrypts it before framing/transmission. The recipient must have activated E2EE and unlocked their own private key to read it.

Keep the E2EE passphrase safe. The server cannot recover it. Losing it means the wrapped private key cannot be opened, and existing ciphertext cannot be decrypted.

## Message format and security scope

The browser encrypts each plaintext message with AES-GCM using a fresh random content key. That content key is separately wrapped for the sender and recipient using ECDH P-256 plus HKDF. The ciphertext envelope is base64-encoded and then converted to SYNTRIX's 10-bit printable-ASCII frames (start bit, seven data bits, even parity, stop bit). The resulting bits are visualized with NRZ-I.

The server stores ciphertext and public keys, not plaintext messages or plaintext private keys. This implementation uses persistent account ECDH identity keys; it does not implement forward secrecy or key transparency against a malicious server.

## Permanent message deletion

The **Hapus pesan** action is available on every message in a 1:1 conversation. Either participant may remove their own message or the other participant's message. The server checks that the caller is a participant, physically deletes the row, and the Realtime DELETE event causes both clients to animate the message out of the conversation. There is no "hide for me" mode or recoverable tombstone in the application.

## Deploy to Cloudflare Pages

See [\`docs/DEPLOYMENT.md\`](docs/DEPLOYMENT.md).

## License

See [\`LICENSE\`](LICENSE).
