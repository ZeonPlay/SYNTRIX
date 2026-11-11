# SYNTRIX

**SYNTRIX** is a browser-based real-time chat and data-communication learning project. It demonstrates ASCII framing, parity checking, NRZ-I line encoding, and live message exchange.

This repository is an independent implementation. It uses a different architecture and original source code while preserving the learning goals and user-facing capabilities of the reference project.

## Features

- Email and password registration/login through Supabase Auth.
- Unique public SYNTRIX handle (3–24 lowercase letters, numbers, or underscores).
- Add contacts by handle and search the contact list.
- One-to-one messaging with live delivery through Supabase Realtime.
- Online/offline status through Realtime Presence.
- Persistent conversations, unread counts, and read receipts.
- Messages stored as a 10-bit-per-character ASCII bitstream.
- Per-message unlock-key check; the key is stored as a server-side bcrypt hash.
- NRZ-I waveform preview and a transmission inspector showing frames, data bits, parity, and signal.
- Responsive layout for desktop and mobile.

## Stack

- HTML, CSS, and native JavaScript ES modules.
- Supabase Auth, PostgreSQL, Row Level Security, and Realtime.
- Cloudflare Pages for static hosting.
- `@supabase/supabase-js` pinned to `2.119.0` through the ESM CDN; no build tool or paid server is required.

## Local setup

1. Create or use a Supabase project.
2. Open `supabase/migrations/202611110001_initial_schema.sql` and run it once in **Supabase Dashboard → SQL Editor**.
3. In **Authentication → URL Configuration**, add your local URL (for example `http://localhost:8000`) to the allowed redirect URLs.
4. Open `src/config.js`. Set `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` to the URL and publishable key from your own project. The publishable key is intended for browser use; never put a `service_role` or secret key in this repository.
5. Serve this directory through a local static web server. For example:

   ```bash
   python -m http.server 8000
   ```

6. Open `http://localhost:8000`.
7. Run the encoding test suite with `npm test` (Node.js 20+ recommended).

Do not open `index.html` directly as a `file://` URL; browser ES modules need an HTTP origin.

## Supabase setup notes

- The SQL migration creates the `profiles`, `contacts`, and `messages` tables, adds indexes and Row Level Security policies, creates the profile trigger and unlock-key RPC functions, and registers `messages` in the `supabase_realtime` publication.
- The Realtime Presence topic is `syntrix:live`. The migration limits Presence access to authenticated users. In Supabase Realtime settings, disable public access if the project setting currently allows public channels.
- Hosted Supabase projects commonly require email confirmation. Keep it enabled for real use; for a quick local classroom demo, you may disable confirmation in **Authentication → Providers → Email** and re-enable it before public use.
- The public profile directory exposes only the handle and display name to signed-in users so that a handle can be resolved when adding a contact.
- In **Integrations → Data API**, expose the `public` schema and ensure `profiles`, `contacts`, `messages`, plus the three unlock-key RPC functions are available to the authenticated client. The migration includes least-privilege SQL grants; RLS remains the row-level access boundary.

## Message format and security scope

Each printable ASCII character becomes one 10-bit frame:

```text
Start (0) + Data (7 bits) + Even parity (1 bit) + Stop (1)
```

The resulting bitstream is stored in PostgreSQL and encoded to NRZ-I for the waveform visualization. In NRZ-I, a bit `1` toggles the signal level and a bit `0` keeps the previous level.

**Important:** this bitstream is reversible data framing, not cryptographic encryption. The unlock key is a separate application access check, stored as a bcrypt hash and rate-limited by the database function. It does not make message contents end-to-end encrypted or unreadable to someone with database access. Do not use this demo to exchange sensitive information.

Supabase Auth handles password hashing and session management; passwords are never stored in the application tables.

## Deploy to Cloudflare Pages

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## License

See [`LICENSE`](LICENSE).
