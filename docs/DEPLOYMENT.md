# Deployment — Cloudflare Pages + Supabase Free

SYNTRIX is a static website. It does not need a Flask/Gunicorn server, a Socket.IO server, or a separate PostgreSQL host.

## 1. Prepare Supabase

1. Open your Supabase project.
2. Run all five migrations once in **SQL Editor**, in this order: `supabase/migrations/20261111122920_syntrix_initial_schema.sql`, `20261112000000_syntrix_hardening.sql`, `20261114000000_syntrix_device_alerts.sql`, `20261115000000_syntrix_device_tracking.sql`, then `20261116000000_syntrix_device_security_v2.sql`. The app needs the second one (it adds `frame_count`, `get_message_bits`, `change_message_unlock_key`, and `find_profile_by_handle`) and the last three for device security: the fourth adds the connection time and approximate location, and the fifth adds per-device "Ini aku" / "Bukan aku", instant sign-out of a rejected device, and server-side blocking of revoked sessions.
   - The fifth migration also sets `pgrst.db_pre_request` on the `authenticator` role so the Data API refuses requests from a revoked session. It replaces any pre-request function you configured yourself. To undo it: `alter role authenticator reset pgrst.db_pre_request; notify pgrst, 'reload config';`.
3. Confirm that `profiles`, `contacts`, and `messages` appear in the Table Editor.
4. Open **Project Settings → API** (or API Keys) and copy the Project URL and publishable key.
5. Put those two public values in `src/config.js` before deployment.
6. In **Authentication → URL Configuration**, add both the local development URL and your Cloudflare Pages domain to the allowed redirect URLs.
7. In **Integrations → Data API**, ensure the `public` schema and tables `profiles`, `contacts`, and `messages` are exposed; the migrations' grants and RLS policies restrict actual access. Also make sure the RPC functions created by the migrations are exposed.
8. Under **Realtime → Settings**, disable public access so that the `private: true` Presence channel requires the authenticated policies from the migration.

Never copy a `service_role` key or secret API key into `src/config.js`, HTML, JavaScript, Cloudflare build variables exposed to the browser, or GitHub.

## 2. Push this repository to GitHub

Push the project to `ZeonPlay/SYNTRIX`. The repository root should contain `index.html`, `src/`, `assets/`, `_headers`, and `supabase/`.

## 3. Create the Cloudflare Pages site

1. Sign in to Cloudflare Dashboard.
2. Open **Workers & Pages → Create → Pages → Connect to Git**.
3. Select `ZeonPlay/SYNTRIX` and the `main` branch.
4. Use these settings:
   - Framework preset: **None**
   - Build command: leave empty
   - Build output directory: `.`
   - Root directory: leave blank (repository root)
5. Deploy. The generated `*.pages.dev` URL is your website address.

Every push to `main` will trigger a new static deployment.

## 4. First-time verification

- Create a test account and verify the email if confirmation is enabled.
- Sign in and set an unlock key (minimum six characters).
- Create a second test account in a private/incognito window or another browser.
- Add the second account by its SYNTRIX handle.
- Send a short ASCII message such as `HELLO 123` and confirm that the receiver sees it without refreshing.
- Open the message with the receiver's own unlock key and inspect the frames and NRZ-I waveform.
- Refresh both clients, sign in again, and confirm conversation history is restored.
- Verify that one user cannot read another unrelated user's messages by testing with a third account.
- Device security: sign in with the same account in a second browser. The first browser should show a toast and a red dot on **Keamanan** within a second or two, with the new device's location, IP and login time. Press **Bukan aku**: the second browser must sign itself out immediately. Sign in there again and press **Ini aku** instead; the card should move to the trusted list.

## Notes about the free tier

Free plans have quotas and operational limits. Supabase Free projects can pause after a period of inactivity, and free services are not a production uptime guarantee. Check each provider's current dashboard and pricing page before a public demo. A static Cloudflare Pages deployment does not keep a paid server process running.
