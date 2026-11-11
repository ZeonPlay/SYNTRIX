# Deployment — Cloudflare Pages + Supabase Free

SYNTRIX is a static website. It does not need a Flask/Gunicorn server, a Socket.IO server, or a separate PostgreSQL host.

## 1. Prepare Supabase

1. Open your Supabase project.
2. Run `supabase/migrations/202611110001_initial_schema.sql` once in **SQL Editor**.
3. Confirm that `profiles`, `contacts`, and `messages` appear in the Table Editor.
4. Open **Project Settings → API** (or API Keys) and copy the Project URL and publishable key.
5. Put those two public values in `src/config.js` before deployment.
6. In **Authentication → URL Configuration**, add both the local development URL and your Cloudflare Pages domain to the allowed redirect URLs.
7. Under **Realtime → Settings**, turn off public access when available so that the `private: true` Presence channel is required.

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
   - Root directory: `/` (repository root)
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

## Notes about the free tier

Free plans have quotas and operational limits. Supabase Free projects can pause after a period of inactivity, and free services are not a production uptime guarantee. Check each provider's current dashboard and pricing page before a public demo. A static Cloudflare Pages deployment does not keep a paid server process running.
