# Deployment — Cloudflare Pages + Supabase

SYNTRIX is a static website. It does not need a Flask/Gunicorn server, a Socket.IO server, or a separate application server.

## 1. Prepare Supabase

1. Open your Supabase project.
2. Run the migrations in this exact order, once each, in **SQL Editor**:
   1. \`20261111122920_syntrix_initial_schema.sql\`
   2. \`20261112000000_syntrix_hardening.sql\`
   3. \`20261114000000_syntrix_device_alerts.sql\`
   4. \`20261115000000_syntrix_device_tracking.sql\`
   5. \`20261116000000_syntrix_device_security_v2.sql\`
   6. \`20261117000000_syntrix_e2ee_and_delete.sql\`
   7. \`20261118000000_syntrix_e2ee_hard_delete.sql\`
   8. \`20261114142010_syntrix_key_bundle_e2ee.sql\`

   The hard-delete migration permanently removes existing non-E2EE messages, removes per-user soft hiding, changes \`delete_message_for_everyone\` to physically delete rows, and configures Realtime DELETE events. It is intentionally destructive.

   The key-bundle migration makes \`private.user_keys\` the single E2EE backup store. The passphrase never goes to Supabase; the browser stores only a wrapped private-key backup, its salt, and the PBKDF2 iteration count. It also removes the temporary alternate E2EE RPCs that used a server-checked derived verifier.

   The device-security migration sets \`pgrst.db_pre_request\` for the \`authenticator\` role. It replaces any pre-request function you configured yourself. To undo that setting: \`alter role authenticator reset pgrst.db_pre_request; notify pgrst, 'reload config';\`.
3. Confirm that \`profiles\`, \`contacts\`, and \`messages\` appear in Table Editor. Wrapped private-key backups are stored in the unexposed \`private.user_keys\` table.
4. Open **Project Settings → API** and copy the Project URL and publishable key.
5. Put those public values in \`src/config.js\`. Never use a \`service_role\` or secret API key in client code.
6. In **Authentication → URL Configuration**, add your local development URL and Cloudflare Pages domain to allowed redirect URLs.
7. In **Integrations → Data API**, expose the \`public\` schema and the tables/RPC functions created by these migrations. Do not remove their column grants or RLS policies.
8. Under **Realtime → Settings**, disable public access so the private Presence channel requires authenticated authorization.

## 2. Push this repository to GitHub

Push the project to \`ZeonPlay/SYNTRIX\`. The repository root should contain \`index.html\`, \`src/\`, \`assets/\`, \`_headers\`, and \`supabase/\`.

## 3. Create the Cloudflare Pages site

1. Open **Workers & Pages → Create → Pages → Connect to Git**.
2. Select \`ZeonPlay/SYNTRIX\` and the \`main\` branch.
3. Use these settings:
   - Framework preset: **None**
   - Build command: leave empty
   - Build output directory: \`.\`
   - Root directory: repository root
4. Deploy. Every push to \`main\` triggers a static deployment.

## 4. First-time verification

- Create a test account. If email confirmation is enabled, confirm the address before signing in.
- Activate E2EE with a passphrase of at least 10 characters. The passphrase stays in the browser; Supabase only receives the wrapped key bundle.
- Existing accounts with a row in \`private.user_keys\` should unlock that saved bundle rather than generate a new identity.
- Create a second test account in a private/incognito window or another browser and activate E2EE on that account too.
- Add the second account by handle. Verify both profiles have a public key before attempting to send.
- Send \`HELLO 123\`. Confirm the receiver can decrypt it after unlocking E2EE with their own passphrase.
- Refresh both browsers, unlock E2EE again, and verify conversation history can be decrypted.
- Send a message from each participant. Delete each other's messages in turn. Verify the message row disappears from the Supabase \`messages\` table and both clients remove the bubble through the Realtime delete event.
- Test with a third account. It must not be able to list or decrypt messages from the unrelated conversation.
- Device security: sign in with the same account in a second browser. Check the trusted-device approval and revocation flow.

## Notes about permanent deletion

The application performs a PostgreSQL DELETE for the message row. It does not retain a tombstone or a per-user hidden copy. Supabase's configured database backups / point-in-time recovery are separate from the live application tables and may have their own retention policy.

## Notes about the free tier

Free plans have quotas and operational limits. Supabase Free projects can pause after inactivity, and free services are not a production uptime guarantee. Check provider dashboards before a public demo.
