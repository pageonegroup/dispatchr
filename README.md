# Dispatchr backend

The server piece of Dispatchr. It does the two things the browser **can't** do safely:

1. **Create logins** (agency users, clients) via the Supabase admin API — because setting someone else's password requires the service-role key.
2. **Broker Google Drive** — upload files to your Gmail Drive (OAuth) and stream downloads back only to people allowed to see the project.

Everything else (reading data, creating/editing projects, acknowledging files) the front-end does **directly** against Supabase, guarded by the RLS policies in `dispatchr-schema.sql`.

---

## Go-live order

### 1. Supabase
- Create a project. SQL editor → run `dispatchr-schema.sql`.
- Project settings → API: copy `URL`, `anon` key, and `service_role` key.
- Create your first super admin (SQL editor, one time):
  ```sql
  -- after creating the auth user in Authentication > Users:
  insert into profiles (id, role, display_name)
  values ('<that-users-uuid>', 'super_admin', 'Super Admin');
  ```

### 2. Google Cloud (Drive OAuth — personal Gmail)
- console.cloud.google.com → new project → enable **Google Drive API**.
- OAuth consent screen: External, add your Gmail as a **test user** (keeps it in testing mode, which is fine for one account).
- Credentials → OAuth client ID → **Web application**.
  - Authorised redirect URI: `https://<your-backend>.up.railway.app/drive/callback`
- Copy the client ID + secret into Railway env.

### 3. Railway
- New project → deploy this folder from GitHub.
- Add the env vars from `.env.example` (Supabase keys, Google client id/secret, redirect URI, allowed origins).
- Deploy. Then visit `https://<your-backend>.up.railway.app/drive/connect` once, approve, and copy the printed **refresh token** into `GOOGLE_REFRESH_TOKEN`. Redeploy.
- Create your destination folder in Google Drive, copy its ID from the URL into `DRIVE_ROOT_FOLDER_ID`.

### 4. GitHub
- Push this repo; Railway auto-deploys on push.

### 5. Front-end
- Point the prototype at Supabase (`@supabase/supabase-js` in the browser with the **anon** key) for reads/writes, and at this backend for uploads/downloads and user creation.

---

## Endpoints
| Method | Path | Who | Purpose |
|---|---|---|---|
| GET  | `/drive/connect` | (browser, once) | Start Google OAuth |
| GET  | `/drive/callback` | Google | Returns the refresh token |
| GET  | `/drive/status` | super admin | Connected account email |
| POST | `/agency-users` | super admin | Create agency login |
| POST | `/clients` | agency | Create client login (series auto) |
| POST | `/projects/:id/files` | agency member | Upload → Drive → `files` row |
| GET  | `/files/:id/download` | anyone allowed | Access-checked stream from Drive |

## Security notes
- `service_role` key and `GOOGLE_REFRESH_TOKEN` are powerful secrets — Railway env only, never in the front-end or git.
- The OAuth scope is `drive.file` (the app can only touch files it creates), not full Drive access.
- Download access reuses the `can_see_project` RLS function, called **as the requesting user**, so the broker can't leak another client's files.
