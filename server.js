// ============================================================
// Dispatchr backend (Railway)
// Two jobs only a server can do:
//   1. Create logins (agency users, clients) via Supabase admin API
//   2. Broker Google Drive: upload as your Gmail account (OAuth), download with access checks
// Everything else (reads, project CRUD, acknowledge) the browser does
// directly against Supabase, protected by the RLS policies in dispatchr-schema.sql.
// ============================================================
import express from "express";
import cors from "cors";
import multer from "multer";
import { createClient } from "@supabase/supabase-js";
import { google } from "googleapis";
import { Readable } from "node:stream";

const {
  SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ANON_KEY,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
  GOOGLE_REFRESH_TOKEN, DRIVE_ROOT_FOLDER_ID,
  ALLOWED_ORIGINS = "", PORT = 8080,
} = process.env;

// Service-role client: full access, bypasses RLS. Backend only.
const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});
// Anon client: used only to resolve a caller's JWT into a user
const anon = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const app = express();
app.use(cors({ origin: ALLOWED_ORIGINS.split(",").map(s => s.trim()).filter(Boolean) }));
app.use(express.json());
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 100 * 1024 * 1024 } });

// ---------- helpers ----------
const oauth = () => new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);

function driveClient() {
  const o = oauth();
  o.setCredentials({ refresh_token: GOOGLE_REFRESH_TOKEN });
  return google.drive({ version: "v3", auth: o });
}

// Identify the caller from their Supabase JWT and load their profile (role, agency)
async function authed(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "Missing token" });
    const { data: { user }, error } = await anon.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: "Invalid token" });
    const { data: profile } = await admin.from("profiles").select("id, role, display_name").eq("id", user.id).single();
    if (!profile) return res.status(403).json({ error: "No profile" });
    req.user = profile;
    if (profile.role === "agency") {
      const { data: au } = await admin.from("agency_users").select("agency_id, series").eq("profile_id", user.id).single();
      req.agency = au;
    }
    next();
  } catch (e) { res.status(500).json({ error: e.message }); }
}
const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: "Forbidden" });

// Find-or-create a subfolder by name under a parent (for per-client / per-project structure)
async function ensureFolder(drive, name, parentId) {
  const q = `name = '${name.replace(/'/g, "\\'")}' and '${parentId}' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false`;
  const found = await drive.files.list({ q, fields: "files(id)", spaces: "drive" });
  if (found.data.files?.length) return found.data.files[0].id;
  const created = await drive.files.create({
    requestBody: { name, mimeType: "application/vnd.google-apps.folder", parents: [parentId] },
    fields: "id",
  });
  return created.data.id;
}

app.get("/health", (_req, res) => res.json({ ok: true }));

// ============================================================
// GOOGLE DRIVE — one-time OAuth connect (run as super admin once)
// ============================================================
// 1. Visit /drive/connect in a browser, approve consent.
// 2. The callback prints a refresh token. Put it in GOOGLE_REFRESH_TOKEN on Railway.
app.get("/drive/connect", (_req, res) => {
  const url = oauth().generateAuthUrl({
    access_type: "offline",
    prompt: "consent", // forces a refresh_token to be returned
    scope: ["https://www.googleapis.com/auth/drive.file"], // only files this app creates
  });
  res.redirect(url);
});

app.get("/drive/callback", async (req, res) => {
  try {
    const { tokens } = await oauth().getToken(req.query.code);
    res.send(
      `<pre>Connected. Copy this into Railway as GOOGLE_REFRESH_TOKEN, then redeploy:\n\n` +
      `${tokens.refresh_token || "(no refresh token — remove app access in your Google account and retry)"}\n</pre>`
    );
  } catch (e) { res.status(500).send("OAuth error: " + e.message); }
});

app.get("/drive/status", authed, requireRole("super_admin"), async (_req, res) => {
  try {
    const about = await driveClient().about.get({ fields: "user(emailAddress)" });
    res.json({ connected: true, account: about.data.user.emailAddress });
  } catch { res.json({ connected: false }); }
});

// ============================================================
// USER CREATION (passwords set by an admin/agency, so service-role only)
// ============================================================
// Super admin creates an agency user
app.post("/agency-users", authed, requireRole("super_admin"), async (req, res) => {
  const { series, name, agency_id, email, password } = req.body;
  if (!/^A\d{6}$/.test(series || "")) return res.status(400).json({ error: "Series must be A + 6 digits" });
  try {
    const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    if (error) throw error;
    const id = created.user.id;
    await admin.from("profiles").insert({ id, role: "agency", display_name: name });
    await admin.from("agency_users").insert({ profile_id: id, series, agency_id });
    res.json({ id, series, name });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Agency creates a client (exclusive to the caller's agency). Series auto-generated.
app.post("/clients", authed, requireRole("agency"), async (req, res) => {
  const { name, email, password } = req.body;
  try {
    // C + yyyymm + monthly sequence
    const d = new Date();
    const ym = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}`;
    const { count } = await admin.from("clients").select("*", { count: "exact", head: true }).like("series", `C${ym}%`);
    const series = `C${ym}${String((count || 0) + 1).padStart(3, "0")}`;

    const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    if (error) throw error;
    const id = created.user.id;
    await admin.from("profiles").insert({ id, role: "client", display_name: name });
    await admin.from("clients").insert({
      series, name, owner_agency_id: req.agency.agency_id,
      profile_id: id, email, created_by: req.user.id,
    });
    res.json({ id, series, name });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============================================================
// FILE UPLOAD  (agency member of the project -> Google Drive -> files row)
// ============================================================
app.post("/projects/:id/files", authed, requireRole("agency"), upload.single("file"), async (req, res) => {
  const projectId = req.params.id;
  const { description, type } = req.body;
  try {
    // membership check (defense in depth; RLS also guards the insert)
    const { data: member } = await admin.from("project_members")
      .select("project_id").eq("project_id", projectId).eq("member_id", req.user.id).maybeSingle();
    if (!member) return res.status(403).json({ error: "Not a member of this project" });
    if (!req.file) return res.status(400).json({ error: "No file" });

    const { data: project } = await admin.from("projects")
      .select("id, name, start_date, drive_folder_id, agencies(name)").eq("id", projectId).single();

    const drive = driveClient();
    // Each project gets ONE permanent folder. The first time a file is uploaded we create it
    // and store its id on the project, then always reuse that id — so renaming the project or
    // changing its date never moves or forks the files.
    // Tree: _DISPATCHR / [AGENCY NAME, UPPERCASE] / [yyyymmdd Project Name]
    let parent = project.drive_folder_id;
    if (!parent) {
      const agencyName = (project.agencies?.name || "UNKNOWN").toUpperCase();
      const root = await ensureFolder(drive, "_DISPATCHR", "root");
      const agencyFolder = await ensureFolder(drive, agencyName, root);
      const ymd = String(project.start_date || "").replace(/-/g, "").slice(0, 8) || "00000000";
      const created = await drive.files.create({
        requestBody: {
          name: `${ymd} ${project.name}`,
          mimeType: "application/vnd.google-apps.folder",
          parents: [agencyFolder],
        },
        fields: "id",
      });
      parent = created.data.id;
      await admin.from("projects").update({ drive_folder_id: parent }).eq("id", projectId);
    }

    const uploaded = await drive.files.create({
      requestBody: { name: req.file.originalname, parents: [parent] },
      media: { mimeType: req.file.mimetype, body: Readable.from(req.file.buffer) },
      fields: "id, webViewLink",
    });

    const { data: row, error } = await admin.from("files").insert({
      project_id: projectId, description, type: type || "Others",
      file_name: req.file.originalname,
      drive_file_id: uploaded.data.id, drive_link: uploaded.data.webViewLink,
      uploaded_by: req.user.id,
    }).select().single();
    if (error) throw error;
    res.json(row);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============================================================
// FILE DOWNLOAD  (access-checked broker -> streams bytes from Drive)
// ============================================================
app.get("/files/:id/download", authed, async (req, res) => {
  try {
    // can the caller see the parent project? reuse the RLS helper
    const { data: file } = await admin.from("files").select("project_id, file_name, drive_file_id").eq("id", req.params.id).single();
    if (!file) return res.status(404).json({ error: "Not found" });
    const { data: allowed } = await admin.rpc("can_see_project", { p: file.project_id });
    // can_see_project uses auth.uid(); call it as the user instead:
    const userClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: req.headers.authorization } },
    });
    const { data: ok } = await userClient.rpc("can_see_project", { p: file.project_id });
    if (!ok) return res.status(403).json({ error: "Forbidden" });

    const drive = driveClient();
    const stream = await drive.files.get({ fileId: file.drive_file_id, alt: "media" }, { responseType: "stream" });
    res.setHeader("Content-Disposition", `attachment; filename="${file.file_name}"`);
    stream.data.pipe(res);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Dispatchr backend on :${PORT}`));
