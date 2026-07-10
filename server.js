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
  SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_SECRET, SUPABASE_ANON_KEY,
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI,
  GOOGLE_REFRESH_TOKEN, DRIVE_ROOT_FOLDER_ID,
  ALLOWED_ORIGINS = "", PORT = 8080,
} = process.env;

// The service-role SECRET (bypasses RLS). Prefer SUPABASE_SECRET — set that fresh
// on Railway; fall back to the old SUPABASE_SERVICE_ROLE_KEY if it's not present.
const SERVICE_KEY = SUPABASE_SECRET || SUPABASE_SERVICE_ROLE_KEY;
if (!SERVICE_KEY || String(SERVICE_KEY).startsWith("sb_publishable")) {
  console.error("[Dispatchr] Service key looks WRONG — it must be the service_role secret (starts sb_secret_), NOT the publishable/anon key. Set SUPABASE_SECRET on Railway.");
}

// Service-role client: full access, bypasses RLS. Backend only.
const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
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
    if (profile.role === "supplier") {
      const { data: su } = await admin.from("supplier_users").select("supplier_company_id, series").eq("profile_id", user.id).single();
      req.supplier = su;
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
  if (!/^A[A-Za-z0-9]{1,12}$/.test(series || "")) return res.status(400).json({ error: "Series must be A + up to 12 letters or numbers" });
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

// Agency creates a supplier user (S + up to 12 letters/numbers) under one of its supplier companies.
// The supplier company itself is created by the browser directly (RLS allows the agency);
// only the login needs the service role, so it lives here.
app.post("/supplier-users", authed, requireRole("agency"), async (req, res) => {
  const { series, name, supplier_company_id, email, password } = req.body;
  if (!/^S[A-Za-z0-9]{1,12}$/.test(series || "")) return res.status(400).json({ error: "Series must be S + up to 12 letters or numbers" });
  if (!name) return res.status(400).json({ error: "Name is required" });
  try {
    // the supplier company must belong to the calling agency
    const { data: sc } = await admin.from("supplier_companies")
      .select("id").eq("id", supplier_company_id).eq("owner_agency_id", req.agency.agency_id).maybeSingle();
    if (!sc) return res.status(403).json({ error: "That supplier company isn't yours" });

    const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    if (error) throw error;
    const id = created.user.id;
    await admin.from("profiles").insert({ id, role: "supplier", display_name: name });
    await admin.from("supplier_users").insert({ profile_id: id, series, supplier_company_id, email });
    res.json({ id, series, name });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
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
// AGENCY-PROJECT FILE UPLOAD  (the SUPPLIER uploads; the agency acknowledges)
// Drive tree: _DISPATCHR / [AGENCY] / _SUPPLIERS / [SUPPLIER COMPANY] / [yyyymmdd Project]
// ============================================================
app.post("/agency-projects/:id/files", authed, requireRole("supplier"), upload.single("file"), async (req, res) => {
  const apId = req.params.id;
  const { description, type } = req.body;
  try {
    if (!req.file) return res.status(400).json({ error: "No file" });
    const { data: ap } = await admin.from("agency_projects")
      .select("id, name, start_date, drive_folder_id, supplier_company_id, agencies(name), supplier_companies(name)")
      .eq("id", apId).single();
    if (!ap) return res.status(404).json({ error: "Project not found" });
    // the uploader must belong to this project's supplier company
    if (ap.supplier_company_id !== req.supplier?.supplier_company_id) {
      return res.status(403).json({ error: "Not your supplier company's project" });
    }

    const drive = driveClient();
    // One permanent folder per agency project, stored on first upload (renames never fork it).
    let parent = ap.drive_folder_id;
    if (!parent) {
      const agencyName = (ap.agencies?.name || "UNKNOWN").toUpperCase();
      const supplierName = ap.supplier_companies?.name || "SUPPLIER";
      const root = await ensureFolder(drive, "_DISPATCHR", "root");
      const agencyFolder = await ensureFolder(drive, agencyName, root);
      const supRoot = await ensureFolder(drive, "_SUPPLIERS", agencyFolder);
      const supFolder = await ensureFolder(drive, supplierName, supRoot);
      const ymd = String(ap.start_date || "").replace(/-/g, "").slice(0, 8) || "00000000";
      const created = await drive.files.create({
        requestBody: { name: `${ymd} ${ap.name}`, mimeType: "application/vnd.google-apps.folder", parents: [supFolder] },
        fields: "id",
      });
      parent = created.data.id;
      await admin.from("agency_projects").update({ drive_folder_id: parent }).eq("id", apId);
    }

    const uploaded = await drive.files.create({
      requestBody: { name: req.file.originalname, parents: [parent] },
      media: { mimeType: req.file.mimetype, body: Readable.from(req.file.buffer) },
      fields: "id, webViewLink",
    });

    const { data: row, error } = await admin.from("files").insert({
      agency_project_id: apId, description, type: type || "Others",
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
    // can the caller see the parent project? reuse the RLS helpers, called AS the user
    const { data: file } = await admin.from("files").select("project_id, agency_project_id, file_name, drive_file_id").eq("id", req.params.id).single();
    if (!file) return res.status(404).json({ error: "Not found" });
    const userClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: req.headers.authorization } },
    });
    let ok = false;
    if (file.project_id) {
      const { data } = await userClient.rpc("can_see_project", { p: file.project_id });
      ok = data;
    } else if (file.agency_project_id) {
      const { data } = await userClient.rpc("can_see_agency_project", { p: file.agency_project_id });
      ok = data;
    }
    if (!ok) return res.status(403).json({ error: "Forbidden" });

    const drive = driveClient();
    const stream = await drive.files.get({ fileId: file.drive_file_id, alt: "media" }, { responseType: "stream" });
    res.setHeader("Content-Disposition", `attachment; filename="${file.file_name}"`);
    stream.data.pipe(res);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============================================================
// SUPER ADMIN — "god mode" over clients & suppliers (ANY agency)
// The admin isn't tied to one agency, so every create takes an explicit
// target agency_id / company id. All writes use the service role, so no
// RLS changes are needed. Deletes are blocked while dependent rows exist.
// ============================================================
const NUM = /^[A-Za-z0-9]{1,12}$/; // matches the frontend's loosened number rule

// ---- CLIENTS -------------------------------------------------
// Create a client under any agency (series auto-generated, same C+yyyymm+seq rule)
app.post("/admin/clients", authed, requireRole("super_admin"), async (req, res) => {
  const { name, email, password, agency_id } = req.body;
  if (!name || !email || !password || !agency_id)
    return res.status(400).json({ error: "name, email, password and agency_id are required" });
  try {
    const d = new Date();
    const ym = `${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, "0")}`;
    const { count } = await admin.from("clients").select("*", { count: "exact", head: true }).like("series", `C${ym}%`);
    const series = `C${ym}${String((count || 0) + 1).padStart(3, "0")}`;

    const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    if (error) throw error;
    const id = created.user.id;
    await admin.from("profiles").insert({ id, role: "client", display_name: name });
    await admin.from("clients").insert({ series, name, owner_agency_id: agency_id, profile_id: id, email, created_by: req.user.id });
    res.json({ id, series, name });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Edit a client (name / email / owning agency / optional password reset)
app.patch("/admin/clients/:id", authed, requireRole("super_admin"), async (req, res) => {
  const { name, email, agency_id, password } = req.body;
  try {
    const { data: c } = await admin.from("clients").select("profile_id").eq("id", req.params.id).single();
    if (!c) return res.status(404).json({ error: "Client not found" });
    const patch = {};
    if (name != null) patch.name = name;
    if (email != null) patch.email = email;
    if (agency_id != null) patch.owner_agency_id = agency_id;
    if (Object.keys(patch).length) await admin.from("clients").update(patch).eq("id", req.params.id);
    if (name != null) await admin.from("profiles").update({ display_name: name }).eq("id", c.profile_id);
    if (email != null || password)
      await admin.auth.admin.updateUserById(c.profile_id, { ...(email != null ? { email } : {}), ...(password ? { password } : {}) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Delete a client (blocked while it still has projects)
app.delete("/admin/clients/:id", authed, requireRole("super_admin"), async (req, res) => {
  try {
    const { data: c } = await admin.from("clients").select("profile_id").eq("id", req.params.id).single();
    if (!c) return res.status(404).json({ error: "Client not found" });
    const { count } = await admin.from("projects").select("*", { count: "exact", head: true }).eq("client_id", req.params.id);
    if (count > 0) return res.status(409).json({ error: `This client still has ${count} project(s). Delete or reassign those first.` });
    await admin.from("clients").delete().eq("id", req.params.id);
    await admin.auth.admin.deleteUser(c.profile_id); // removes the login; profile cascades
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ---- SUPPLIER COMPANIES -------------------------------------
// Create a supplier company under any agency
app.post("/admin/supplier-companies", authed, requireRole("super_admin"), async (req, res) => {
  const { name, agency_id } = req.body;
  if (!name || !agency_id) return res.status(400).json({ error: "name and agency_id are required" });
  try {
    const { data, error } = await admin.from("supplier_companies").insert({ name, owner_agency_id: agency_id }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Edit a supplier company (rename / move to another agency)
app.patch("/admin/supplier-companies/:id", authed, requireRole("super_admin"), async (req, res) => {
  const { name, agency_id } = req.body;
  try {
    const patch = {};
    if (name != null) patch.name = name;
    if (agency_id != null) patch.owner_agency_id = agency_id;
    if (!Object.keys(patch).length) return res.json({ ok: true });
    const { error } = await admin.from("supplier_companies").update(patch).eq("id", req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Delete a supplier company (blocked while it has users or agency projects)
app.delete("/admin/supplier-companies/:id", authed, requireRole("super_admin"), async (req, res) => {
  try {
    const { count: users } = await admin.from("supplier_users").select("*", { count: "exact", head: true }).eq("supplier_company_id", req.params.id);
    if (users > 0) return res.status(409).json({ error: `This company still has ${users} supplier user(s). Delete those first.` });
    const { count: aps } = await admin.from("agency_projects").select("*", { count: "exact", head: true }).eq("supplier_company_id", req.params.id);
    if (aps > 0) return res.status(409).json({ error: `This company still has ${aps} agency project(s). Delete or reassign those first.` });
    const { error } = await admin.from("supplier_companies").delete().eq("id", req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ---- SUPPLIER USERS -----------------------------------------
// Create a supplier user under any company. Accepts either an existing
// supplier_company_id, or a company name + agency_id to find-or-create.
app.post("/admin/supplier-users", authed, requireRole("super_admin"), async (req, res) => {
  let { series, name, supplier_company_id, supplier_company_name, agency_id, email, password } = req.body;
  const num = (series || "").replace(/^S/, "");
  if (!NUM.test(num)) return res.status(400).json({ error: "Series must be S + up to 12 letters or numbers" });
  if (!name) return res.status(400).json({ error: "Name is required" });
  if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
  try {
    // resolve the company: use the id if given, else find-or-create by name under agency_id
    if (!supplier_company_id) {
      if (!supplier_company_name || !agency_id)
        return res.status(400).json({ error: "Provide supplier_company_id, or supplier_company_name + agency_id" });
      const { data: found } = await admin.from("supplier_companies")
        .select("id").eq("owner_agency_id", agency_id).ilike("name", supplier_company_name).maybeSingle();
      if (found) supplier_company_id = found.id;
      else {
        const { data: made, error: mErr } = await admin.from("supplier_companies")
          .insert({ name: supplier_company_name, owner_agency_id: agency_id }).select("id").single();
        if (mErr) throw mErr;
        supplier_company_id = made.id;
      }
    }
    const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
    if (error) throw error;
    const id = created.user.id;
    await admin.from("profiles").insert({ id, role: "supplier", display_name: name });
    await admin.from("supplier_users").insert({ profile_id: id, series, supplier_company_id, email });
    res.json({ id, series, name });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Edit a supplier user (name / company / optional email + password)
app.patch("/admin/supplier-users/:profile_id", authed, requireRole("super_admin"), async (req, res) => {
  const { name, supplier_company_id, series, email, password } = req.body;
  try {
    if (series != null && !NUM.test((series || "").replace(/^S/, "")))
      return res.status(400).json({ error: "Series must be S + up to 12 letters or numbers" });
    if (name != null) {
      await admin.from("profiles").update({ display_name: name }).eq("id", req.params.profile_id);
    }
    const suPatch = {};
    if ("supplier_company_id" in req.body) suPatch.supplier_company_id = supplier_company_id || null;
    if (series != null) suPatch.series = series;
    if (Object.keys(suPatch).length) await admin.from("supplier_users").update(suPatch).eq("profile_id", req.params.profile_id);
    if (email != null || password)
      await admin.auth.admin.updateUserById(req.params.profile_id, { ...(email != null ? { email } : {}), ...(password ? { password } : {}) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Delete a supplier user (blocked while they have uploaded files)
app.delete("/admin/supplier-users/:profile_id", authed, requireRole("super_admin"), async (req, res) => {
  try {
    const { count } = await admin.from("files").select("*", { count: "exact", head: true }).eq("uploaded_by", req.params.profile_id);
    if (count > 0) return res.status(409).json({ error: `This supplier has uploaded ${count} file(s). Remove those first.` });
    await admin.from("supplier_users").delete().eq("profile_id", req.params.profile_id);
    await admin.auth.admin.deleteUser(req.params.profile_id); // removes login; profile cascades
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ---- AGENCY USERS (edit / delete / password reset) ----------
// Edit an agency user. Email is kept in both the login and agency_users.email.
app.patch("/admin/agency-users/:profile_id", authed, requireRole("super_admin"), async (req, res) => {
  const { name, agency_id, series, email, password } = req.body;
  const pid = req.params.profile_id;
  try {
    if (series != null && !NUM.test((series || "").replace(/^A/, "")))
      return res.status(400).json({ error: "Series must be A + up to 12 letters or numbers" });
    if (name != null) await admin.from("profiles").update({ display_name: name }).eq("id", pid);
    const auPatch = {};
    if (agency_id != null) auPatch.agency_id = agency_id;
    if (series != null) auPatch.series = series;
    if (email != null) auPatch.email = email;
    if (Object.keys(auPatch).length) await admin.from("agency_users").update(auPatch).eq("profile_id", pid);
    if (email != null || password)
      await admin.auth.admin.updateUserById(pid, { ...(email != null ? { email } : {}), ...(password ? { password } : {}) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Delete an agency user (blocked while they still own projects)
app.delete("/admin/agency-users/:profile_id", authed, requireRole("super_admin"), async (req, res) => {
  const pid = req.params.profile_id;
  try {
    const { count: cp } = await admin.from("projects").select("*", { count: "exact", head: true }).eq("created_by", pid);
    const { count: cap } = await admin.from("agency_projects").select("*", { count: "exact", head: true }).eq("created_by", pid);
    const owned = (cp || 0) + (cap || 0);
    if (owned > 0) return res.status(409).json({ error: `This user created ${owned} project(s). Reassign or delete those first.` });
    // remove their project memberships so the delete doesn't trip a foreign key
    await admin.from("project_members").delete().eq("member_id", pid);
    await admin.from("agency_project_members").delete().eq("member_id", pid);
    await admin.from("agency_users").delete().eq("profile_id", pid);
    await admin.auth.admin.deleteUser(pid); // removes login; profile cascades
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============================================================
// AGENCY — create projects via the backend (service role, bypasses RLS)
// ============================================================

// Client project
app.post("/projects", authed, requireRole("agency"), async (req, res) => {
  const { name, start_date, client_id, slug, members } = req.body;
  if (!name || !client_id) return res.status(400).json({ error: "name and client_id are required" });
  try {
    const row = { name, start_date: start_date || null, client_id, agency_id: req.agency.agency_id, created_by: req.user.id };
    if (slug) row.slug = slug;
    const { data: proj, error } = await admin.from("projects").insert(row).select().single();
    if (error) throw error;
    const mem = [...new Set([req.user.id, ...((members || []).filter(Boolean))])];
    if (mem.length) {
      const { error: mErr } = await admin.from("project_members").insert(mem.map(m => ({ project_id: proj.id, member_id: m })));
      if (mErr) throw mErr;
    }
    res.json(proj);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Agency project (supplier side). Accepts an existing company id, or a company
// name to find-or-create under the caller's agency.
app.post("/agency-projects", authed, requireRole("agency"), async (req, res) => {
  let { name, start_date, supplier_company_id, supplier_company_name, slug, members } = req.body;
  if (!name) return res.status(400).json({ error: "name is required" });
  try {
    if (!supplier_company_id) {
      if (!supplier_company_name) return res.status(400).json({ error: "Pick or name a supplier company" });
      const { data: found } = await admin.from("supplier_companies")
        .select("id").eq("owner_agency_id", req.agency.agency_id).ilike("name", supplier_company_name).maybeSingle();
      if (found) supplier_company_id = found.id;
      else {
        const { data: made, error: cErr } = await admin.from("supplier_companies")
          .insert({ name: supplier_company_name, owner_agency_id: req.agency.agency_id }).select("id").single();
        if (cErr) throw cErr;
        supplier_company_id = made.id;
      }
    }
    const row = { name, start_date: start_date || null, supplier_company_id, agency_id: req.agency.agency_id, created_by: req.user.id };
    if (slug) row.slug = slug;
    const { data: proj, error } = await admin.from("agency_projects").insert(row).select().single();
    if (error) throw error;
    const mem = [...new Set([req.user.id, ...((members || []).filter(Boolean))])];
    if (mem.length) {
      const { error: mErr } = await admin.from("agency_project_members").insert(mem.map(m => ({ agency_project_id: proj.id, member_id: m })));
      if (mErr) throw mErr;
    }
    res.json(proj);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============================================================
// AGENCY — manage its OWN clients and supplier users
// ============================================================
app.patch("/clients/:id", authed, requireRole("agency"), async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const { data: c } = await admin.from("clients").select("owner_agency_id, profile_id").eq("id", req.params.id).single();
    if (!c) return res.status(404).json({ error: "Client not found" });
    if (c.owner_agency_id !== req.agency.agency_id) return res.status(403).json({ error: "Not your client" });
    if (name != null) { await admin.from("clients").update({ name }).eq("id", req.params.id); await admin.from("profiles").update({ display_name: name }).eq("id", c.profile_id); }
    if (email != null) await admin.from("clients").update({ email }).eq("id", req.params.id);
    if (email != null || password) await admin.auth.admin.updateUserById(c.profile_id, { ...(email != null ? { email } : {}), ...(password ? { password } : {}) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete("/clients/:id", authed, requireRole("agency"), async (req, res) => {
  try {
    const { data: c } = await admin.from("clients").select("owner_agency_id, profile_id").eq("id", req.params.id).single();
    if (!c) return res.status(404).json({ error: "Client not found" });
    if (c.owner_agency_id !== req.agency.agency_id) return res.status(403).json({ error: "Not your client" });
    const { count } = await admin.from("projects").select("*", { count: "exact", head: true }).eq("client_id", req.params.id);
    if (count > 0) return res.status(409).json({ error: `This client has ${count} project(s). Delete or reassign those first.` });
    await admin.from("clients").delete().eq("id", req.params.id);
    await admin.auth.admin.deleteUser(c.profile_id);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.patch("/supplier-users/:profile_id", authed, requireRole("agency"), async (req, res) => {
  const { name, email, password, supplier_company_id } = req.body;
  const pid = req.params.profile_id;
  try {
    const { data: su } = await admin.from("supplier_users").select("supplier_company_id").eq("profile_id", pid).single();
    if (!su) return res.status(404).json({ error: "Supplier user not found" });
    const { data: sc } = await admin.from("supplier_companies").select("owner_agency_id").eq("id", su.supplier_company_id).single();
    if (!sc || sc.owner_agency_id !== req.agency.agency_id) return res.status(403).json({ error: "Not your supplier" });
    if (supplier_company_id != null && supplier_company_id !== su.supplier_company_id) {
      const { data: dest } = await admin.from("supplier_companies").select("owner_agency_id").eq("id", supplier_company_id).single();
      if (!dest || dest.owner_agency_id !== req.agency.agency_id) return res.status(403).json({ error: "That company isn't yours" });
    }
    if (name != null) await admin.from("profiles").update({ display_name: name }).eq("id", pid);
    const suPatch = {};
    if ("supplier_company_id" in req.body) suPatch.supplier_company_id = supplier_company_id || null;
    if (email != null) suPatch.email = email;
    if (Object.keys(suPatch).length) await admin.from("supplier_users").update(suPatch).eq("profile_id", pid);
    if (email != null || password) await admin.auth.admin.updateUserById(pid, { ...(email != null ? { email } : {}), ...(password ? { password } : {}) });
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete("/supplier-users/:profile_id", authed, requireRole("agency"), async (req, res) => {
  const pid = req.params.profile_id;
  try {
    const { data: su } = await admin.from("supplier_users").select("supplier_company_id").eq("profile_id", pid).single();
    if (!su) return res.status(404).json({ error: "Supplier user not found" });
    const { data: sc } = await admin.from("supplier_companies").select("owner_agency_id").eq("id", su.supplier_company_id).single();
    if (!sc || sc.owner_agency_id !== req.agency.agency_id) return res.status(403).json({ error: "Not your supplier" });
    const { count } = await admin.from("files").select("*", { count: "exact", head: true }).eq("uploaded_by", pid);
    if (count > 0) return res.status(409).json({ error: `This supplier uploaded ${count} file(s). Remove those first.` });
    await admin.from("supplier_users").delete().eq("profile_id", pid);
    await admin.auth.admin.deleteUser(pid);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.listen(PORT, () => console.log(`Dispatchr backend on :${PORT}`));
