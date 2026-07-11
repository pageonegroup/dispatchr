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

// The Google refresh token lives in the DB (app_secrets) so re-connecting never needs a
// redeploy. We cache it in memory for synchronous driveClient() calls, seed it from the
// env var as a fallback, load it fresh at boot, and update it whenever a new one is saved.
let currentRefreshToken = GOOGLE_REFRESH_TOKEN || null;
async function loadRefreshToken() {
  try {
    const { data } = await admin.from("app_secrets").select("value").eq("key", "google_refresh_token").maybeSingle();
    // If a row exists it's authoritative (empty value = explicitly disconnected). Only when no
    // row has ever been written do we keep the env-var fallback already in currentRefreshToken.
    if (data) currentRefreshToken = data.value || null;
  } catch (e) { console.error("[Dispatchr] could not load refresh token:", e.message); }
}
async function saveRefreshToken(tok) {
  currentRefreshToken = tok;
  driveStatusCache = { at: 0, connected: false }; // force a fresh check after reconnect
  const { error } = await admin.from("app_secrets")
    .upsert({ key: "google_refresh_token", value: tok, updated_at: new Date().toISOString() }, { onConflict: "key" });
  if (error) throw error;
}
// Explicit disconnect: forget the token (stored as empty so it survives redeploys and
// overrides any env-var fallback). Drive access stops until the admin reconnects.
async function clearRefreshToken() {
  currentRefreshToken = null;
  driveStatusCache = { at: 0, connected: false };
  const { error } = await admin.from("app_secrets")
    .upsert({ key: "google_refresh_token", value: "", updated_at: new Date().toISOString() }, { onConflict: "key" });
  if (error) throw error;
}

function driveClient() {
  const o = oauth();
  o.setCredentials({ refresh_token: currentRefreshToken });
  return google.drive({ version: "v3", auth: o });
}

// Cheap "is Drive working" check shared by all users, cached 60s so many page loads don't
// each hit Google. Any authed user can read this (boolean only — no account details).
let driveStatusCache = { at: 0, connected: false };
async function driveConnected() {
  const now = Date.now();
  if (now - driveStatusCache.at < 60000) return driveStatusCache.connected;
  let connected = false;
  try { await driveClient().about.get({ fields: "user(emailAddress)" }); connected = true; } catch (_) {}
  driveStatusCache = { at: now, connected };
  return connected;
}

// ---------- root folder (the top Dispatchr folder in Drive) ----------
// Configurable from the admin UI, cached in memory. Falls back to the legacy "_DISPATCHR"
// folder under My Drive when nothing has been set, so existing installs keep working.
let rootFolder = { id: null, name: null };
async function loadRootFolder() {
  try {
    const { data } = await admin.from("app_secrets").select("key, value").in("key", ["drive_root_folder_id", "drive_root_folder_name"]);
    const m = {}; (data || []).forEach(r => { m[r.key] = r.value; });
    rootFolder = { id: m.drive_root_folder_id || null, name: m.drive_root_folder_name || null };
  } catch (e) { console.error("[Dispatchr] could not load root folder:", e.message); }
}
async function saveRootFolder(id, name) {
  rootFolder = { id, name };
  const now = new Date().toISOString();
  const { error } = await admin.from("app_secrets").upsert([
    { key: "drive_root_folder_id", value: id, updated_at: now },
    { key: "drive_root_folder_name", value: name, updated_at: now },
  ], { onConflict: "key" });
  if (error) throw error;
}
// Forget the stored root (e.g. after switching Google accounts — a root from one account is
// meaningless in another). Stored empty so it survives redeploys.
async function clearRootFolder() {
  rootFolder = { id: null, name: null };
  const now = new Date().toISOString();
  await admin.from("app_secrets").upsert([
    { key: "drive_root_folder_id", value: "", updated_at: now },
    { key: "drive_root_folder_name", value: "", updated_at: now },
  ], { onConflict: "key" });
}
// The parent every agency folder is created under: the configured root when set,
// otherwise the legacy "_DISPATCHR" folder under My Drive — which we then adopt as the
// stored root so it appears in the UI (ensureFolder finds the existing one, no duplicate).
async function resolveRootFolderId(drive) {
  if (rootFolder.id) return rootFolder.id;
  const id = await ensureFolder(drive, "_DISPATCHR", "root");
  try { await saveRootFolder(id, "_DISPATCHR"); } catch (_) {}
  return id;
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

// Resolve the permanent Drive folder for the project (or agency project) that a files row
// belongs to, creating the folder tree on first need — mirrors the upload endpoints exactly.
async function resolveFolderForFileRow(drive, file) {
  if (file.project_id) {
    const { data: project } = await admin.from("projects")
      .select("id, name, start_date, drive_folder_id, agencies(name)").eq("id", file.project_id).single();
    if (project.drive_folder_id) return project.drive_folder_id;
    const agencyName = (project.agencies?.name || "UNKNOWN").toUpperCase();
    const root = await resolveRootFolderId(drive);
    const agencyFolder = await ensureFolder(drive, agencyName, root);
    const ymd = String(project.start_date || "").replace(/-/g, "").slice(0, 8) || "00000000";
    const created = await drive.files.create({
      requestBody: { name: `${ymd} ${project.name}`, mimeType: "application/vnd.google-apps.folder", parents: [agencyFolder] },
      fields: "id",
    });
    await admin.from("projects").update({ drive_folder_id: created.data.id }).eq("id", file.project_id);
    return created.data.id;
  }
  if (file.agency_project_id) {
    const { data: ap } = await admin.from("agency_projects")
      .select("id, name, start_date, drive_folder_id, agencies(name), supplier_companies(name)").eq("id", file.agency_project_id).single();
    if (ap.drive_folder_id) return ap.drive_folder_id;
    const agencyName = (ap.agencies?.name || "UNKNOWN").toUpperCase();
    const supplierName = ap.supplier_companies?.name || "SUPPLIER";
    const root = await resolveRootFolderId(drive);
    const agencyFolder = await ensureFolder(drive, agencyName, root);
    const supRoot = await ensureFolder(drive, "_SUPPLIERS", agencyFolder);
    const supFolder = await ensureFolder(drive, supplierName, supRoot);
    const ymd = String(ap.start_date || "").replace(/-/g, "").slice(0, 8) || "00000000";
    const created = await drive.files.create({
      requestBody: { name: `${ymd} ${ap.name}`, mimeType: "application/vnd.google-apps.folder", parents: [supFolder] },
      fields: "id",
    });
    await admin.from("agency_projects").update({ drive_folder_id: created.data.id }).eq("id", file.agency_project_id);
    return created.data.id;
  }
  throw new Error("File row is not attached to a project");
}

// May the current user manage (add/remove files on) this delivery row? Same gate as the
// UI edit/delete buttons: an admin, or the person who uploaded it.
function canManageFileRow(req, file) {
  return req.user.role === "super_admin" || file.uploaded_by === req.user.id;
}

app.get("/health", (_req, res) => res.json({ ok: true }));

// ============================================================
// GOOGLE DRIVE — one-click connect. An admin clicks "Connect" in the app, which opens
// /drive/connect?t=<their login token>. We verify they're a super admin, send them to
// Google's account picker, and on return SAVE the refresh token to the DB automatically —
// no copy-paste, no redeploy. Reconnecting with the SAME Google account restores access to
// every existing folder (each project's folder id is stored in the DB and never changes).
// ============================================================
let pendingConnectState = null;

async function isSuperAdminToken(tok) {
  if (!tok) return false;
  const { data: { user }, error } = await anon.auth.getUser(tok);
  if (error || !user) return false;
  const { data: profile } = await admin.from("profiles").select("role").eq("id", user.id).single();
  return !!profile && profile.role === "super_admin";
}

const drivePage = (title, body, ok) => `<!doctype html><meta charset="utf-8"><title>${title}</title>
  <body style="font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0b0d12;color:#e8eaf0;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">
  <div style="max-width:420px;text-align:center;padding:32px">
    <div style="font-size:44px;margin-bottom:10px">${ok ? "\u2705" : "\u26A0\uFE0F"}</div>
    <h1 style="font-size:20px;margin:0 0 8px">${title}</h1>
    <p style="color:#8b93a7;line-height:1.55;margin:0 0 22px">${body}</p>
    <button onclick="window.close()" style="background:#c8a96e;color:#0b0d12;border:0;border-radius:8px;padding:10px 18px;font-weight:600;cursor:pointer">Close this window</button>
  </div></body>`;

app.get("/drive/connect", async (req, res) => {
  try {
    if (!(await isSuperAdminToken(req.query.t)))
      return res.status(403).send(drivePage("Not authorised", "Open this from the Google Drive settings page while signed in as an admin.", false));
    pendingConnectState = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const url = oauth().generateAuthUrl({
      access_type: "offline",
      prompt: "consent",              // always return a refresh token
      include_granted_scopes: true,
      state: pendingConnectState,
      scope: ["https://www.googleapis.com/auth/drive.file"], // only files this app creates
    });
    res.redirect(url);
  } catch (e) { res.status(500).send(drivePage("Couldn't start", e.message, false)); }
});

app.get("/drive/callback", async (req, res) => {
  try {
    if (!req.query.state || req.query.state !== pendingConnectState)
      return res.status(400).send(drivePage("Couldn't connect", "This connect link is invalid or expired. Please start again from the Google Drive settings page.", false));
    pendingConnectState = null;
    const { tokens } = await oauth().getToken(req.query.code);
    if (!tokens.refresh_token)
      return res.status(400).send(drivePage("Almost there", "Google didn't return a refresh token. Remove Dispatchr's access at myaccount.google.com/permissions, then click Connect again.", false));
    await saveRefreshToken(tokens.refresh_token);
    let email = "";
    try { const about = await driveClient().about.get({ fields: "user(emailAddress)" }); email = about.data.user.emailAddress; } catch (_) {}
    res.send(drivePage("Google Drive connected", `Dispatchr is now connected${email ? " as <b>" + email + "</b>" : ""}. You can close this window — uploads and downloads work right away.`, true));
  } catch (e) { res.status(500).send(drivePage("Couldn't connect", "Something went wrong: " + e.message, false)); }
});

app.get("/drive/status", authed, requireRole("super_admin"), async (_req, res) => {
  const configured = !!currentRefreshToken; // a token is still on file (system drop vs. user disconnect)
  try {
    const about = await driveClient().about.get({ fields: "user(emailAddress)" });
    res.json({ connected: true, configured, account: about.data.user.emailAddress });
  } catch { res.json({ connected: false, configured }); }
});

// Global connection indicator for the top-bar — readable by ANY signed-in user (boolean only).
app.get("/drive/connected", authed, async (_req, res) => {
  res.json({ connected: await driveConnected() });
});

// Explicit disconnect (super admin) — forgets the saved token so the admin can connect a
// different account cleanly. Does NOT touch any folders or files in Drive.
app.post("/drive/disconnect", authed, requireRole("super_admin"), async (_req, res) => {
  try { await clearRefreshToken(); await clearRootFolder(); res.json({ ok: true }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});

// ---- ROOT FOLDER management (super admin) --------------------------------
// Current root (id + name). Validates the saved root is reachable by the CURRENTLY connected
// account — if not (e.g. the account was switched), it forgets it and re-detects. If none is
// set, it adopts an EXISTING "_DISPATCHR" in this account (search only, nothing is created).
app.get("/drive/root", authed, requireRole("super_admin"), async (_req, res) => {
  const drive = driveClient();
  if (rootFolder.id) {
    try {
      const meta = await drive.files.get({ fileId: rootFolder.id, fields: "id, name, trashed" });
      if (meta.data && !meta.data.trashed) return res.json({ id: rootFolder.id, name: meta.data.name || rootFolder.name });
    } catch (_) { /* not reachable from this account — fall through and forget it */ }
    try { await clearRootFolder(); } catch (_) {}
  }
  try {
    const found = await drive.files.list({
      q: "name = '_DISPATCHR' and 'root' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false",
      fields: "files(id, name)", spaces: "drive",
    });
    if (found.data.files && found.data.files.length) {
      const f = found.data.files[0];
      await saveRootFolder(f.id, f.name);
      return res.json({ id: f.id, name: f.name });
    }
  } catch (_) {}
  res.json({ id: null, name: null });
});

// Create a brand-new folder in Drive and make it the root.
app.post("/drive/root/create", authed, requireRole("super_admin"), async (req, res) => {
  const name = (req.body.name || "").trim();
  if (!name) return res.status(400).json({ error: "Folder name is required" });
  try {
    const created = await driveClient().files.create({
      requestBody: { name, mimeType: "application/vnd.google-apps.folder", parents: ["root"] },
      fields: "id, name",
    });
    await saveRootFolder(created.data.id, created.data.name || name);
    res.json({ id: created.data.id, name: created.data.name || name });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// List TOP-LEVEL folders (directly under My Drive) that Dispatchr can see, for the
// "Connect Root" picker. A root should be a top folder, not a nested project folder.
// (drive.file scope = only folders this app created.)
app.get("/drive/folders", authed, requireRole("super_admin"), async (_req, res) => {
  try {
    const drive = driveClient();
    const out = []; let pageToken;
    do {
      const r = await drive.files.list({
        q: "'root' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false",
        fields: "nextPageToken, files(id, name)",
        pageSize: 100, spaces: "drive", orderBy: "name", pageToken,
      });
      (r.data.files || []).forEach(f => out.push({ id: f.id, name: f.name }));
      pageToken = r.data.nextPageToken;
    } while (pageToken && out.length < 500);
    res.json({ folders: out });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Point the root at an existing folder chosen from the picker.
app.post("/drive/root/connect", authed, requireRole("super_admin"), async (req, res) => {
  const id = (req.body.id || "").trim();
  if (!id) return res.status(400).json({ error: "Folder id is required" });
  try {
    const meta = await driveClient().files.get({ fileId: id, fields: "id, name, mimeType, trashed" });
    if (meta.data.trashed) return res.status(400).json({ error: "That folder is in the trash" });
    if (meta.data.mimeType !== "application/vnd.google-apps.folder") return res.status(400).json({ error: "That item is not a folder" });
    await saveRootFolder(meta.data.id, meta.data.name);
    res.json({ id: meta.data.id, name: meta.data.name });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Storage quota on the connected service account — represents the whole system,
// since every upload runs through this one Drive account. Super admin only.
app.get("/drive/storage", authed, requireRole("super_admin"), async (_req, res) => {
  try {
    const about = await driveClient().about.get({
      fields: "storageQuota, user(emailAddress)",
    });
    const q = about.data.storageQuota || {};
    res.json({
      account: about.data.user?.emailAddress || null,
      limit:        q.limit ? Number(q.limit) : null,   // null = unlimited/pooled (Workspace)
      usage:        Number(q.usage || 0),
      usageInDrive: Number(q.usageInDrive || 0),
      usageInTrash: Number(q.usageInDriveTrash || 0),
    });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Top projects by Drive space used. Lists every file this account created (drive.file
// scope = only Dispatchr's own files), sums bytes per project folder, returns the top 20.
// Super admin only.
app.get("/drive/top-projects", authed, requireRole("super_admin"), async (_req, res) => {
  try {
    const drive = driveClient();
    // Map each project's Drive folder id -> display name (client + agency projects).
    const [{ data: projs }, { data: aps }] = await Promise.all([
      admin.from("projects").select("name, drive_folder_id"),
      admin.from("agency_projects").select("name, drive_folder_id"),
    ]);
    const folderName = {};
    (projs || []).forEach(p => { if (p.drive_folder_id) folderName[p.drive_folder_id] = p.name; });
    (aps || []).forEach(p => { if (p.drive_folder_id) folderName[p.drive_folder_id] = p.name; });

    const sizes = {}; // folder id -> total bytes
    let pageToken;
    do {
      const r = await drive.files.list({
        q: "mimeType != 'application/vnd.google-apps.folder' and trashed = false",
        fields: "nextPageToken, files(size, parents)",
        pageSize: 1000,
        spaces: "drive",
        pageToken,
      });
      for (const f of r.data.files || []) {
        const sz = Number(f.size || 0);
        for (const par of (f.parents || [])) {
          if (folderName[par] != null) { sizes[par] = (sizes[par] || 0) + sz; break; }
        }
      }
      pageToken = r.data.nextPageToken;
    } while (pageToken);

    const projects = Object.entries(sizes)
      .map(([fid, bytes]) => ({ project: folderName[fid], bytes }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 20);
    res.json({ projects });
  } catch (e) { res.status(400).json({ error: e.message }); }
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
    await admin.from("supplier_users").insert({ profile_id: id, series, supplier_company_id, email, created_by: req.user.id });
    res.json({ id, series, name });
  } catch (e) { res.status(400).json({ error: e.message }); }
});
// One upload session = ONE file row. All files chosen together are stored as
// attachments on that single row (they share one description, type, and acknowledgement).
app.post("/projects/:id/files", authed, upload.array("files", 50), async (req, res) => {
  const projectId = req.params.id;
  const { description, type } = req.body;
  try {
    // permission: an agency member of the project, OR the project's client
    const { data: proj0 } = await admin.from("projects").select("client_id").eq("id", projectId).single();
    let allowed = false;
    if (req.user.role === "agency") {
      const { data: member } = await admin.from("project_members").select("project_id").eq("project_id", projectId).eq("member_id", req.user.id).maybeSingle();
      allowed = !!member;
    } else if (req.user.role === "client" && proj0) {
      const { data: cl } = await admin.from("clients").select("profile_id").eq("id", proj0.client_id).single();
      allowed = !!cl && cl.profile_id === req.user.id;
    }
    if (!allowed) return res.status(403).json({ error: "Not allowed to upload to this project" });
    if (!req.files || !req.files.length) return res.status(400).json({ error: "No file" });

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
      const root = await resolveRootFolderId(drive);
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

    const attachments = [];
    for (const file of req.files) {
      const uploaded = await drive.files.create({
        requestBody: { name: file.originalname, parents: [parent] },
        media: { mimeType: file.mimetype, body: Readable.from(file.buffer) },
        fields: "id, webViewLink",
      });
      attachments.push({ id: uploaded.data.id, link: uploaded.data.webViewLink, name: file.originalname, by: req.user.id, at: new Date().toISOString() });
    }
    const first = attachments[0];

    const { data: row, error } = await admin.from("files").insert({
      project_id: projectId, description: description || first.name, type: type || "Others",
      file_name: first.name, attachments,
      drive_file_id: first.id, drive_link: first.link,
      uploaded_by: req.user.id, uploader_role: req.user.role,
    }).select().single();
    if (error) throw error;
    res.json(row);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============================================================
// AGENCY-PROJECT FILE UPLOAD  (the SUPPLIER uploads; the agency acknowledges)
// Drive tree: _DISPATCHR / [AGENCY] / _SUPPLIERS / [SUPPLIER COMPANY] / [yyyymmdd Project]
// ============================================================
app.post("/agency-projects/:id/files", authed, upload.array("files", 50), async (req, res) => {
  const apId = req.params.id;
  const { description, type } = req.body;
  try {
    if (!req.files || !req.files.length) return res.status(400).json({ error: "No file" });
    const { data: ap } = await admin.from("agency_projects")
      .select("id, name, start_date, drive_folder_id, supplier_company_id, agencies(name), supplier_companies(name)")
      .eq("id", apId).single();
    if (!ap) return res.status(404).json({ error: "Project not found" });
    // permission: the project's supplier company, OR an agency member of the project
    let allowed = false;
    if (req.user.role === "supplier") {
      allowed = ap.supplier_company_id === req.supplier?.supplier_company_id;
    } else if (req.user.role === "agency") {
      const { data: member } = await admin.from("agency_project_members").select("agency_project_id").eq("agency_project_id", apId).eq("member_id", req.user.id).maybeSingle();
      allowed = !!member;
    }
    if (!allowed) return res.status(403).json({ error: "Not allowed to upload to this project" });

    const drive = driveClient();
    // One permanent folder per agency project, stored on first upload (renames never fork it).
    let parent = ap.drive_folder_id;
    if (!parent) {
      const agencyName = (ap.agencies?.name || "UNKNOWN").toUpperCase();
      const supplierName = ap.supplier_companies?.name || "SUPPLIER";
      const root = await resolveRootFolderId(drive);
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

    const attachments = [];
    for (const file of req.files) {
      const uploaded = await drive.files.create({
        requestBody: { name: file.originalname, parents: [parent] },
        media: { mimeType: file.mimetype, body: Readable.from(file.buffer) },
        fields: "id, webViewLink",
      });
      attachments.push({ id: uploaded.data.id, link: uploaded.data.webViewLink, name: file.originalname, by: req.user.id, at: new Date().toISOString() });
    }
    const first = attachments[0];

    const { data: row, error } = await admin.from("files").insert({
      agency_project_id: apId, description: description || first.name, type: type || "Others",
      file_name: first.name, attachments,
      drive_file_id: first.id, drive_link: first.link,
      uploaded_by: req.user.id, uploader_role: req.user.role,
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
    const { data: file } = await admin.from("files").select("project_id, agency_project_id, file_name, drive_file_id, attachments").eq("id", req.params.id).single();
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

    // pick the attachment to stream (a row can hold several files from one upload session)
    const atts = Array.isArray(file.attachments) && file.attachments.length
      ? file.attachments
      : [{ id: file.drive_file_id, name: file.file_name }];
    let idx = parseInt(req.query.idx, 10);
    if (!Number.isInteger(idx) || idx < 0 || idx >= atts.length) idx = 0;
    const att = atts[idx];

    const drive = driveClient();
    const stream = await drive.files.get({ fileId: att.id, alt: "media" }, { responseType: "stream" });
    res.setHeader("Content-Disposition", `attachment; filename="${att.name || file.file_name}"`);
    stream.data.pipe(res);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============================================================
// FILE ATTACHMENTS  (add/remove individual files within one delivery row)
// ============================================================

// Remove ONE file from a delivery. Deletes it from Drive too. If it was the last
// file in the delivery, the whole row is removed.
app.delete("/files/:id/attachments/:idx", authed, async (req, res) => {
  try {
    const { data: file } = await admin.from("files")
      .select("id, uploaded_by, attachments, drive_file_id, drive_link, file_name").eq("id", req.params.id).single();
    if (!file) return res.status(404).json({ error: "Not found" });
    if (!canManageFileRow(req, file)) return res.status(403).json({ error: "Not allowed" });

    const atts = (Array.isArray(file.attachments) && file.attachments.length)
      ? file.attachments.slice()
      : [{ id: file.drive_file_id, link: file.drive_link, name: file.file_name }];
    const idx = parseInt(req.params.idx, 10);
    if (!Number.isInteger(idx) || idx < 0 || idx >= atts.length) return res.status(400).json({ error: "Bad index" });

    const removed = atts[idx];
    if (removed && removed.id) { try { await driveClient().files.delete({ fileId: removed.id }); } catch (_) {} }
    atts.splice(idx, 1);

    if (!atts.length) {
      await admin.from("files").delete().eq("id", file.id);
      return res.json({ deleted: true, rowDeleted: true });
    }
    const first = atts[0];
    const { data: row, error } = await admin.from("files")
      .update({ attachments: atts, drive_file_id: first.id, drive_link: first.link, file_name: first.name })
      .eq("id", file.id).select().single();
    if (error) throw error;
    res.json({ deleted: true, rowDeleted: false, file: row });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// Add one or more files to an existing delivery (drops them in the same Drive folder).
app.post("/files/:id/attachments", authed, upload.array("files", 50), async (req, res) => {
  try {
    if (!req.files || !req.files.length) return res.status(400).json({ error: "No file" });
    const { data: file } = await admin.from("files")
      .select("id, uploaded_by, project_id, agency_project_id, attachments, drive_file_id, drive_link, file_name").eq("id", req.params.id).single();
    if (!file) return res.status(404).json({ error: "Not found" });
    if (!canManageFileRow(req, file)) return res.status(403).json({ error: "Not allowed" });

    const drive = driveClient();
    const parent = await resolveFolderForFileRow(drive, file);

    const atts = (Array.isArray(file.attachments) && file.attachments.length)
      ? file.attachments.slice()
      : (file.drive_file_id ? [{ id: file.drive_file_id, link: file.drive_link, name: file.file_name }] : []);
    for (const f of req.files) {
      const up = await drive.files.create({
        requestBody: { name: f.originalname, parents: [parent] },
        media: { mimeType: f.mimetype, body: Readable.from(f.buffer) },
        fields: "id, webViewLink",
      });
      atts.push({ id: up.data.id, link: up.data.webViewLink, name: f.originalname, by: req.user.id, at: new Date().toISOString() });
    }
    const first = atts[0];
    const { data: row, error } = await admin.from("files")
      .update({ attachments: atts, drive_file_id: first.id, drive_link: first.link, file_name: first.name })
      .eq("id", file.id).select().single();
    if (error) throw error;
    res.json(row);
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
    await admin.from("supplier_users").insert({ profile_id: id, series, supplier_company_id, email, created_by: req.user.id });
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

// ---- HIDE / INACTIVE for client & supplier users ------------------------------
// A person is BANNED from logging in whenever hidden OR inactive (RLS can't block
// login, so we ban the auth user). Provenance (hidden_by / role / at) decides who
// may unhide: admin always; otherwise only the agency user who hid it, and only if
// it was an agency hide (admin hides are admin-only to reverse).
const PEOPLE_TABLE = { client: "clients", supplier: "supplier_users", company: "supplier_companies", agency: "agency_users" };

async function applyBan(profileId, banned) {
  if (!profileId) return;
  try { await admin.auth.admin.updateUserById(profileId, { ban_duration: banned ? "876600h" : "none" }); }
  catch (e) { console.error("[Dispatchr] ban toggle failed:", e.message); }
}
async function getPersonRow(kind, id) {
  const table = PEOPLE_TABLE[kind];
  if (!table) return null;
  const key = (kind === "supplier" || kind === "agency") ? "profile_id" : "id";
  const { data } = await admin.from(table).select("*").eq(key, id).maybeSingle();
  return data ? { table, key, row: data } : null;
}
const canManagePerson = (req, row) => req.user.role === "super_admin" || row.created_by === req.user.id;
const canUnhidePerson = (req, row) => req.user.role === "super_admin" || (row.hidden_by === req.user.id && row.hidden_by_role === "agency");

app.post("/people/:kind/:id/hide", authed, requireRole("super_admin", "agency"), async (req, res) => {
  try {
    const found = await getPersonRow(req.params.kind, req.params.id);
    if (!found) return res.status(404).json({ error: "Not found" });
    if (!canManagePerson(req, found.row)) return res.status(403).json({ error: "Only the creator or an admin can hide this." });
    const patch = { hidden_by: req.user.id, hidden_by_role: req.user.role === "super_admin" ? "super_admin" : "agency", hidden_at: new Date().toISOString() };
    const { error } = await admin.from(found.table).update(patch).eq(found.key, req.params.id);
    if (error) throw error;
    await applyBan(found.row.profile_id, true); // hidden => login blocked
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/people/:kind/:id/unhide", authed, requireRole("super_admin", "agency"), async (req, res) => {
  try {
    const found = await getPersonRow(req.params.kind, req.params.id);
    if (!found) return res.status(404).json({ error: "Not found" });
    if (!canUnhidePerson(req, found.row)) return res.status(403).json({ error: "Only whoever hid this (or an admin) can unhide it." });
    const { error } = await admin.from(found.table).update({ hidden_by: null, hidden_by_role: null, hidden_at: null }).eq(found.key, req.params.id);
    if (error) throw error;
    await applyBan(found.row.profile_id, (found.row.status || "active") === "inactive"); // stay banned if still inactive
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/people/:kind/:id/status", authed, requireRole("super_admin", "agency"), async (req, res) => {
  try {
    const status = req.body.status === "inactive" ? "inactive" : "active";
    const found = await getPersonRow(req.params.kind, req.params.id);
    if (!found) return res.status(404).json({ error: "Not found" });
    if (!canManagePerson(req, found.row)) return res.status(403).json({ error: "Only the creator or an admin can change status." });
    const { error } = await admin.from(found.table).update({ status, status_by: req.user.id, status_at: new Date().toISOString() }).eq(found.key, req.params.id);
    if (error) throw error;
    await applyBan(found.row.profile_id, status === "inactive" || !!found.row.hidden_at); // banned if inactive OR still hidden
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

// Resolve profile IDs -> display names (any authed user; service role bypasses RLS)
app.post("/names", authed, async (req, res) => {
  const ids = (req.body.ids || []).filter(Boolean).slice(0, 1000);
  if (!ids.length) return res.json({});
  try {
    const { data } = await admin.from("profiles").select("id, display_name").in("id", ids);
    const map = {}; (data || []).forEach(p => { map[p.id] = p.display_name; });
    res.json(map);
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ============================================================
// ACKNOWLEDGE  — only the party who did NOT upload the file may acknowledge it
// ============================================================
async function isAcknowledger(req, file){
  if(file.project_id){
    const side = file.uploader_role === "client" ? "agency" : "client";
    if(side === "client"){
      const { data: pr } = await admin.from("projects").select("client_id").eq("id", file.project_id).single();
      if(!pr) return false;
      const { data: cl } = await admin.from("clients").select("profile_id").eq("id", pr.client_id).single();
      return req.user.role === "client" && !!cl && cl.profile_id === req.user.id;
    } else {
      if(req.user.role !== "agency") return false;
      const { data: m } = await admin.from("project_members").select("project_id").eq("project_id", file.project_id).eq("member_id", req.user.id).maybeSingle();
      if(m) return true;
      const { data: pr } = await admin.from("projects").select("created_by, agency_id").eq("id", file.project_id).single();
      return !!pr && (pr.created_by === req.user.id || (req.agency && pr.agency_id === req.agency.agency_id));
    }
  } else if(file.agency_project_id){
    const { data: ap } = await admin.from("agency_projects").select("supplier_company_id, agency_id, created_by").eq("id", file.agency_project_id).single();
    if(!ap) return false;
    const side = file.uploader_role === "agency" ? "supplier" : "agency";
    if(side === "supplier"){
      return req.user.role === "supplier" && req.supplier && req.supplier.supplier_company_id === ap.supplier_company_id;
    } else {
      if(req.user.role !== "agency") return false;
      const { data: m } = await admin.from("agency_project_members").select("agency_project_id").eq("agency_project_id", file.agency_project_id).eq("member_id", req.user.id).maybeSingle();
      return !!m || ap.created_by === req.user.id || (req.agency && ap.agency_id === req.agency.agency_id);
    }
  }
  return false;
}

app.post("/files/:id/acknowledge", authed, async (req, res) => {
  try {
    const { data: file } = await admin.from("files").select("id, ack_at, uploader_role, project_id, agency_project_id").eq("id", req.params.id).single();
    if (!file) return res.status(404).json({ error: "Not found" });
    if (!(await isAcknowledger(req, file))) return res.status(403).json({ error: "You're not the party who acknowledges this file" });
    await admin.from("files").update({ ack_at: new Date().toISOString() }).eq("id", file.id);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/files/:id/unacknowledge", authed, async (req, res) => {
  try {
    const { data: file } = await admin.from("files").select("id, ack_at, uploader_role, project_id, agency_project_id").eq("id", req.params.id).single();
    if (!file) return res.status(404).json({ error: "Not found" });
    if (!(await isAcknowledger(req, file))) return res.status(403).json({ error: "Not allowed" });
    if (file.ack_at && (Date.now() - new Date(file.ack_at).getTime() > 5 * 60 * 1000))
      return res.status(409).json({ error: "Reset is only allowed within 5 minutes of acknowledging" });
    await admin.from("files").update({ ack_at: null }).eq("id", file.id);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

await loadRefreshToken(); // seed the current Google token from the DB before serving
await loadRootFolder();   // seed the configured root folder from the DB
app.listen(PORT, () => console.log(`Dispatchr backend on :${PORT}`));
