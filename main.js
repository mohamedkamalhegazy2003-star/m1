const { app, BrowserWindow, Menu, ipcMain, dialog, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const os = require("os");
const http = require("http");
const crypto = require("crypto");
const util = require("util");

let XLSX = null;
try { XLSX = require("xlsx"); } catch (e) { /* reported to the UI when an import is attempted */ }

if (!app.requestSingleInstanceLock()) app.quit();

const APP_DIR = path.join(__dirname, "app");
const DEFAULT_CFG = { mode: null, port: 3210, host: "" };
let cfg = Object.assign({}, DEFAULT_CFG);
let win = null;
let server = null;
let state = { rev: 0, data: null };

/* ---------- config (per device) ---------- */
const cfgFile = () => path.join(app.getPath("userData"), "config.json");
const dataFile = () => path.join(app.getPath("userData"), "data.json");

function loadCfg() {
  try { return Object.assign({}, DEFAULT_CFG, JSON.parse(fs.readFileSync(cfgFile(), "utf8"))); }
  catch (e) { return Object.assign({}, DEFAULT_CFG); }
}
function saveCfg(c) {
  fs.mkdirSync(path.dirname(cfgFile()), { recursive: true });
  fs.writeFileSync(cfgFile(), JSON.stringify(c, null, 2));
}

/* ---------- shared data (lives on the server device only) ---------- */
function loadState() {
  try {
    const s = JSON.parse(fs.readFileSync(dataFile(), "utf8"));
    state = { rev: Number(s.rev) || 0, data: s.data || null };
  } catch (e) { state = { rev: 0, data: null }; }
}
function persistState() {
  const tmp = dataFile() + ".tmp";
  fs.mkdirSync(path.dirname(dataFile()), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(state));
  fs.renameSync(tmp, dataFile());
}

/* ---------- users + authentication (server side; passwords never leave this process) ---------- */
const scrypt = util.promisify(crypto.scrypt);
const usersFile = () => path.join(app.getPath("userData"), "users.json");
const ROLES = ["Admin", "Sales", "Viewer"];
let users = [];
const sessions = new Map();   // token -> { uid, exp }
const attempts = new Map();   // "ip|username" -> { n, until }

function loadUsers() {
  try { users = JSON.parse(fs.readFileSync(usersFile(), "utf8")); if (!Array.isArray(users)) users = []; }
  catch (e) { users = []; }
}
function persistUsers() {
  const tmp = usersFile() + ".tmp";
  fs.mkdirSync(path.dirname(usersFile()), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(users));
  fs.renameSync(tmp, usersFile());
}
async function hashPw(pw, salt) { return (await scrypt(String(pw), salt, 64)).toString("hex"); }
async function makeCred(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: await hashPw(pw, salt) };
}
async function checkPw(u, pw) {
  const a = Buffer.from(await hashPw(pw, u.salt), "hex"), b = Buffer.from(u.hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const pub = (u) => ({ id: u.id, username: u.username, name: u.name, email: u.email || "", role: u.role });
const adminCount = () => users.filter((u) => u.role === "Admin").length;
const cleanUsername = (s) => String(s || "").trim().toLowerCase();
const validUsername = (s) => /^\S{2,40}$/.test(s);
const validPw = (s) => typeof s === "string" && s.length >= 6 && s.length <= 200;
const nextUserId = () => Date.now() * 1000 + Math.floor(Math.random() * 1000);

function newSession(u, remember) {
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, { uid: u.id, exp: Date.now() + (remember ? 30 * 86400e3 : 12 * 3600e3) });
  return token;
}
function tokenOf(req) {
  const m = /^Bearer (\S+)$/.exec(req.headers.authorization || "");
  return m ? m[1] : null;
}
function authUser(req) {
  const t = tokenOf(req), s = t && sessions.get(t);
  if (!s) return null;
  const u = s.exp > Date.now() ? users.find((x) => x.id === s.uid) : null;
  if (!u) { sessions.delete(t); return null; }
  return u;
}
function dropSessions(uid, keep) {
  sessions.forEach((s, t) => { if (s.uid === uid && t !== keep) sessions.delete(t); });
}
function lockWait(key) {
  const a = attempts.get(key);
  return a && a.until > Date.now() ? Math.ceil((a.until - Date.now()) / 1000) : 0;
}
function failed(key) {
  const a = attempts.get(key) || { n: 0, until: 0 };
  a.n++;
  if (a.n >= 5) a.until = Date.now() + Math.min(300, 30 * Math.pow(2, a.n - 5)) * 1000;
  attempts.set(key, a);
}
const isLocal = (req) => ["127.0.0.1", "::1", "::ffff:127.0.0.1"].indexOf(req.socket.remoteAddress) >= 0;

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error("too big"), { code: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); }
      catch (e) { reject(Object.assign(new Error("bad json"), { code: 400 })); }
    });
    req.on("error", reject);
  });
}

const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon"
};

function sendJson(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
  res.end(JSON.stringify(obj));
}

async function handleApi(req, res, p) {
  const m = req.method;

  /* ----- public: auth ----- */
  if (p === "/api/auth/status" && m === "GET") return sendJson(res, 200, { setup: users.length === 0, canSetup: isLocal(req) });

  if (p === "/api/auth/setup" && m === "POST") {
    if (users.length) return sendJson(res, 403, { error: "forbidden" });
    // The very first admin can only be created from the server device itself, so nobody else on the network can claim the system.
    if (!isLocal(req)) return sendJson(res, 403, { error: "setup_local" });
    const b = await readBody(req, 1e5), username = cleanUsername(b.username);
    if (!validUsername(username)) return sendJson(res, 400, { error: "bad_username" });
    if (!validPw(b.password)) return sendJson(res, 400, { error: "weak" });
    const u = Object.assign({ id: nextUserId(), username, name: String(b.name || username).trim().slice(0, 100) || username, email: "", role: "Admin" }, await makeCred(b.password));
    users.push(u); persistUsers();
    return sendJson(res, 200, { token: newSession(u, false), user: pub(u) });
  }

  if (p === "/api/auth/login" && m === "POST") {
    const b = await readBody(req, 1e5), username = cleanUsername(b.username), key = req.socket.remoteAddress + "|" + username;
    const wait = lockWait(key);
    if (wait) return sendJson(res, 429, { error: "locked", wait });
    const u = users.find((x) => x.username === username);
    // hash even for unknown users so response time does not reveal which usernames exist
    const ok = u ? await checkPw(u, b.password || "") : (await hashPw(b.password || "", "0".repeat(32)), false);
    if (!ok) { failed(key); return sendJson(res, 401, { error: "bad_login" }); }
    attempts.delete(key);
    return sendJson(res, 200, { token: newSession(u, !!b.remember), user: pub(u) });
  }

  /* ----- everything below needs a valid session ----- */
  const me = authUser(req);
  if (!me) return sendJson(res, 401, { error: "auth" });

  if (p === "/api/auth/me" && m === "GET") return sendJson(res, 200, { user: pub(me) });
  if (p === "/api/auth/logout" && m === "POST") { sessions.delete(tokenOf(req)); return sendJson(res, 200, { ok: true }); }

  if (p === "/api/state" && m === "GET") return sendJson(res, 200, { rev: state.rev, data: state.data, users: users.map(pub) });
  if (p === "/api/rev" && m === "GET") return sendJson(res, 200, { rev: state.rev });

  if (p === "/api/state" && m === "PUT") {
    if (me.role === "Viewer") return sendJson(res, 403, { error: "forbidden" });
    const b = await readBody(req, 50 * 1024 * 1024);
    if (!b || typeof b.data !== "object" || b.data === null) return sendJson(res, 400, { error: "bad data" });
    // Someone else saved first: tell the client so it reloads instead of overwriting.
    if (Number(b.rev) !== state.rev) return sendJson(res, 409, { rev: state.rev });
    delete b.data.users; // user accounts are only changed through /api/users
    state = { rev: state.rev + 1, data: b.data };
    try { persistState(); } catch (e) { return sendJson(res, 500, { error: "write failed" }); }
    return sendJson(res, 200, { rev: state.rev });
  }

  /* ----- user management ----- */
  if (p === "/api/users" && m === "GET") return sendJson(res, 200, { users: users.map(pub) });

  if (p === "/api/users" && m === "POST") {
    if (me.role !== "Admin") return sendJson(res, 403, { error: "forbidden" });
    const b = await readBody(req, 1e5), username = cleanUsername(b.username);
    if (!validUsername(username)) return sendJson(res, 400, { error: "bad_username" });
    if (users.some((x) => x.username === username)) return sendJson(res, 409, { error: "exists" });
    if (!validPw(b.password)) return sendJson(res, 400, { error: "weak" });
    if (ROLES.indexOf(b.role) < 0) return sendJson(res, 400, { error: "bad_role" });
    const u = Object.assign({ id: nextUserId(), username, name: String(b.name || username).trim().slice(0, 100) || username, email: String(b.email || "").trim().slice(0, 200), role: b.role }, await makeCred(b.password));
    users.push(u); persistUsers();
    return sendJson(res, 200, { user: pub(u) });
  }

  const um = /^\/api\/users\/(\d+)$/.exec(p);
  if (um && (m === "PUT" || m === "DELETE")) {
    const t = users.find((x) => String(x.id) === um[1]);
    if (!t) return sendJson(res, 404, { error: "not_found" });
    const self = t.id === me.id;

    if (m === "DELETE") {
      if (me.role !== "Admin") return sendJson(res, 403, { error: "forbidden" });
      if (self) return sendJson(res, 409, { error: "self_delete" });
      if (t.role === "Admin" && adminCount() <= 1) return sendJson(res, 409, { error: "last_admin" });
      users = users.filter((x) => x !== t); persistUsers(); dropSessions(t.id);
      return sendJson(res, 200, { ok: true });
    }

    if (me.role !== "Admin" && !self) return sendJson(res, 403, { error: "forbidden" });
    const b = await readBody(req, 1e5);
    if (b.role !== undefined && me.role === "Admin") {
      if (ROLES.indexOf(b.role) < 0) return sendJson(res, 400, { error: "bad_role" });
      if (t.role === "Admin" && b.role !== "Admin" && adminCount() <= 1) return sendJson(res, 409, { error: "last_admin" });
    }
    let cred = null;
    if (b.password) {
      if (!validPw(b.password)) return sendJson(res, 400, { error: "weak" });
      if (self && !(await checkPw(t, b.currentPassword || ""))) return sendJson(res, 403, { error: "bad_current" });
      cred = await makeCred(b.password);
    }
    if (b.name !== undefined) t.name = String(b.name).trim().slice(0, 100) || t.name;
    if (b.email !== undefined) t.email = String(b.email).trim().slice(0, 200);
    if (b.role !== undefined && me.role === "Admin") t.role = b.role;
    if (cred) { Object.assign(t, cred); dropSessions(t.id, self ? tokenOf(req) : null); }
    persistUsers();
    return sendJson(res, 200, { user: pub(t) });
  }

  return sendJson(res, 404, { error: "not_found" });
}

function handleRequest(req, res) {
  let u;
  try { u = new URL(req.url, "http://localhost"); } catch (e) { res.writeHead(400); return res.end(); }

  if (u.pathname.indexOf("/api/") === 0) {
    handleApi(req, res, u.pathname).catch((e) => {
      if (!res.headersSent) sendJson(res, e && (e.code === 413 || e.code === 400) ? e.code : 500, { error: "request failed" });
    });
    return;
  }

  if (req.method !== "GET") { res.writeHead(405); return res.end(); }

  const rel = u.pathname === "/" ? "index.html" : decodeURIComponent(u.pathname).replace(/^\/+/, "");
  const file = path.normalize(path.join(APP_DIR, rel));
  if (file.indexOf(APP_DIR + path.sep) !== 0) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end("Not found"); }
    res.writeHead(200, { "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
    res.end(buf);
  });
}

function stopServer() {
  if (server) { try { server.close(); } catch (e) {} server = null; }
}
function startServer(port) {
  stopServer();
  return new Promise((resolve, reject) => {
    const s = http.createServer(handleRequest);
    s.once("error", reject);
    s.listen(port, "0.0.0.0", () => { server = s; resolve(); });
  });
}

function lanAddresses() {
  const out = [];
  const nets = os.networkInterfaces();
  Object.keys(nets).forEach((n) => (nets[n] || []).forEach((a) => {
    if (a.family === "IPv4" && !a.internal) out.push(a.address);
  }));
  return out;
}

/* ---------- window ---------- */
function createWindow() {
  if (win && !win.isDestroyed()) return win;
  win = new BrowserWindow({
    width: 1280, height: 800, minWidth: 900, minHeight: 600,
    autoHideMenuBar: true,
    title: "Quotation Management",
    webPreferences: { contextIsolation: true, nodeIntegration: false, preload: path.join(__dirname, "preload.js") }
  });
  win.on("closed", () => { win = null; });
  win.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  win.webContents.on("did-fail-load", (e, code, desc, url, isMain) => {
    if (!isMain || code === -3) return; // -3 = aborted by a newer navigation
    if (url && url.indexOf("file:") === 0) return;
    showSetup(desc + " (" + url + ")");
  });
  return win;
}

function showSetup(error) {
  const w = createWindow();
  w.loadFile(path.join(APP_DIR, "setup.html"), error ? { query: { error } } : undefined);
}

async function boot() {
  cfg = loadCfg();
  const w = createWindow();
  if (cfg.mode === "server") {
    try {
      loadState();
      loadUsers();
      await startServer(cfg.port);
      w.loadURL("http://127.0.0.1:" + cfg.port + "/");
    } catch (e) {
      showSetup("Cannot start the server on port " + cfg.port + ": " + e.message);
    }
  } else if (cfg.mode === "terminal" && cfg.host) {
    stopServer();
    w.loadURL("http://" + cfg.host + ":" + cfg.port + "/");
  } else {
    stopServer();
    showSetup();
  }
}

/* ---------- IPC ---------- */
const fromLocalFile = (e) => !!(e.senderFrame && String(e.senderFrame.url).indexOf("file:") === 0);

ipcMain.handle("info:get", () => ({
  mode: cfg.mode, port: cfg.port, host: cfg.host,
  ips: lanAddresses(), dataFile: dataFile(), version: app.getVersion()
}));

ipcMain.handle("cfg:set", async (e, c) => {
  if (!fromLocalFile(e)) return { ok: false };
  const mode = c && c.mode === "terminal" ? "terminal" : "server";
  const port = Math.round(Number(c && c.port));
  if (!(port >= 1 && port <= 65535)) return { ok: false, error: "port" };
  let host = String((c && c.host) || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  if (mode === "terminal" && !host) return { ok: false, error: "host" };
  cfg = { mode, port, host: mode === "terminal" ? host : "" };
  saveCfg(cfg);
  setImmediate(boot);
  return { ok: true };
});

ipcMain.handle("cfg:setup", () => { showSetup(); return true; });

function decodeCsv(buf) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(buf); }
  catch (e) { return new TextDecoder("windows-1256").decode(buf); } // Arabic Excel "CSV" files
}

ipcMain.handle("excel:pick", async () => {
  const r = await dialog.showOpenDialog(win, {
    properties: ["openFile"],
    filters: [{ name: "Excel / CSV", extensions: ["xlsx", "xls", "xlsm", "csv"] }]
  });
  if (r.canceled || !r.filePaths.length) return null;
  if (!XLSX) return { error: "The 'xlsx' module is not installed. Run npm install." };
  try {
    const f = r.filePaths[0];
    const buf = fs.readFileSync(f);
    const wb = path.extname(f).toLowerCase() === ".csv"
      ? XLSX.read(decodeCsv(buf).replace(/^﻿/, ""), { type: "string" })
      : XLSX.read(buf, { type: "buffer" });
    return {
      name: path.basename(f),
      sheets: wb.SheetNames.map((n) => ({
        name: n,
        rows: XLSX.utils.sheet_to_json(wb.Sheets[n], { header: 1, defval: "", raw: true, blankrows: false })
      }))
    };
  } catch (e) { return { error: String(e.message || e) }; }
});

ipcMain.handle("pdf:save", async (e, o) => {
  const safe = String((o && o.name) || "quotation").replace(/[\\/:*?"<>|]/g, "_").slice(0, 80) + ".pdf";
  const dir = path.join(app.getPath("documents"), "Quotations");
  let target = path.join(dir, safe);
  if (o && o.ask) {
    const r = await dialog.showSaveDialog(win, { defaultPath: target, filters: [{ name: "PDF", extensions: ["pdf"] }] });
    if (r.canceled || !r.filePath) return null;
    target = r.filePath;
  }
  const tmp = path.join(os.tmpdir(), "qm-" + Date.now() + ".html");
  fs.writeFileSync(tmp, String(o.html), "utf8");
  const w = new BrowserWindow({ show: false, webPreferences: { sandbox: true, javascript: false } });
  try {
    await w.loadFile(tmp);
    // Page size and margins come from the document's own @page rule (A4, template margin).
    const pdf = await w.webContents.printToPDF({ printBackground: true, preferCSSPageSize: true });
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, pdf);
    return target;
  } finally {
    w.destroy();
    fs.unlink(tmp, () => {});
  }
});

ipcMain.handle("wa:open", async (e, o) => {
  const phone = String((o && o.phone) || "").replace(/\D/g, "");
  if (!phone) return false;
  await shell.openExternal("https://wa.me/" + phone + "?text=" + encodeURIComponent(String((o && o.text) || "")));
  return true;
});

ipcMain.handle("file:show", (e, p) => { if (p) shell.showItemInFolder(String(p)); return true; });

/* ---------- lifecycle ---------- */
app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  boot();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) boot(); });
});

app.on("window-all-closed", () => {
  stopServer();
  if (process.platform !== "darwin") app.quit();
});
