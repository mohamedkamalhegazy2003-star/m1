const { app, BrowserWindow, Menu, Tray, nativeImage, clipboard, ipcMain, dialog, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const os = require("os");
const http = require("http");
const crypto = require("crypto");
const util = require("util");
const zlib = require("zlib");

let XLSX = null;
try { XLSX = require("xlsx"); } catch (e) { /* reported to the UI when an import is attempted */ }

const HIDDEN = process.argv.indexOf("--hidden") >= 0;   // started by Windows at login: stay in the tray
if (!app.requestSingleInstanceLock()) app.quit();

const APP_DIR = path.join(__dirname, "app");
const DEFAULT_CFG = { mode: null, port: 3210, host: "", background: true, remote: false, tailscale: true };
let cfg = Object.assign({}, DEFAULT_CFG);
let win = null;
let tray = null;
let quitting = false;
let startHidden = HIDDEN;
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
/* start with Windows, in the background (only meaningful for the installed app) */
function applyAutostart() {
  if (!app.isPackaged) return;
  try { app.setLoginItemSettings({ openAtLogin: !!(cfg.background && cfg.mode), args: ["--hidden"] }); } catch (e) {}
}

/* ---------- shared data (lives on the server device only) ---------- */
function loadState() {
  try {
    const s = JSON.parse(fs.readFileSync(dataFile(), "utf8"));
    state = { rev: Number(s.rev) || 0, data: s.data || null };
    dataJsonCache = { rev: -1, json: "null" };
  } catch (e) { state = { rev: 0, data: null }; }
}
/* Saves answer immediately; the file is written a moment later (and always before the app exits). */
let dirtyState = false, persistTimer = null, dataJsonCache = { rev: -1, json: "null" };
function flushState() {
  if (persistTimer) { clearTimeout(persistTimer); persistTimer = null; }
  if (!dirtyState) return;
  const tmp = dataFile() + ".tmp";
  fs.mkdirSync(path.dirname(dataFile()), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(state));
  fs.renameSync(tmp, dataFile());
  dirtyState = false;
}
function persistState() {
  dirtyState = true;
  if (!persistTimer) persistTimer = setTimeout(() => { persistTimer = null; try { flushState(); } catch (e) { console.error("write failed", e); } }, 400);
}
function stateJson() {
  if (dataJsonCache.rev !== state.rev) dataJsonCache = { rev: state.rev, json: JSON.stringify(state.data) };
  return dataJsonCache.json;
}

/* ---------- users, permissions, authentication (server side; passwords never leave this process) ---------- */
const scrypt = util.promisify(crypto.scrypt);
const usersFile = () => path.join(app.getPath("userData"), "users.json");
const actFile = () => path.join(app.getPath("userData"), "activity.json");
const PERMS = ["q_add", "q_edit", "q_del", "clients", "products", "requests", "company", "tpl"];
const ROLES = ["Admin", "Sales", "Viewer", "Custom"];
const PRESET = { Admin: PERMS, Sales: PERMS, Viewer: [], Custom: [] };
let users = [];
let activity = [];
let actTimer = null;
const sessions = new Map();   // token -> { uid, exp, ip, ua, created, seen }
const attempts = new Map();   // "ip|username" -> { n, until }

function writeJson(file, obj) {
  const tmp = file + ".tmp";
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(tmp, JSON.stringify(obj));
  fs.renameSync(tmp, file);
}
function loadUsers() {
  try { users = JSON.parse(fs.readFileSync(usersFile(), "utf8")); if (!Array.isArray(users)) users = []; }
  catch (e) { users = []; }
}
const persistUsers = () => writeJson(usersFile(), users);
function loadActivity() {
  try { activity = JSON.parse(fs.readFileSync(actFile(), "utf8")); if (!Array.isArray(activity)) activity = []; }
  catch (e) { activity = []; }
}

/* who connected, from which IP, with what: kept for the admin "login activity" page */
function ipOf(req) {
  let a = (req && req.socket && req.socket.remoteAddress) || "";
  a = a.replace(/^::ffff:/, "");
  return a === "::1" ? "127.0.0.1" : a;
}
function isPrivateIp(a) {
  if (!a) return false;
  if (a.indexOf(":") >= 0) { a = a.toLowerCase(); return a === "::1" || /^f[cd]/.test(a) || /^fe[89ab]/.test(a); }
  const p = a.split(".").map(Number);
  if (p.length !== 4 || p.some((x) => !(x >= 0 && x <= 255))) return false;
  return p[0] === 10 || p[0] === 127 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 169 && p[1] === 254);
}
function isTailscaleIp(a) {
  if (!a) return false;
  if (a.indexOf(":") >= 0) return a.toLowerCase().indexOf("fd7a:115c:a1e0:") === 0;
  const p = a.split(".").map(Number);
  return p.length === 4 && p[0] === 100 && p[1] >= 64 && p[1] <= 127;
}
function tailscaleAddresses() {
  const out = [];
  const nets = os.networkInterfaces();
  Object.keys(nets).forEach((n) => (nets[n] || []).forEach((a) => { if (a.family === "IPv4" && isTailscaleIp(a.address)) out.push(a.address); }));
  return out;
}
function uaShort(req) {
  const ua = String((req && req.headers && req.headers["user-agent"]) || "");
  const osn = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  const br = /Electron\//.test(ua) ? "Desktop app" : /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "";
  return (br + (br && osn ? " / " : "") + osn).slice(0, 60);
}
function logAct(ev, username, ip, ua, note) {
  activity.push({ ts: Date.now(), ev, user: username || "", ip: ip || "", ua: ua || "", note: note || "" });
  if (activity.length > 5000) activity.splice(0, activity.length - 5000);
  clearTimeout(actTimer);
  actTimer = setTimeout(() => { try { writeJson(actFile(), activity); } catch (e) {} }, 400);
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
function effPerms(u) {
  if (u.role === "Admin") return PERMS.slice();
  if (Array.isArray(u.perms)) return u.perms.filter((p) => PERMS.indexOf(p) >= 0);
  return (PRESET[u.role] || []).slice();
}
const pub = (u) => ({ id: u.id, username: u.username, name: u.name, email: u.email || "", phone: u.phone || "", role: u.role, perms: effPerms(u), disabled: !!u.disabled, sig: !!(u.sig && (u.sig.ar || u.sig.en)) });
const activeAdmins = () => users.filter((u) => u.role === "Admin" && !u.disabled).length;
const cleanUsername = (s) => String(s || "").trim().toLowerCase();
const validUsername = (s) => /^\S{2,40}$/.test(s);
const validPw = (s) => typeof s === "string" && s.length >= 6 && s.length <= 200;
const nextUserId = () => Date.now() * 1000 + Math.floor(Math.random() * 1000);
const cleanPerms = (a) => (Array.isArray(a) ? a.filter((p, i) => PERMS.indexOf(p) >= 0 && a.indexOf(p) === i) : null);
const sid = (token) => crypto.createHash("sha256").update(token).digest("hex").slice(0, 16);

function newSession(u, remember, req) {
  const token = crypto.randomBytes(32).toString("hex"), now = Date.now();
  sessions.set(token, { uid: u.id, exp: now + (remember ? 30 * 86400e3 : 12 * 3600e3), ip: ipOf(req), ua: uaShort(req), created: now, seen: now });
  return token;
}
function tokenOf(req) {
  const m = /^Bearer (\S+)$/.exec(req.headers.authorization || "");
  return m ? m[1] : null;
}
function authUser(req) {
  const t = tokenOf(req), s = t && sessions.get(t);
  if (!s) return null;
  const u = users.find((x) => x.id === s.uid);
  if (s.exp <= Date.now()) { logAct("expired", u ? u.username : "", s.ip, s.ua); sessions.delete(t); return null; }
  if (!u || u.disabled) { sessions.delete(t); return null; }
  s.seen = Date.now();
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
  a.t = Date.now();
  attempts.set(key, a);
  if (attempts.size > 5000) {
    const now = Date.now();
    attempts.forEach((v, k) => { if (v.until < now && now - (v.t || 0) > 3600000) attempts.delete(k); });
    if (attempts.size > 20000) attempts.clear();
  }
}
const isLocal = (req) => ipOf(req) === "127.0.0.1";

/* ---------- which permission does a change to the shared data need? ---------- */
function canon(v) {
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  return JSON.stringify(v === undefined ? null : v);
}
const same = (a, b) => canon(a) === canon(b);
// templates: new design keys added by an app update are not a "change" made by the user
function tplEq(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
  for (const nt of b) {
    const ot = a.find((x) => x.id === nt.id);
    if (!ot || ot.name !== nt.name || !!ot.b !== !!nt.b) return false;
    const od = ot.d || {}, nd = nt.d || {};
    for (const k of Object.keys(nd)) if (k in od && !same(od[k], nd[k])) return false;
    for (const k of Object.keys(od)) if (!(k in nd)) return false;
  }
  return true;
}
function settingsChanged(o, n) {
  o = o || {}; n = n || {};
  const hasT = Array.isArray(o.templates), keys = new Set(Object.keys(o).concat(Object.keys(n)));
  for (const k of keys) {
    if (k === "templates") { if (hasT && !tplEq(o.templates, n.templates)) return true; continue; }
    if (k === "defaultTpl") { if (hasT && o.defaultTpl !== n.defaultTpl) return true; continue; }
    if (k === "cc" && o.cc === undefined && n.cc === "20") continue;
    if (!same(o[k], n[k])) return true;
  }
  return false;
}
function needPerms(o, n) {
  o = o || {}; n = n || {};
  const need = new Set();
  if (!same(o.clients, n.clients)) need.add("clients");
  if (!same(o.products, n.products)) need.add("products");
  if (!same(o.requests, n.requests)) need.add("requests");
  if (!same(o.companies, n.companies)) need.add("company");
  if (settingsChanged(o.settings, n.settings)) need.add("tpl");
  const oq = new Map((o.quotations || []).map((q) => [String(q.id), q])), nq = new Map((n.quotations || []).map((q) => [String(q.id), q]));
  nq.forEach((q, id) => { if (!oq.has(id)) need.add("q_add"); else if (!same(oq.get(id), q)) need.add("q_edit"); });
  oq.forEach((q, id) => { if (!nq.has(id)) need.add("q_del"); });
  return Array.from(need);
}

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

function sendRaw(res, code, body, headers) {
  const h = Object.assign({ "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Vary": "Accept-Encoding" }, headers);
  const ae = (res.req && res.req.headers["accept-encoding"]) || "";
  if (body.length > 1024 && /\bgzip\b/.test(ae)) {
    return zlib.gzip(body, { level: 1 }, (err, z) => {
      if (err) { res.writeHead(code, h); return res.end(body); }
      h["Content-Encoding"] = "gzip"; res.writeHead(code, h); res.end(z);
    });
  }
  res.writeHead(code, h); res.end(body);
}
function sendJson(res, code, obj) { sendRaw(res, code, JSON.stringify(obj), { "Content-Type": "application/json; charset=utf-8" }); }

async function handleApi(req, res, p) {
  const m = req.method, ip = ipOf(req), ua = uaShort(req);

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
    logAct("setup", u.username, ip, ua);
    return sendJson(res, 200, { token: newSession(u, false, req), user: pub(u) });
  }

  if (p === "/api/auth/login" && m === "POST") {
    const b = await readBody(req, 1e5), username = cleanUsername(b.username), key = ip + "|" + username;
    const wait = lockWait(key);
    if (wait) { logAct("locked", username, ip, ua); return sendJson(res, 429, { error: "locked", wait }); }
    const u = users.find((x) => x.username === username);
    // hash even for unknown users so response time does not reveal which usernames exist
    const ok = u ? await checkPw(u, b.password || "") : (await hashPw(b.password || "", "0".repeat(32)), false);
    if (!ok) { failed(key); logAct("login_failed", username, ip, ua); return sendJson(res, 401, { error: "bad_login" }); }
    if (u.disabled) { logAct("login_failed", username, ip, ua, "disabled"); return sendJson(res, 403, { error: "disabled" }); }
    attempts.delete(key);
    logAct("login", u.username, ip, ua);
    return sendJson(res, 200, { token: newSession(u, !!b.remember, req), user: pub(u) });
  }

  /* ----- everything below needs a valid session ----- */
  const me = authUser(req);
  if (!me) return sendJson(res, 401, { error: "auth" });
  const myPerms = effPerms(me);

  if (p === "/api/auth/me" && m === "GET") return sendJson(res, 200, { user: pub(me) });
  if (p === "/api/auth/logout" && m === "POST") {
    sessions.delete(tokenOf(req)); logAct("logout", me.username, ip, ua);
    return sendJson(res, 200, { ok: true });
  }

  if (p === "/api/state" && m === "GET") return sendRaw(res, 200, '{"rev":' + state.rev + ",\"data\":" + stateJson() + ",\"users\":" + JSON.stringify(users.map(pub)) + "}", { "Content-Type": "application/json; charset=utf-8" });
  if (p === "/api/rev" && m === "GET") return sendJson(res, 200, { rev: state.rev });

  if (p === "/api/state" && m === "PUT") {
    const b = await readBody(req, 50 * 1024 * 1024);
    if (!b || typeof b.data !== "object" || b.data === null) return sendJson(res, 400, { error: "bad data" });
    // Someone else saved first: tell the client so it reloads instead of overwriting.
    if (Number(b.rev) !== state.rev) return sendJson(res, 409, { rev: state.rev });
    delete b.data.users; // user accounts are only changed through /api/users
    const need = state.data === null ? (myPerms.length ? [] : ["q_add"]) : needPerms(state.data, b.data);
    if (need.some((x) => myPerms.indexOf(x) < 0)) return sendJson(res, 403, { error: "forbidden", need });
    state = { rev: state.rev + 1, data: b.data };
    try { persistState(); } catch (e) { return sendJson(res, 500, { error: "write failed" }); }
    return sendJson(res, 200, { rev: state.rev });
  }

  /* ----- admin: user management, login activity, active sessions ----- */
  if (p === "/api/users" && m === "GET") return sendJson(res, 200, { users: users.map(pub) });

  if (p === "/api/sigs" && m === "GET") {
    const out = {};
    users.forEach((u) => { if (u.sig && (u.sig.ar || u.sig.en)) out[u.id] = { ar: u.sig.ar || "", en: u.sig.en || "" }; });
    return sendJson(res, 200, { sigs: out });
  }

  const adminOnly = p.indexOf("/api/users") === 0 || p === "/api/activity" || p.indexOf("/api/sessions") === 0;
  if (adminOnly && me.role !== "Admin" && !(m === "PUT" && new RegExp("^/api/users/" + me.id + "$").test(p))) return sendJson(res, 403, { error: "forbidden" });

  if (p === "/api/activity" && m === "GET") return sendJson(res, 200, { items: activity.slice(-1000).reverse() });

  if (p === "/api/sessions" && m === "GET") {
    const now = Date.now(), t0 = tokenOf(req), out = [];
    sessions.forEach((s, t) => {
      const u = users.find((x) => x.id === s.uid);
      if (s.exp > now && u && !u.disabled) out.push({ id: sid(t), username: u.username, name: u.name, ip: s.ip, ua: s.ua, created: s.created, seen: s.seen, current: t === t0 });
    });
    return sendJson(res, 200, { sessions: out.sort((a, b) => b.seen - a.seen) });
  }
  const sm = /^\/api\/sessions\/([0-9a-f]{16})$/.exec(p);
  if (sm && m === "DELETE") {
    let hit = false;
    sessions.forEach((s, t) => {
      if (sid(t) !== sm[1]) return;
      const u = users.find((x) => x.id === s.uid);
      logAct("revoked", u ? u.username : "", s.ip, s.ua, me.username);
      sessions.delete(t); hit = true;
    });
    return sendJson(res, hit ? 200 : 404, hit ? { ok: true } : { error: "not_found" });
  }

  if (p === "/api/users" && m === "POST") {
    const b = await readBody(req, 1e5), username = cleanUsername(b.username);
    if (!validUsername(username)) return sendJson(res, 400, { error: "bad_username" });
    if (users.some((x) => x.username === username)) return sendJson(res, 409, { error: "exists" });
    if (!validPw(b.password)) return sendJson(res, 400, { error: "weak" });
    if (ROLES.indexOf(b.role) < 0) return sendJson(res, 400, { error: "bad_role" });
    const perms = cleanPerms(b.perms) || PRESET[b.role].slice();
    const u = Object.assign({ id: nextUserId(), username, name: String(b.name || username).trim().slice(0, 100) || username, email: String(b.email || "").trim().slice(0, 200), phone: String(b.phone || "").trim().slice(0, 30), role: b.role, perms, disabled: false }, await makeCred(b.password));
    users.push(u); persistUsers();
    return sendJson(res, 200, { user: pub(u) });
  }

  const um = /^\/api\/users\/(\d+)$/.exec(p);
  if (um && (m === "PUT" || m === "DELETE")) {
    const t = users.find((x) => String(x.id) === um[1]);
    if (!t) return sendJson(res, 404, { error: "not_found" });
    const self = t.id === me.id, isAdmin = me.role === "Admin";

    if (m === "DELETE") {
      if (self) return sendJson(res, 409, { error: "self_delete" });
      if (t.role === "Admin" && !t.disabled && activeAdmins() <= 1) return sendJson(res, 409, { error: "last_admin" });
      users = users.filter((x) => x !== t); persistUsers(); dropSessions(t.id);
      return sendJson(res, 200, { ok: true });
    }

    const b = await readBody(req, 6e5);
    if (b.sig !== undefined) {
      const ok = (v) => v === "" || (typeof v === "string" && v.length <= 200000 && /^data:image\/png;base64,[A-Za-z0-9+\/=]+$/.test(v));
      const sg = b.sig && typeof b.sig === "object" ? b.sig : {};
      if ((sg.ar !== undefined && !ok(sg.ar)) || (sg.en !== undefined && !ok(sg.en))) return sendJson(res, 400, { error: "bad_sig" });
      t.sig = { ar: sg.ar !== undefined ? sg.ar : (t.sig && t.sig.ar) || "", en: sg.en !== undefined ? sg.en : (t.sig && t.sig.en) || "" };
    }
    if (isAdmin) {
      if (b.role !== undefined && ROLES.indexOf(b.role) < 0) return sendJson(res, 400, { error: "bad_role" });
      const losesAdmin = (b.role !== undefined && b.role !== "Admin") || b.disabled === true;
      if (t.role === "Admin" && !t.disabled && losesAdmin && activeAdmins() <= 1) return sendJson(res, 409, { error: "last_admin" });
      if (self && b.disabled === true) return sendJson(res, 409, { error: "self_disable" });
    }
    let cred = null;
    if (b.password) {
      if (!validPw(b.password)) return sendJson(res, 400, { error: "weak" });
      if (self && !(await checkPw(t, b.currentPassword || ""))) return sendJson(res, 403, { error: "bad_current" });
      cred = await makeCred(b.password);
    }
    if (b.name !== undefined) t.name = String(b.name).trim().slice(0, 100) || t.name;
    if (b.email !== undefined) t.email = String(b.email).trim().slice(0, 200);
    if (b.phone !== undefined) t.phone = String(b.phone).trim().slice(0, 30);
    if (isAdmin) {
      if (b.role !== undefined) { t.role = b.role; if (!Array.isArray(b.perms)) t.perms = PRESET[b.role].slice(); }
      if (Array.isArray(b.perms)) t.perms = cleanPerms(b.perms);
      if (b.disabled !== undefined) { t.disabled = !!b.disabled; if (t.disabled) dropSessions(t.id); }
    }
    if (cred) { Object.assign(t, cred); dropSessions(t.id, self ? tokenOf(req) : null); }
    persistUsers();
    return sendJson(res, 200, { user: pub(t) });
  }

  return sendJson(res, 404, { error: "not_found" });
}

let xlsxBuf = null;
function serveXlsx(res) {
  try {
    if (!xlsxBuf) xlsxBuf = fs.readFileSync(require.resolve("xlsx/dist/xlsx.full.min.js"));
    res.writeHead(200, { "Content-Type": MIME[".js"], "Cache-Control": "public, max-age=86400" });
    res.end(xlsxBuf);
  } catch (e) { res.writeHead(404); res.end("Not found"); }
}

process.on("uncaughtException", (e) => { try { console.error("uncaught", e && e.message); } catch (x) {} });
const SEC_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
};
function handleRequest(req, res) {
  for (const k in SEC_HEADERS) res.setHeader(k, SEC_HEADERS[k]);
  try { return handleRequest2(req, res); }
  catch (e) { try { if (!res.headersSent) res.writeHead(400); res.end(); } catch (e2) {} }
}
function handleRequest2(req, res) {
  if (!cfg.remote && !isPrivateIp(ipOf(req)) && !(cfg.tailscale !== false && isTailscaleIp(ipOf(req)))) { res.writeHead(403, { "Content-Type": "text/plain" }); return res.end("Remote access is disabled"); }
  let u;
  try { u = new URL(req.url, "http://localhost"); } catch (e) { res.writeHead(400); return res.end(); }

  if (u.pathname.indexOf("/api/") === 0) {
    handleApi(req, res, u.pathname).catch((e) => {
      if (!res.headersSent) sendJson(res, e && (e.code === 413 || e.code === 400) ? e.code : 500, { error: "request failed" });
    });
    return;
  }

  if (req.method !== "GET") { res.writeHead(405); return res.end(); }
  if (u.pathname === "/vendor/xlsx.js") return serveXlsx(res);

  const rel = u.pathname === "/" ? "index.html" : decodeURIComponent(u.pathname).replace(/^\/+/, "");
  if (rel.indexOf("\0") >= 0) { res.writeHead(400); return res.end(); }
  const file = path.normalize(path.join(APP_DIR, rel));
  if (file.indexOf(APP_DIR + path.sep) !== 0 || file === path.join(APP_DIR, "setup.html")) { res.writeHead(403); return res.end(); }
  fs.stat(file, (e0, st) => {
    if (e0 || !st.isFile()) { res.writeHead(404); return res.end("Not found"); }
    const etag = '"' + st.size + "-" + Math.round(st.mtimeMs) + '"';
    if (req.headers["if-none-match"] === etag) { res.writeHead(304, { ETag: etag }); return res.end(); }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404); return res.end("Not found"); }
      sendRaw(res, 200, buf, { "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream", "Cache-Control": "no-cache", ETag: etag });
    });
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

/* ---------- tray + window ---------- */
function trayImage() {
  const img = nativeImage.createFromPath(path.join(APP_DIR, "icon.png"));
  return img.isEmpty() ? img : img.resize({ width: 16, height: 16 });
}
function showWin() {
  if (!win || win.isDestroyed()) { startHidden = false; boot(); return; }
  if (win.isMinimized()) win.restore();
  win.show(); win.focus();
}
function updateTray() {
  if (!tray) return;
  const items = [{ label: "فتح · Open", click: showWin }];
  if (cfg.mode === "server") {
    lanAddresses().forEach((ip) => {
      const url = "http://" + ip + ":" + cfg.port;
      items.push({ label: url + "  (" + "نسخ · Copy" + ")", click: () => clipboard.writeText(url) });
    });
  }
  items.push({ type: "separator" }, { label: "خروج · Exit", click: () => { quitting = true; app.quit(); } });
  tray.setContextMenu(Menu.buildFromTemplate(items));
  tray.setToolTip("Quotation Management" + (cfg.mode === "server" ? " - server :" + cfg.port : ""));
}
function syncTray() {
  const want = !!(cfg.background && cfg.mode);
  if (want && !tray) {
    try { tray = new Tray(trayImage()); tray.on("click", showWin); tray.on("double-click", showWin); } catch (e) { tray = null; }
  } else if (!want && tray) { tray.destroy(); tray = null; }
  updateTray();
}

function createWindow() {
  if (win && !win.isDestroyed()) return win;
  win = new BrowserWindow({
    width: 1280, height: 800, minWidth: 900, minHeight: 600,
    autoHideMenuBar: true,
    show: !(startHidden && cfg.mode),
    icon: path.join(APP_DIR, "icon.png"),
    title: "Quotation Management",
    webPreferences: { contextIsolation: true, nodeIntegration: false, preload: path.join(__dirname, "preload.js") }
  });
  win.on("close", (e) => {
    // closing the window keeps the server running in the tray; "Exit" in the tray quits for real
    if (!quitting && tray && cfg.background && cfg.mode) { e.preventDefault(); win.hide(); }
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
  w.show();
  w.loadFile(path.join(APP_DIR, "setup.html"), error ? { query: { error } } : undefined);
}

async function boot() {
  cfg = loadCfg();
  const w = createWindow();
  startHidden = false;
  applyAutostart();
  syncTray();
  if (cfg.mode === "server") {
    try {
      loadState();
      loadUsers();
      loadActivity();
      await startServer(cfg.port);
      updateTray();
      w.loadURL("http://127.0.0.1:" + cfg.port + "/");
    } catch (e) {
      w.show();
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
  mode: cfg.mode, port: cfg.port, host: cfg.host, background: !!cfg.background, remote: !!cfg.remote, tailscale: cfg.tailscale !== false, tsIps: tailscaleAddresses(), packaged: app.isPackaged,
  ips: lanAddresses(), dataFile: dataFile(), version: app.getVersion()
}));

ipcMain.handle("cfg:set", async (e, c) => {
  if (!fromLocalFile(e)) return { ok: false };
  const mode = c && c.mode === "terminal" ? "terminal" : "server";
  const port = Math.round(Number(c && c.port));
  if (!(port >= 1 && port <= 65535)) return { ok: false, error: "port" };
  let host = String((c && c.host) || "").trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  if (mode === "terminal" && !host) return { ok: false, error: "host" };
  cfg = Object.assign({}, cfg, { mode, port, host: mode === "terminal" ? host : "" });
  saveCfg(cfg);
  setImmediate(boot);
  return { ok: true };
});

ipcMain.handle("bg:set", (e, on) => {
  cfg.background = !!on;
  saveCfg(cfg);
  applyAutostart();
  syncTray();
  return cfg.background;
});

ipcMain.handle("remote:set", (e, on) => {
  if (!fromLocalFile(e)) return !!cfg.remote;
  cfg.remote = !!on;
  saveCfg(cfg);
  if (!cfg.remote) { sessions.forEach((s, t) => { if (!isPrivateIp(s.ip) && !(cfg.tailscale !== false && isTailscaleIp(s.ip))) sessions.delete(t); }); }
  return cfg.remote;
});

ipcMain.handle("ts:set", (e, on) => {
  if (!fromLocalFile(e)) return cfg.tailscale !== false;
  cfg.tailscale = !!on;
  saveCfg(cfg);
  if (!cfg.tailscale && !cfg.remote) sessions.forEach((s, t) => { if (isTailscaleIp(s.ip)) sessions.delete(t); });
  return cfg.tailscale;
});

ipcMain.handle("ip:public", () => new Promise((resolve) => {
  try {
    const r = require("https").get("https://api.ipify.org", { timeout: 6000 }, (res) => {
      let d = ""; res.on("data", (c) => { d += c; if (d.length > 100) res.destroy(); });
      res.on("end", () => resolve(/^[0-9a-fA-F.:]{3,45}$/.test(d.trim()) ? d.trim() : ""));
    });
    r.on("timeout", () => { r.destroy(); resolve(""); });
    r.on("error", () => resolve(""));
  } catch (e) { resolve(""); }
}));

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
    // web fonts (when online) need a moment to arrive before the page is printed
    if (/fonts\.googleapis\.com/.test(String(o.html))) await new Promise((r) => setTimeout(r, 1800));
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

ipcMain.handle("mail:open", async (e, o) => {
  const to = String((o && o.to) || "").trim().slice(0, 200);
  const q = "subject=" + encodeURIComponent(String((o && o.subject) || "").slice(0, 300)) + "&body=" + encodeURIComponent(String((o && o.body) || "").slice(0, 3000));
  await shell.openExternal("mailto:" + encodeURIComponent(to).replace(/%40/g, "@") + "?" + q);
  return true;
});

ipcMain.handle("file:show", (e, p) => { if (p) shell.showItemInFolder(String(p)); return true; });

/* ---------- lifecycle ---------- */
app.on("second-instance", () => showWin());
process.on("exit", () => { try { flushState(); } catch (e) {} });
app.on("before-quit", () => { quitting = true; try { flushState(); } catch (e) {} });

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  boot();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) boot(); });
});

app.on("window-all-closed", () => {
  // with the tray active the window is only hidden, so this fires when we really are done
  stopServer();
  if (process.platform !== "darwin") app.quit();
});
