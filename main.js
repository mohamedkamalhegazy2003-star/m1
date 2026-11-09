const { app, BrowserWindow, Menu, ipcMain, dialog, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const os = require("os");
const http = require("http");

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

const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon"
};

function sendJson(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}

function handleRequest(req, res) {
  let u;
  try { u = new URL(req.url, "http://localhost"); } catch (e) { res.writeHead(400); return res.end(); }

  if (u.pathname === "/api/state" && req.method === "GET") return sendJson(res, 200, state);
  if (u.pathname === "/api/rev" && req.method === "GET") return sendJson(res, 200, { rev: state.rev });

  if (u.pathname === "/api/state" && req.method === "PUT") {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > 50 * 1024 * 1024) { res.writeHead(413); res.end(); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch (e) { return sendJson(res, 400, { error: "bad json" }); }
      if (!body || typeof body.data !== "object" || body.data === null) return sendJson(res, 400, { error: "bad data" });
      // Someone else saved first: tell the client so it reloads instead of overwriting.
      if (Number(body.rev) !== state.rev) return sendJson(res, 409, { rev: state.rev });
      state = { rev: state.rev + 1, data: body.data };
      try { persistState(); } catch (e) { return sendJson(res, 500, { error: "write failed" }); }
      sendJson(res, 200, { rev: state.rev });
    });
    return;
  }

  if (req.method !== "GET") { res.writeHead(405); return res.end(); }

  const rel = u.pathname === "/" ? "index.html" : decodeURIComponent(u.pathname).replace(/^\/+/, "");
  const file = path.normalize(path.join(APP_DIR, rel));
  if (file.indexOf(APP_DIR + path.sep) !== 0) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end("Not found"); }
    res.writeHead(200, { "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream", "Cache-Control": "no-store" });
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
    const pdf = await w.webContents.printToPDF({ printBackground: true, pageSize: "A4", margins: { marginType: "default" } });
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
