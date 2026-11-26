require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const required = ["ADMIN_USERNAME", "ADMIN_PASSWORD", "SESSION_SECRET", "KEY_PEPPER"];
for (const name of required) {
  if (!process.env[name] || process.env[name].startsWith("CAMBIA-")) {
    console.error(`Falta configurar ${name}. Copia .env.example a .env y cambia los secretos.`);
    process.exit(1);
  }
}
if (process.env.ADMIN_PASSWORD.length < 16 ||
    process.env.SESSION_SECRET.length < 32 ||
    process.env.KEY_PEPPER.length < 32) {
  console.error("ADMIN_PASSWORD debe tener 16+ caracteres y los dos secretos 32+.");
  process.exit(1);
}

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === "production";
if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "rx7.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS access_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    key_hint TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT
  );
  CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hint TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    success INTEGER NOT NULL,
    created_at TEXT NOT NULL
  );
`);
const insertKey = db.prepare(`INSERT INTO access_keys
  (key_hash,key_hint,label,created_at,expires_at) VALUES (?,?,?,?,?)`);
const listKeys = db.prepare(`SELECT id,key_hint,label,created_at,expires_at,revoked_at,last_used_at
  FROM access_keys ORDER BY id DESC LIMIT 300`);
const getKey = db.prepare("SELECT * FROM access_keys WHERE key_hash = ?");
const useKey = db.prepare("UPDATE access_keys SET last_used_at=? WHERE id=?");
const revokeKey = db.prepare("UPDATE access_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL");
const logEvent = db.prepare("INSERT INTO login_events (key_hint,ip_hash,success,created_at) VALUES (?,?,?,?)");

const SQLiteStore = SQLiteStoreFactory(session);
app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: isProd ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use(session({
  name: "rx7.sid",
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir, table: "sessions" }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: "strict",
    maxAge: 30 * 60 * 1000
  }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false });
const keyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: "draft-7", legacyHeaders: false });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 60, standardHeaders: "draft-7", legacyHeaders: false });

function nowIso() { return new Date().toISOString(); }
function keyDigest(key) {
  return crypto.createHmac("sha256", process.env.KEY_PEPPER).update(key).digest("hex");
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function ipDigest(ip) {
  return crypto.createHmac("sha256", process.env.KEY_PEPPER).update(String(ip || "")).digest("hex");
}
function requireAdmin(req, res, next) {
  if (!req.session || req.session.admin !== true) return res.status(401).json({ success: false, message: "Inicia sesión como administrador." });
  next();
}
function requireSameOrigin(req, res, next) {
  const origin = req.get("origin");
  const host = req.get("host");
  if (origin) {
    try {
      const u = new URL(origin);
      if (u.host !== host) return res.status(403).json({ success: false, message: "Origen no permitido." });
    } catch { return res.status(403).json({ success: false, message: "Origen no válido." }); }
  }
  next();
}
function requireCsrf(req, res, next) {
  if (!req.session.csrf || !safeEqual(req.get("x-rx7-csrf") || "", req.session.csrf))
    return res.status(403).json({ success: false, message: "Solicitud no válida. Recarga el panel." });
  next();
}
function makeAccessKey() {
  const raw = crypto.randomBytes(18).toString("hex").toUpperCase();
  return "RX7-" + raw.match(/.{1,6}/g).join("-");
}
function parseExpiry(body) {
  if (body.duration === "permanent") return null;
  if (body.duration === "custom") {
    const d = new Date(body.expiresAt);
    if (!body.expiresAt || Number.isNaN(d.getTime()) || d.getTime() <= Date.now())
      throw new Error("Indica una fecha y hora futura para la expiración.");
    return d.toISOString();
  }
  const days = Number(body.duration);
  if (![1, 7, 30, 90, 365].includes(days)) throw new Error("Duración no permitida.");
  return new Date(Date.now() + days * 86400000).toISOString();
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "RX7 LOGIN" }));

app.post("/api/login", keyLimiter, (req, res) => {
  const key = String(req.body.key || "").trim().toUpperCase();
  if (key.length < 10 || key.length > 100) return res.status(401).json({ success: false, message: "KEY inválida o desactivada." });
  const row = getKey.get(keyDigest(key));
  const now = nowIso();
  const valid = row && !row.revoked_at && (!row.expires_at || new Date(row.expires_at).getTime() > Date.now());
  logEvent.run(key.slice(-8), ipDigest(req.ip), valid ? 1 : 0, now);
  if (!valid) return res.status(401).json({ success: false, message: "KEY inválida, vencida o desactivada." });
  useKey.run(now, row.id);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ success: false, message: "No se pudo iniciar la sesión." });
    req.session.userAccess = true;
    req.session.save(err2 => {
      if (err2) return res.status(500).json({ success: false, message: "No se pudo guardar la sesión." });
      res.json({ success: true, redirect: "/acceso.html" });
    });
  });
});

app.get("/api/admin/session", (req, res) => {
  if (req.session.admin === true) {
    if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString("hex");
    return res.json({ authenticated: true, csrf: req.session.csrf, username: process.env.ADMIN_USERNAME });
  }
  res.json({ authenticated: false });
});
app.post("/api/admin/login", authLimiter, requireSameOrigin, (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  const userOk = safeEqual(username, process.env.ADMIN_USERNAME);
  const passOk = safeEqual(password, process.env.ADMIN_PASSWORD);
  if (!userOk || !passOk) return res.status(401).json({ success: false, message: "Usuario o contraseña incorrectos." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ success: false, message: "No se pudo iniciar sesión." });
    req.session.admin = true;
    req.session.csrf = crypto.randomBytes(24).toString("hex");
    req.session.save(err2 => {
      if (err2) return res.status(500).json({ success: false, message: "No se pudo guardar la sesión." });
      res.json({ success: true, csrf: req.session.csrf });
    });
  });
});
app.post("/api/admin/logout", adminLimiter, requireSameOrigin, requireAdmin, requireCsrf, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("rx7.sid", { httpOnly: true, secure: isProd, sameSite: "strict" });
    res.json({ success: true });
  });
});
app.get("/api/admin/keys", adminLimiter, requireAdmin, (req, res) => {
  res.json({ keys: listKeys.all() });
});
app.post("/api/admin/keys", adminLimiter, requireSameOrigin, requireAdmin, requireCsrf, (req, res) => {
  try {
    const key = makeAccessKey();
    const expiresAt = parseExpiry(req.body);
    const label = String(req.body.label || "").trim().slice(0, 80);
    insertKey.run(keyDigest(key), key.slice(-8), label, nowIso(), expiresAt);
    // La clave completa solo se muestra una vez. La base de datos guarda únicamente su HMAC.
    res.status(201).json({ success: true, key, expiresAt });
  } catch (e) {
    res.status(400).json({ success: false, message: e.message || "No se pudo crear la KEY." });
  }
});
app.post("/api/admin/keys/:id/revoke", adminLimiter, requireSameOrigin, requireAdmin, requireCsrf, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ success: false, message: "ID inválido." });
  const result = revokeKey.run(nowIso(), id);
  if (!result.changes) return res.status(404).json({ success: false, message: "KEY no encontrada o ya desactivada." });
  res.json({ success: true });
});

app.get("/acceso.html", (req, res) => {
  if (req.session.userAccess === true) return res.sendFile(path.join(__dirname, "public", "acceso.html"));
  res.redirect("/");
});
app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"], index: "index.html", maxAge: isProd ? "1h" : 0 }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ success: false, message: "Error interno del servidor." });
});
app.listen(PORT, () => console.log(`RX7 LOGIN activo en puerto ${PORT}`));
