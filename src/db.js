'use strict';
/**
 * Capa de datos sobre SQLite (sql.js, compilado a WebAssembly).
 * No requiere instalar un motor de base de datos ni compiladores nativos:
 * el archivo data/ceiba.db se crea solo y se guarda en disco tras cada escritura.
 * Todas las consultas usan parámetros enlazados (?), lo que evita la inyección SQL.
 */
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');
const config = require('./config');

let db = null;

const SCHEMA = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  name                TEXT    NOT NULL,
  email               TEXT    NOT NULL UNIQUE,
  phone               TEXT,
  password_hash       TEXT    NOT NULL,
  role                TEXT    NOT NULL DEFAULT 'usuario',
  failed_attempts     INTEGER NOT NULL DEFAULT 0,
  locked_until        INTEGER,
  lock_count          INTEGER NOT NULL DEFAULT 0,
  mfa_failures        INTEGER NOT NULL DEFAULT 0,
  last_login_at       INTEGER,
  last_login_ip       TEXT,
  password_changed_at INTEGER,
  created_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mfa_methods (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type           TEXT    NOT NULL CHECK (type IN ('totp','email','sms')),
  destination    TEXT,
  secret_enc     TEXT,
  last_used_step INTEGER,
  is_primary     INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER,
  UNIQUE (user_id, type)
);

CREATE TABLE IF NOT EXISTS otp_codes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     TEXT    NOT NULL,
  channel     TEXT    NOT NULL,
  destination TEXT,
  code_hash   TEXT    NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  consumed    INTEGER NOT NULL DEFAULT 0,
  expires_at  INTEGER NOT NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT    NOT NULL,
  used_at    INTEGER,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_devices (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   TEXT    NOT NULL UNIQUE,
  label        TEXT,
  ip           TEXT,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER,
  email      TEXT,
  event      TEXT NOT NULL,
  severity   TEXT NOT NULL DEFAULT 'info',
  detail     TEXT,
  ip         TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  channel     TEXT NOT NULL,
  destination TEXT NOT NULL,
  subject     TEXT,
  body        TEXT NOT NULL,
  delivered   TEXT NOT NULL DEFAULT 'simulado',
  created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_otp_user    ON otp_codes(user_id, purpose, consumed);
CREATE INDEX IF NOT EXISTS idx_audit_user  ON audit_log(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_time  ON audit_log(created_at);
`;

function persist() {
  const data = db.export();
  const tmp = config.dbPath + '.tmp';
  fs.writeFileSync(tmp, Buffer.from(data));
  fs.renameSync(tmp, config.dbPath);
}

async function init() {
  const SQL = await initSqlJs();
  fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
  if (fs.existsSync(config.dbPath)) {
    db = new SQL.Database(fs.readFileSync(config.dbPath));
  } else {
    db = new SQL.Database();
  }
  db.exec(SCHEMA);
  persist();
  return db;
}

function normalize(params) {
  return (params || []).map((p) => (p === undefined ? null : typeof p === 'boolean' ? (p ? 1 : 0) : p));
}

/** Ejecuta INSERT/UPDATE/DELETE. Devuelve { changes, lastId }. */
function run(sql, params = []) {
  const stmt = db.prepare(sql);
  try {
    stmt.run(normalize(params));
  } finally {
    stmt.free();
  }
  const changes = db.getRowsModified();
  const lastId = db.exec('SELECT last_insert_rowid() AS id')[0].values[0][0];
  persist();
  return { changes, lastId };
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  const rows = [];
  try {
    stmt.bind(normalize(params));
    while (stmt.step()) rows.push(stmt.getAsObject());
  } finally {
    stmt.free();
  }
  return rows;
}

function get(sql, params = []) {
  return all(sql, params)[0] || null;
}

module.exports = { init, run, all, get };
