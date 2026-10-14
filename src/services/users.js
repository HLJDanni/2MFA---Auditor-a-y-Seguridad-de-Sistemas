'use strict';
const db = require('../db');
const config = require('../config');
const password = require('../security/password');

const normEmail = (e) => String(e || '').trim().toLowerCase();

function findByEmail(email) {
  return db.get('SELECT * FROM users WHERE email = ?', [normEmail(email)]);
}

function findById(id) {
  return db.get('SELECT * FROM users WHERE id = ?', [id]);
}

async function create({ name, email, phone, plainPassword, role = 'usuario' }) {
  const hash = await password.hash(plainPassword);
  const now = Date.now();
  const { lastId } = db.run(
    'INSERT INTO users (name, email, phone, password_hash, role, password_changed_at, created_at) VALUES (?,?,?,?,?,?,?)',
    [String(name).trim(), normEmail(email), phone || null, hash, role, now, now]
  );
  return findById(lastId);
}

function lockRemainingMs(user) {
  return user && user.locked_until && user.locked_until > Date.now() ? user.locked_until - Date.now() : 0;
}

/**
 * Bloqueo progresivo: 15 min el primero, 30 el segundo, 60 el tercero… hasta 24 h.
 * Frena la fuerza bruta sin dejar la cuenta inutilizable para siempre.
 */
function lock(user) {
  const minutes = Math.min(config.security.lockMinutes * 2 ** (user.lock_count || 0), 24 * 60);
  db.run('UPDATE users SET locked_until = ?, lock_count = lock_count + 1, failed_attempts = 0 WHERE id = ?', [
    Date.now() + minutes * 60000,
    user.id,
  ]);
  return minutes;
}

/** Registra contraseña incorrecta. Devuelve minutos de bloqueo si se alcanzó el límite. */
function registerPasswordFailure(user) {
  const attempts = (user.failed_attempts || 0) + 1;
  if (attempts >= config.security.maxPasswordAttempts) return { locked: lock(user), attempts };
  db.run('UPDATE users SET failed_attempts = ? WHERE id = ?', [attempts, user.id]);
  return { locked: 0, attempts };
}

function registerMfaFailure(user) {
  const fresh = findById(user.id);
  const failures = (fresh.mfa_failures || 0) + 1;
  if (failures >= config.security.maxMfaFailuresBeforeLock) {
    db.run('UPDATE users SET mfa_failures = 0 WHERE id = ?', [user.id]);
    return { locked: lock(fresh) };
  }
  db.run('UPDATE users SET mfa_failures = ? WHERE id = ?', [failures, user.id]);
  return { locked: 0 };
}

function clearPasswordFailures(userId) {
  db.run('UPDATE users SET failed_attempts = 0 WHERE id = ?', [userId]);
}

function recordSuccessfulLogin(userId, ip) {
  db.run('UPDATE users SET failed_attempts = 0, mfa_failures = 0, lock_count = 0, locked_until = NULL, last_login_at = ?, last_login_ip = ? WHERE id = ?', [
    Date.now(),
    ip,
    userId,
  ]);
}

function unlock(userId) {
  db.run('UPDATE users SET failed_attempts = 0, mfa_failures = 0, lock_count = 0, locked_until = NULL WHERE id = ?', [userId]);
}

async function changePassword(userId, plain) {
  const hash = await password.hash(plain);
  db.run('UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?', [hash, Date.now(), userId]);
}

/** Puntaje de seguridad de la cuenta (0-100) con recomendaciones concretas. */
function securityScore(user, methods, recoveryLeft) {
  const tips = [];
  let score = 30; // contraseña robusta obligatoria
  if (methods.length >= 1) score += 30;
  if (methods.some((m) => m.type === 'totp')) score += 20;
  else tips.push({ text: 'Agrega una app de autenticación: funciona sin señal y resiste el robo de SIM.', href: '/cuenta/metodos/totp' });
  if (methods.length >= 2) score += 10;
  else tips.push({ text: 'Registra un segundo método por si pierdes acceso al primero.', href: '/cuenta/metodos' });
  if (recoveryLeft >= 3) score += 10;
  else tips.push({ text: 'Te quedan pocos códigos de respaldo. Genera nuevos.', href: '/cuenta/respaldo' });
  const ageDays = (Date.now() - (user.password_changed_at || user.created_at)) / 864e5;
  if (ageDays > 180) {
    score -= 10;
    tips.push({ text: 'Tu contraseña tiene más de seis meses. Considera cambiarla.', href: '/cuenta/contrasena' });
  }
  return { score: Math.max(0, Math.min(100, score)), tips };
}

function stats() {
  const since = Date.now() - 864e5;
  const one = (sql, p = []) => db.get(sql, p).n;
  return {
    users: one('SELECT COUNT(*) AS n FROM users'),
    withTotp: one("SELECT COUNT(DISTINCT user_id) AS n FROM mfa_methods WHERE type = 'totp'"),
    locked: one('SELECT COUNT(*) AS n FROM users WHERE locked_until > ?', [Date.now()]),
    logins24: one("SELECT COUNT(*) AS n FROM audit_log WHERE event = 'mfa_success' AND created_at > ?", [since]),
    pwFails24: one("SELECT COUNT(*) AS n FROM audit_log WHERE event IN ('login_password_fail','login_unknown_user') AND created_at > ?", [since]),
    mfaFails24: one("SELECT COUNT(*) AS n FROM audit_log WHERE event IN ('mfa_fail','totp_replay') AND created_at > ?", [since]),
    blocked24: one("SELECT COUNT(*) AS n FROM audit_log WHERE event IN ('account_locked','mfa_session_killed','rate_limited','csrf_blocked','login_blocked_locked') AND created_at > ?", [since]),
    stolenStopped: one("SELECT COUNT(*) AS n FROM audit_log a WHERE event = 'login_password_ok' AND created_at > ? AND NOT EXISTS (SELECT 1 FROM audit_log b WHERE b.user_id = a.user_id AND b.event IN ('mfa_success','mfa_trusted_device') AND b.created_at BETWEEN a.created_at AND a.created_at + 900000)", [since]),
  };
}

function list() {
  return db.all(`SELECT u.id, u.name, u.email, u.role, u.locked_until, u.last_login_at, u.created_at,
    (SELECT GROUP_CONCAT(type, ',') FROM mfa_methods m WHERE m.user_id = u.id) AS methods
    FROM users u ORDER BY u.created_at DESC`);
}

module.exports = {
  normEmail,
  findByEmail,
  findById,
  create,
  lockRemainingMs,
  registerPasswordFailure,
  registerMfaFailure,
  clearPasswordFailures,
  recordSuccessfulLogin,
  unlock,
  changePassword,
  securityScore,
  stats,
  list,
};
