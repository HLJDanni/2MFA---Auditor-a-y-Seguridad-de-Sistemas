'use strict';
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const db = require('../db');
const config = require('../config');
const cx = require('../security/crypto');
const notifier = require('./notifier');

// TOTP (RFC 6238): 6 dígitos, pasos de 30 s, tolerancia de ±1 paso por desfase de reloj.
authenticator.options = { digits: 6, step: 30, window: 1 };

const METHOD_INFO = {
  totp: { name: 'App de autenticación', short: 'App', hint: 'Google Authenticator, Microsoft Authenticator, Authy…' },
  email: { name: 'Correo electrónico', short: 'Correo', hint: 'Código de 6 dígitos a tu correo' },
  sms: { name: 'Mensaje de texto (SMS)', short: 'SMS', hint: 'Código de 6 dígitos a tu celular' },
};

function mask(type, dest) {
  if (!dest) return '';
  if (type === 'email') {
    const [u, d] = dest.split('@');
    return `${u.slice(0, 2)}${'•'.repeat(Math.max(2, u.length - 2))}@${d}`;
  }
  if (type === 'sms') return `${dest.slice(0, 4)} •••• ${dest.slice(-4)}`;
  return '';
}

/* ---------- Métodos registrados ---------- */

function listMethods(userId) {
  return db
    .all('SELECT id, type, destination, is_primary, created_at, last_used_at FROM mfa_methods WHERE user_id = ? ORDER BY is_primary DESC, created_at', [userId])
    .map((m) => ({ ...m, ...METHOD_INFO[m.type], masked: mask(m.type, m.destination) }));
}

function getMethod(userId, type) {
  return db.get('SELECT * FROM mfa_methods WHERE user_id = ? AND type = ?', [userId, type]);
}

function addMethod(userId, type, { destination = null, secret = null, step = null } = {}) {
  const existing = listMethods(userId);
  const isPrimary = existing.length === 0 ? 1 : 0;
  db.run('DELETE FROM mfa_methods WHERE user_id = ? AND type = ?', [userId, type]);
  db.run(
    `INSERT INTO mfa_methods (user_id, type, destination, secret_enc, last_used_step, is_primary, created_at)
     VALUES (?,?,?,?,?,?,?)`,
    [userId, type, destination, secret ? cx.encrypt(secret) : null, step, isPrimary, Date.now()]
  );
}

function removeMethod(userId, type) {
  const methods = listMethods(userId);
  if (methods.length <= 1) return { ok: false, error: 'Necesitas al menos un método de verificación activo.' };
  const target = methods.find((m) => m.type === type);
  if (!target) return { ok: false, error: 'Ese método no está registrado.' };
  db.run('DELETE FROM mfa_methods WHERE user_id = ? AND type = ?', [userId, type]);
  if (target.is_primary) {
    const next = methods.find((m) => m.type !== type);
    db.run('UPDATE mfa_methods SET is_primary = 1 WHERE user_id = ? AND type = ?', [userId, next.type]);
  }
  return { ok: true };
}

function setPrimary(userId, type) {
  if (!getMethod(userId, type)) return false;
  db.run('UPDATE mfa_methods SET is_primary = CASE WHEN type = ? THEN 1 ELSE 0 END WHERE user_id = ?', [type, userId]);
  return true;
}

function touchMethod(userId, type) {
  db.run('UPDATE mfa_methods SET last_used_at = ? WHERE user_id = ? AND type = ?', [Date.now(), userId, type]);
}

/* ---------- TOTP ---------- */

async function newTotpSecret(email, existing = null) {
  const secret = existing || authenticator.generateSecret(20); // 160 bits, recomendado por RFC 4226
  const otpauth = authenticator.keyuri(email, config.appName, secret);
  const qr = await QRCode.toDataURL(otpauth, { margin: 1, width: 220, color: { dark: '#0E3B36', light: '#FFFFFF' } });
  return { secret, otpauth, qr, grouped: secret.match(/.{1,4}/g).join(' ') };
}

/** Devuelve el número de paso que coincidió, o null. No valida reutilización. */
function matchTotp(secret, token) {
  const clean = String(token || '').replace(/\D/g, '');
  if (clean.length !== 6) return null;
  const delta = authenticator.checkDelta(clean, secret);
  if (delta === null || delta === undefined) return null;
  return Math.floor(Date.now() / 1000 / 30) + delta;
}

/** Verifica TOTP de un método guardado e impide reutilizar un código ya aceptado. */
function verifyTotp(userId, token) {
  const m = getMethod(userId, 'totp');
  if (!m) return { ok: false };
  const step = matchTotp(cx.decrypt(m.secret_enc), token);
  if (step === null) return { ok: false };
  if (m.last_used_step !== null && step <= m.last_used_step) return { ok: false, replay: true };
  db.run('UPDATE mfa_methods SET last_used_step = ? WHERE id = ?', [step, m.id]);
  return { ok: true };
}

/* ---------- Códigos por correo / SMS ---------- */

function lastOtp(userId, purpose) {
  return db.get('SELECT * FROM otp_codes WHERE user_id = ? AND purpose = ? ORDER BY id DESC LIMIT 1', [userId, purpose]);
}

/** Segundos que faltan para poder pedir otro código. */
function resendWait(userId, purpose) {
  const last = lastOtp(userId, purpose);
  if (!last) return 0;
  const elapsed = (Date.now() - last.created_at) / 1000;
  return Math.max(0, Math.ceil(config.security.otpResendSeconds - elapsed));
}

async function issueOtp(userId, purpose, channel, destination, { force = false } = {}) {
  const wait = resendWait(userId, purpose);
  if (wait > 0 && !force) return { ok: false, wait };
  db.run('UPDATE otp_codes SET consumed = 1 WHERE user_id = ? AND purpose = ? AND consumed = 0', [userId, purpose]);
  const code = cx.numericCode(6);
  const ttl = config.security.otpTtlSeconds;
  db.run(
    `INSERT INTO otp_codes (user_id, purpose, channel, destination, code_hash, expires_at, created_at)
     VALUES (?,?,?,?,?,?,?)`,
    [userId, purpose, channel, destination, cx.hmac(`${userId}:${purpose}:${code}`), Date.now() + ttl * 1000, Date.now()]
  );
  const minutes = Math.round(ttl / 60);
  if (channel === 'email') {
    const enrolling = purpose.startsWith('enroll');
    await notifier.sendEmail(
      destination,
      enrolling ? 'Confirma tu correo como método de verificación' : 'Tu código para iniciar sesión',
      [
        enrolling
          ? 'Escribe este código para activar tu correo como segundo factor.'
          : 'Alguien (esperamos que tú) escribió tu contraseña correctamente. Para terminar de entrar, usa este código.',
        `Vence en ${minutes} minutos y solo funciona una vez.`,
      ],
      code
    );
  } else {
    await notifier.sendSms(destination, `${config.appName}: tu código es ${code}. Vence en ${minutes} min. No lo compartas con nadie.`);
  }
  return { ok: true, expiresIn: ttl };
}

/**
 * Verifica un código enviado. Cada código admite como máximo 5 intentos y vence a los 5 minutos.
 * Resultado: { ok } | { ok:false, reason: 'expired'|'invalid'|'exhausted'|'none' }
 */
function verifyOtp(userId, purpose, code) {
  const row = db.get('SELECT * FROM otp_codes WHERE user_id = ? AND purpose = ? AND consumed = 0 ORDER BY id DESC LIMIT 1', [userId, purpose]);
  if (!row) return { ok: false, reason: 'none' };
  if (Date.now() > row.expires_at) {
    db.run('UPDATE otp_codes SET consumed = 1 WHERE id = ?', [row.id]);
    return { ok: false, reason: 'expired' };
  }
  const attempts = row.attempts + 1;
  const clean = String(code || '').replace(/\D/g, '');
  const match = cx.safeEqual(cx.hmac(`${userId}:${purpose}:${clean}`), row.code_hash);
  if (match) {
    db.run('UPDATE otp_codes SET consumed = 1, attempts = ? WHERE id = ?', [attempts, row.id]);
    return { ok: true, destination: row.destination };
  }
  const exhausted = attempts >= config.security.maxMfaAttemptsPerSession;
  db.run('UPDATE otp_codes SET attempts = ?, consumed = ? WHERE id = ?', [attempts, exhausted ? 1 : 0, row.id]);
  return { ok: false, reason: exhausted ? 'exhausted' : 'invalid', left: config.security.maxMfaAttemptsPerSession - attempts };
}

function otpExpiresAt(userId, purpose) {
  const row = db.get('SELECT expires_at FROM otp_codes WHERE user_id = ? AND purpose = ? AND consumed = 0 ORDER BY id DESC LIMIT 1', [userId, purpose]);
  return row ? row.expires_at : null;
}

/* ---------- Códigos de respaldo ---------- */

function generateRecoveryCodes(userId, count = 10) {
  db.run('DELETE FROM recovery_codes WHERE user_id = ?', [userId]);
  const codes = [];
  for (let i = 0; i < count; i++) {
    const c = cx.recoveryCode();
    codes.push(c);
    db.run('INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?,?,?)', [userId, cx.hmac(`rc:${userId}:${c}`), Date.now()]);
  }
  return codes;
}

function useRecoveryCode(userId, input) {
  const raw = String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (raw.length !== 8) return false;
  const code = raw.slice(0, 4) + '-' + raw.slice(4);
  const row = db.get('SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL', [userId, cx.hmac(`rc:${userId}:${code}`)]);
  if (!row) return false;
  db.run('UPDATE recovery_codes SET used_at = ? WHERE id = ?', [Date.now(), row.id]);
  return true;
}

function recoveryRemaining(userId) {
  return db.get('SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL', [userId]).n;
}

/* ---------- Dispositivos de confianza ---------- */

function deviceLabel(ua = '') {
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Navegador';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'otro sistema';
  return `${browser} en ${os}`;
}

function trustDevice(userId, ua, ip) {
  const token = cx.randomToken(32);
  const days = config.security.trustedDeviceDays;
  db.run(
    'INSERT INTO trusted_devices (user_id, token_hash, label, ip, created_at, expires_at, last_used_at) VALUES (?,?,?,?,?,?,?)',
    [userId, cx.hmac(`td:${token}`), deviceLabel(ua), ip, Date.now(), Date.now() + days * 864e5, Date.now()]
  );
  return { token, maxAge: days * 864e5 };
}

function checkTrustedDevice(userId, token) {
  if (!token) return false;
  const row = db.get('SELECT id FROM trusted_devices WHERE user_id = ? AND token_hash = ? AND expires_at > ?', [userId, cx.hmac(`td:${token}`), Date.now()]);
  if (!row) return false;
  db.run('UPDATE trusted_devices SET last_used_at = ? WHERE id = ?', [Date.now(), row.id]);
  return true;
}

function listDevices(userId) {
  return db.all('SELECT id, label, ip, created_at, expires_at, last_used_at FROM trusted_devices WHERE user_id = ? AND expires_at > ? ORDER BY last_used_at DESC', [userId, Date.now()]);
}

function revokeDevice(userId, id) {
  return db.run('DELETE FROM trusted_devices WHERE user_id = ? AND id = ?', [userId, id]).changes > 0;
}

function revokeAllDevices(userId) {
  db.run('DELETE FROM trusted_devices WHERE user_id = ?', [userId]);
}

module.exports = {
  METHOD_INFO,
  mask,
  listMethods,
  getMethod,
  addMethod,
  removeMethod,
  setPrimary,
  touchMethod,
  newTotpSecret,
  matchTotp,
  verifyTotp,
  issueOtp,
  verifyOtp,
  resendWait,
  otpExpiresAt,
  generateRecoveryCodes,
  useRecoveryCode,
  recoveryRemaining,
  trustDevice,
  checkTrustedDevice,
  listDevices,
  revokeDevice,
  revokeAllDevices,
  deviceLabel,
};
