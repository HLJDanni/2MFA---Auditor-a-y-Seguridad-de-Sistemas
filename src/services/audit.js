'use strict';
const db = require('../db');

// Catálogo de eventos de seguridad con su descripción legible.
const EVENTS = {
  register: 'Cuenta creada',
  login_password_ok: 'Contraseña correcta, falta el segundo factor',
  login_password_fail: 'Contraseña incorrecta',
  login_unknown_user: 'Intento con un correo no registrado',
  login_blocked_locked: 'Intento sobre una cuenta bloqueada',
  account_locked: 'Cuenta bloqueada temporalmente',
  mfa_success: 'Segundo factor verificado, sesión iniciada',
  mfa_fail: 'Código de verificación incorrecto',
  mfa_session_killed: 'Demasiados códigos incorrectos, se exigió la contraseña otra vez',
  mfa_code_sent: 'Código de verificación enviado',
  mfa_trusted_device: 'Acceso desde un dispositivo de confianza',
  totp_replay: 'Se intentó reutilizar un código de la app',
  recovery_used: 'Código de respaldo utilizado',
  method_added: 'Método de verificación agregado',
  method_removed: 'Método de verificación eliminado',
  method_primary: 'Método principal cambiado',
  recovery_regenerated: 'Códigos de respaldo regenerados',
  password_changed: 'Contraseña cambiada',
  device_revoked: 'Dispositivo de confianza eliminado',
  logout: 'Sesión cerrada',
  session_expired: 'Sesión expirada por inactividad',
  csrf_blocked: 'Petición bloqueada por token CSRF inválido',
  rate_limited: 'Demasiadas solicitudes desde la misma IP',
  account_unlocked: 'Cuenta desbloqueada por un administrador',
};

function clientIp(req) {
  return (req && (req.ip || req.socket?.remoteAddress)) || '';
}

function log(req, { userId = null, email = null, event, severity = 'info', detail = null }) {
  try {
    db.run(
      `INSERT INTO audit_log (user_id, email, event, severity, detail, ip, user_agent, created_at)
       VALUES (?,?,?,?,?,?,?,?)`,
      [userId, email, event, severity, detail, clientIp(req), (req && req.get && req.get('user-agent')) || '', Date.now()]
    );
  } catch (err) {
    console.error('[auditoría] no se pudo registrar el evento', event, err.message);
  }
}

function label(event) {
  return EVENTS[event] || event;
}

function forUser(userId, limit = 15) {
  return db.all('SELECT * FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT ?', [userId, limit]);
}

function recent(limit = 60) {
  return db.all('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?', [limit]);
}

module.exports = { log, label, forUser, recent, clientIp, EVENTS };
