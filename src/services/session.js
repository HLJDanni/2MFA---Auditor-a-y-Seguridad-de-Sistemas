'use strict';
const crypto = require('crypto');
const config = require('../config');
const users = require('./users');
const audit = require('./audit');
const notifier = require('./notifier');
const mfa = require('./mfa');

const TRUST_COOKIE = 'ceiba.td';

/**
 * Regenera el identificador de sesión antes de elevar privilegios (evita fijación de sesión)
 * y marca al usuario como autenticado por completo.
 */
function completeLogin(req, user, { via, keep = {} } = {}) {
  return new Promise((resolve, reject) => {
    const previousIp = user.last_login_ip;
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = user.id;
      req.session.authAt = Date.now();
      req.session.lastSeen = Date.now();
      req.session.authVia = via;
      req.session.csrf = crypto.randomBytes(24).toString('base64url');
      Object.assign(req.session, keep);
      const ip = audit.clientIp(req);
      users.recordSuccessfulLogin(user.id, ip);
      audit.log(req, { userId: user.id, email: user.email, event: via === 'dispositivo' ? 'mfa_trusted_device' : 'mfa_success', detail: `método: ${via}` });
      if (previousIp && previousIp !== ip) {
        notifier.sendEmail(user.email, 'Nuevo inicio de sesión en tu cuenta', [
          `Se inició sesión desde ${mfa.deviceLabel(req.get('user-agent'))} (IP ${ip}).`,
          `Fecha: ${new Date().toLocaleString('es-GT', { timeZone: 'America/Guatemala' })}.`,
          'Si fuiste tú, no necesitas hacer nada.',
        ]);
      }
      req.session.save((e) => (e ? reject(e) : resolve()));
    });
  });
}

function setTrustCookie(res, token, maxAge) {
  res.cookie(TRUST_COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: config.secureCookies, maxAge, path: '/' });
}

function readCookie(req, name) {
  const header = req.get('cookie') || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

module.exports = { completeLogin, setTrustCookie, readCookie, TRUST_COOKIE };
