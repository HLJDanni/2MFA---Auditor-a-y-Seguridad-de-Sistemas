'use strict';
/**
 * Alta de métodos de verificación. Se usa en dos momentos:
 *  1) Justo después de registrarse (modo "configuración": aún no hay sesión completa).
 *  2) Desde la cuenta, para agregar o reemplazar métodos.
 */
const express = require('express');
const users = require('../services/users');
const mfa = require('../services/mfa');
const audit = require('../services/audit');
const notifier = require('../services/notifier');
const limits = require('../middleware/limits');
const { completeLogin } = require('../services/session');

const router = express.Router();
const SETUP_MAX_MS = 30 * 60000;
const PHONE_RE = /^\+[1-9]\d{7,14}$/;

function enrollContext(req, res, next) {
  if (req.user) {
    req.enrollUser = req.user;
    res.locals.setupMode = false;
    return next();
  }
  const s = req.session.setup;
  if (s && Date.now() - s.startedAt < SETUP_MAX_MS) {
    const u = users.findById(s.userId);
    if (u) {
      req.enrollUser = u;
      res.locals.setupMode = true;
      res.locals.step = 1.5;
      return next();
    }
  }
  delete req.session.setup;
  req.flash('info', 'Inicia sesión para configurar tus métodos de verificación.');
  res.redirect('/login');
}

async function finish(req, res, type, label) {
  const user = req.enrollUser;
  delete req.session.enroll;
  audit.log(req, { userId: user.id, email: user.email, event: 'method_added', detail: type });
  if (res.locals.setupMode) {
    const codes = mfa.generateRecoveryCodes(user.id);
    await completeLogin(req, user, { via: `alta-${type}`, keep: { newCodes: codes, firstSetup: true } });
    return res.redirect('/cuenta/respaldo/nuevos');
  }
  notifier.sendEmail(user.email, 'Agregaste un método de verificación', [
    `Ahora puedes confirmar tu identidad con: ${label}.`,
    'Si no hiciste este cambio, cambia tu contraseña de inmediato.',
  ]);
  req.flash('ok', `${label} quedó activo como método de verificación.`);
  res.redirect('/cuenta/metodos');
}

router.get('/configurar', enrollContext, (req, res) => {
  if (!res.locals.setupMode) return res.redirect('/cuenta/metodos');
  res.render('setup', { title: 'Configura tu verificación', user: null, firstName: req.enrollUser.name.split(' ')[0] });
});

/* ---------- App de autenticación (TOTP) ---------- */

router.get('/cuenta/metodos/totp', enrollContext, async (req, res, next) => {
  try {
    // El secreto vive solo en la sesión hasta que el usuario demuestra que lo escaneó bien.
    req.session.enroll = req.session.enroll || {};
    if (!req.session.enroll.totp) {
      const t = await mfa.newTotpSecret(req.enrollUser.email);
      req.session.enroll.totp = { secret: t.secret, createdAt: Date.now() };
    }
    const t = await mfa.newTotpSecret(req.enrollUser.email, req.session.enroll.totp.secret);
    res.render('enroll-totp', {
      title: 'App de autenticación',
      qr: t.qr,
      grouped: t.grouped,
      replacing: !!mfa.getMethod(req.enrollUser.id, 'totp'),
      error: null,
    });
  } catch (e) {
    next(e);
  }
});

router.post('/cuenta/metodos/totp', enrollContext, limits.sensitive, async (req, res, next) => {
  try {
    const pending = req.session.enroll && req.session.enroll.totp;
    if (!pending) return res.redirect('/cuenta/metodos/totp');
    const step = mfa.matchTotp(pending.secret, req.body.code);
    if (step === null) {
      req.flash('error', 'El código no coincide. Revisa que la hora de tu teléfono sea automática y escribe el código que se ve ahora.');
      return res.redirect('/cuenta/metodos/totp');
    }
    mfa.addMethod(req.enrollUser.id, 'totp', { secret: pending.secret, step });
    await finish(req, res, 'totp', 'App de autenticación');
  } catch (e) {
    next(e);
  }
});

/* ---------- Correo y SMS (código de confirmación) ---------- */

function channelRoutes(type, slug, label) {
  const purpose = `enroll_${type}`;

  router.get(`/cuenta/metodos/${slug}`, enrollContext, (req, res) => {
    const enroll = (req.session.enroll && req.session.enroll[type]) || null;
    res.render('enroll-channel', {
      title: label,
      type,
      slug,
      label,
      sent: !!enroll,
      destination: enroll ? enroll.destination : type === 'email' ? req.enrollUser.email : req.enrollUser.phone || '+502',
      masked: enroll ? mfa.mask(type, enroll.destination) : '',
      expiresAt: enroll ? mfa.otpExpiresAt(req.enrollUser.id, purpose) : null,
      resendWait: enroll ? mfa.resendWait(req.enrollUser.id, purpose) : 0,
      replacing: !!mfa.getMethod(req.enrollUser.id, type),
      error: null,
    });
  });

  router.post(`/cuenta/metodos/${slug}/enviar`, enrollContext, limits.sensitive, async (req, res, next) => {
    try {
      let destination = String(req.body.destination || '').trim();
      if (type === 'sms') {
        destination = destination.replace(/[\s()-]/g, '');
        if (/^\d{8}$/.test(destination)) destination = '+502' + destination; // número local de Guatemala
        if (!PHONE_RE.test(destination)) {
          req.flash('error', 'Escribe el número con código de país, por ejemplo +502 5555 1234.');
          return res.redirect(`/cuenta/metodos/${slug}`);
        }
      } else {
        destination = users.normEmail(destination);
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(destination)) {
          req.flash('error', 'Escribe un correo válido.');
          return res.redirect(`/cuenta/metodos/${slug}`);
        }
      }
      const r = await mfa.issueOtp(req.enrollUser.id, purpose, type, destination, { force: !!req.body.changed });
      if (!r.ok) {
        req.flash('info', `Espera ${r.wait} segundos para pedir otro código.`);
      } else {
        req.session.enroll = req.session.enroll || {};
        req.session.enroll[type] = { destination };
        req.flash('ok', `Enviamos un código a ${mfa.mask(type, destination)}.`);
      }
      res.redirect(`/cuenta/metodos/${slug}`);
    } catch (e) {
      next(e);
    }
  });

  router.post(`/cuenta/metodos/${slug}/verificar`, enrollContext, limits.sensitive, async (req, res, next) => {
    try {
      const enroll = req.session.enroll && req.session.enroll[type];
      if (!enroll) return res.redirect(`/cuenta/metodos/${slug}`);
      const r = mfa.verifyOtp(req.enrollUser.id, purpose, req.body.code);
      if (!r.ok) {
        const msg =
          r.reason === 'expired' || r.reason === 'exhausted' || r.reason === 'none'
            ? 'Ese código ya no es válido. Pide uno nuevo.'
            : `El código no es correcto. Te quedan ${r.left} intentos.`;
        if (r.reason !== 'invalid') delete req.session.enroll[type];
        req.flash('error', msg);
        return res.redirect(`/cuenta/metodos/${slug}`);
      }
      if (r.destination !== enroll.destination) return res.redirect(`/cuenta/metodos/${slug}`);
      mfa.addMethod(req.enrollUser.id, type, { destination: enroll.destination });
      if (type === 'sms') require('../db').run('UPDATE users SET phone = ? WHERE id = ?', [enroll.destination, req.enrollUser.id]);
      await finish(req, res, type, label);
    } catch (e) {
      next(e);
    }
  });

  router.post(`/cuenta/metodos/${slug}/cambiar`, enrollContext, (req, res) => {
    if (req.session.enroll) delete req.session.enroll[type];
    res.redirect(`/cuenta/metodos/${slug}`);
  });
}

channelRoutes('email', 'correo', 'Correo electrónico');
channelRoutes('sms', 'sms', 'Mensaje de texto (SMS)');

module.exports = router;
