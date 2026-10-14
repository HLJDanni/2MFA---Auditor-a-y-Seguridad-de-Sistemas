'use strict';
const express = require('express');
const users = require('../services/users');
const mfa = require('../services/mfa');
const audit = require('../services/audit');
const notifier = require('../services/notifier');
const password = require('../security/password');
const limits = require('../middleware/limits');
const { requireAuth } = require('../middleware/security');

const router = express.Router();

/** Reautenticación: las acciones que debilitan la seguridad piden la contraseña otra vez. */
async function confirmPassword(req) {
  return password.verify(req.body.current_password, req.user.password_hash);
}

router.get('/panel', requireAuth, (req, res) => {
  const methods = mfa.listMethods(req.user.id);
  const recoveryLeft = mfa.recoveryRemaining(req.user.id);
  const sec = users.securityScore(req.user, methods, recoveryLeft);
  res.render('dashboard', {
    title: 'Tu cuenta',
    methods,
    recoveryLeft,
    sec,
    devices: mfa.listDevices(req.user.id),
    activity: audit.forUser(req.user.id, 8),
    label: audit.label,
    authVia: req.session.authVia,
    authAt: req.session.authAt,
  });
});

router.get('/cuenta/metodos', requireAuth, (req, res) => {
  const methods = mfa.listMethods(req.user.id);
  const missing = Object.keys(mfa.METHOD_INFO).filter((t) => !methods.some((m) => m.type === t));
  res.render('methods', { title: 'Métodos de verificación', methods, missing, info: mfa.METHOD_INFO, recoveryLeft: mfa.recoveryRemaining(req.user.id) });
});

router.post('/cuenta/metodos/:type/principal', requireAuth, (req, res) => {
  if (mfa.setPrimary(req.user.id, req.params.type)) {
    audit.log(req, { userId: req.user.id, event: 'method_primary', detail: req.params.type });
    req.flash('ok', `${mfa.METHOD_INFO[req.params.type].name} es ahora tu método principal.`);
  }
  res.redirect('/cuenta/metodos');
});

router.post('/cuenta/metodos/:type/eliminar', requireAuth, limits.sensitive, async (req, res, next) => {
  try {
    const type = req.params.type;
    if (!mfa.METHOD_INFO[type]) return res.redirect('/cuenta/metodos');
    if (!(await confirmPassword(req))) {
      req.flash('error', 'La contraseña no es correcta. No eliminamos el método.');
      return res.redirect('/cuenta/metodos');
    }
    const r = mfa.removeMethod(req.user.id, type);
    if (!r.ok) {
      req.flash('error', r.error);
    } else {
      audit.log(req, { userId: req.user.id, email: req.user.email, event: 'method_removed', severity: 'aviso', detail: type });
      notifier.sendEmail(req.user.email, 'Eliminaste un método de verificación', [
        `Quitamos "${mfa.METHOD_INFO[type].name}" de tu cuenta.`,
        'Si no fuiste tú, cambia tu contraseña de inmediato.',
      ]);
      req.flash('ok', `Eliminamos ${mfa.METHOD_INFO[type].name.toLowerCase()} de tus métodos.`);
    }
    res.redirect('/cuenta/metodos');
  } catch (e) {
    next(e);
  }
});

/* ---------- Códigos de respaldo ---------- */

router.get('/cuenta/respaldo', requireAuth, (req, res) => {
  res.render('recovery', { title: 'Códigos de respaldo', remaining: mfa.recoveryRemaining(req.user.id) });
});

router.post('/cuenta/respaldo', requireAuth, limits.sensitive, async (req, res, next) => {
  try {
    if (!(await confirmPassword(req))) {
      req.flash('error', 'La contraseña no es correcta. Tus códigos actuales siguen vigentes.');
      return res.redirect('/cuenta/respaldo');
    }
    req.session.newCodes = mfa.generateRecoveryCodes(req.user.id);
    audit.log(req, { userId: req.user.id, email: req.user.email, event: 'recovery_regenerated', severity: 'aviso' });
    res.redirect('/cuenta/respaldo/nuevos');
  } catch (e) {
    next(e);
  }
});

router.get('/cuenta/respaldo/nuevos', requireAuth, (req, res) => {
  const codes = req.session.newCodes;
  const firstSetup = !!req.session.firstSetup;
  if (!codes) return res.redirect('/cuenta/respaldo');
  delete req.session.newCodes; // se muestran una sola vez
  delete req.session.firstSetup;
  res.render('recovery-new', { title: 'Guarda tus códigos de respaldo', codes, firstSetup });
});

/* ---------- Contraseña ---------- */

router.get('/cuenta/contrasena', requireAuth, (req, res) => {
  res.render('password', { title: 'Cambiar contraseña', errors: [] });
});

router.post('/cuenta/contrasena', requireAuth, limits.sensitive, async (req, res, next) => {
  try {
    const errors = [];
    const next1 = String(req.body.password || '');
    if (!(await confirmPassword(req))) errors.push('Tu contraseña actual no es correcta.');
    if (next1 !== String(req.body.password2 || '')) errors.push('Las contraseñas nuevas no coinciden.');
    if (await password.verify(next1, req.user.password_hash)) errors.push('La nueva contraseña debe ser distinta de la actual.');
    errors.push(...password.evaluate(next1, req.user).errors);
    if (!errors.length) {
      const pwned = await password.timesPwned(next1);
      if (pwned > 0) errors.push(`Esa contraseña apareció ${pwned.toLocaleString('es-GT')} veces en filtraciones públicas. Elige otra.`);
    }
    if (errors.length) return res.status(400).render('password', { title: 'Cambiar contraseña', errors });

    await users.changePassword(req.user.id, next1);
    mfa.revokeAllDevices(req.user.id); // se exige el segundo factor en todos lados otra vez
    audit.log(req, { userId: req.user.id, email: req.user.email, event: 'password_changed', severity: 'aviso' });
    notifier.sendEmail(req.user.email, 'Tu contraseña cambió', [
      'La contraseña de tu cuenta se cambió correctamente.',
      'También olvidamos todos los dispositivos de confianza: la próxima vez te pediremos el segundo factor.',
      'Si no hiciste este cambio, contacta al administrador de inmediato.',
    ]);
    req.flash('ok', 'Contraseña actualizada. Cerramos el acceso recordado en tus otros dispositivos.');
    res.redirect('/panel');
  } catch (e) {
    next(e);
  }
});

/* ---------- Dispositivos y actividad ---------- */

router.post('/cuenta/dispositivos/:id/eliminar', requireAuth, (req, res) => {
  if (mfa.revokeDevice(req.user.id, parseInt(req.params.id, 10))) {
    audit.log(req, { userId: req.user.id, event: 'device_revoked' });
    req.flash('ok', 'Ese dispositivo volverá a pedir el segundo factor.');
  }
  res.redirect('/panel#dispositivos');
});

router.get('/cuenta/actividad', requireAuth, (req, res) => {
  res.render('activity', { title: 'Actividad de seguridad', activity: audit.forUser(req.user.id, 100), label: audit.label });
});

module.exports = router;
