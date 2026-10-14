'use strict';
const crypto = require('crypto');
const config = require('../config');
const audit = require('../services/audit');
const users = require('../services/users');
const cx = require('../security/crypto');

/** Token CSRF por sesión (patrón synchronizer token). Se exige en todo POST. */
function csrf(req, res, next) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(24).toString('base64url');
  res.locals.csrf = req.session.csrf;
  if (req.method === 'POST') {
    const sent = (req.body && req.body._csrf) || req.get('x-csrf-token') || '';
    if (!cx.safeEqual(sent, req.session.csrf)) {
      audit.log(req, { userId: req.session.userId || null, event: 'csrf_blocked', severity: 'alerta', detail: req.originalUrl });
      return res.status(403).render('error', {
        title: 'Solicitud rechazada',
        message: 'El formulario venció o no proviene de este sitio. Vuelve a abrir la página e inténtalo de nuevo.',
        code: 403,
      });
    }
  }
  next();
}

/** Mensajes de una sola vez entre redirecciones. */
function flash(req, res, next) {
  req.flash = (type, text) => {
    req.session.flash = req.session.flash || [];
    req.session.flash.push({ type, text });
  };
  res.locals.flash = req.session.flash || [];
  delete req.session.flash;
  next();
}

/** Expira la sesión tras inactividad y carga el usuario autenticado. */
function loadUser(req, res, next) {
  res.locals.user = null;
  res.locals.appName = config.appName;
  res.locals.demoMode = config.demoMode;
  res.locals.path = req.path;
  if (req.session.userId) {
    const idleMs = config.security.sessionIdleMinutes * 60000;
    if (req.session.lastSeen && Date.now() - req.session.lastSeen > idleMs) {
      const userId = req.session.userId;
      audit.log(req, { userId, event: 'session_expired' });
      return req.session.regenerate(() => {
        req.session.flash = [{ type: 'info', text: 'Cerramos tu sesión por inactividad. Vuelve a entrar para continuar.' }];
        res.redirect('/login');
      });
    }
    const user = users.findById(req.session.userId);
    if (!user) {
      delete req.session.userId;
    } else {
      req.user = user;
      res.locals.user = user;
      req.session.lastSeen = Date.now();
    }
  }
  if (req.session.pending && Date.now() - req.session.pending.startedAt > config.security.mfaPendingMinutes * 60000) {
    delete req.session.pending;
  }
  next();
}

function requireAuth(req, res, next) {
  if (req.user) return next();
  if (req.session.pending) return res.redirect('/verificar');
  req.flash('info', 'Inicia sesión para continuar.');
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  res.status(403).render('error', { title: 'Sin permiso', message: 'Esta sección es solo para administradores.', code: 403 });
}

function guestOnly(req, res, next) {
  if (req.user) return res.redirect('/panel');
  next();
}

function noStore(req, res, next) {
  res.set('Cache-Control', 'no-store');
  next();
}

module.exports = { csrf, flash, loadUser, requireAuth, requireAdmin, guestOnly, noStore };
