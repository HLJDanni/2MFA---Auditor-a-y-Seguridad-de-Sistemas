'use strict';
const express = require('express');
const config = require('../config');
const users = require('../services/users');
const mfa = require('../services/mfa');
const audit = require('../services/audit');
const notifier = require('../services/notifier');
const password = require('../security/password');
const limits = require('../middleware/limits');
const { guestOnly } = require('../middleware/security');
const { completeLogin, setTrustCookie, readCookie, TRUST_COOKIE } = require('../services/session');

const router = express.Router();

const GENERIC_FAIL = 'El correo o la contraseña no coinciden. Revisa ambos e inténtalo de nuevo.';
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;

// Contadores para correos inexistentes: así una cuenta real y una inventada se comportan igual
// (mismo mensaje, mismo bloqueo) y nadie puede averiguar qué correos están registrados.
const ghostAttempts = new Map();
function ghostFailure(email) {
  const now = Date.now();
  const g = ghostAttempts.get(email) || { n: 0, until: 0 };
  if (g.until > now) return { lockedMs: g.until - now };
  g.n += 1;
  if (g.n >= config.security.maxPasswordAttempts) {
    g.n = 0;
    g.until = now + config.security.lockMinutes * 60000;
    ghostAttempts.set(email, g);
    return { locked: config.security.lockMinutes };
  }
  ghostAttempts.set(email, g);
  return { attempts: g.n };
}

function lockMessage(minutes) {
  const m = Math.max(1, Math.ceil(minutes));
  return `Por seguridad pausamos los intentos de acceso a esta cuenta durante ${m} ${m === 1 ? 'minuto' : 'minutos'}. Si no fuiste tú, cambia tu contraseña cuando vuelvas a entrar.`;
}

function attemptsHint(attempts) {
  const left = config.security.maxPasswordAttempts - attempts;
  return left <= 2 ? ` Te quedan ${left} ${left === 1 ? 'intento' : 'intentos'} antes de una pausa de ${config.security.lockMinutes} minutos.` : '';
}

router.get('/', (req, res) => res.redirect(req.user ? '/panel' : '/login'));

/* ---------------- Inicio de sesión: paso 1 (contraseña) ---------------- */

router.get('/login', guestOnly, (req, res) => {
  res.render('login', { title: 'Iniciar sesión', email: '', error: null, step: 1 });
});

router.post('/login', guestOnly, limits.login, async (req, res, next) => {
  try {
    const email = users.normEmail(req.body.email);
    const plain = String(req.body.password || '');
    const render = (error, status = 401) => res.status(status).render('login', { title: 'Iniciar sesión', email, error, step: 1 });

    if (!EMAIL_RE.test(email) || !plain) return render('Escribe tu correo y tu contraseña.', 400);

    const user = users.findByEmail(email);
    const valid = await password.verify(plain, user && user.password_hash); // siempre se ejecuta bcrypt

    if (!user) {
      audit.log(req, { email, event: 'login_unknown_user', severity: 'aviso' });
      const g = ghostFailure(email);
      if (g.lockedMs) return render(lockMessage(g.lockedMs / 60000), 423);
      if (g.locked) return render(lockMessage(g.locked), 423);
      return render(GENERIC_FAIL + attemptsHint(g.attempts));
    }

    const lockedMs = users.lockRemainingMs(user);
    if (lockedMs) {
      audit.log(req, { userId: user.id, email, event: 'login_blocked_locked', severity: 'alerta' });
      return render(lockMessage(lockedMs / 60000), 423);
    }

    if (!valid) {
      const r = users.registerPasswordFailure(user);
      audit.log(req, { userId: user.id, email, event: 'login_password_fail', severity: 'aviso', detail: `intento ${r.attempts}` });
      if (r.locked) {
        audit.log(req, { userId: user.id, email, event: 'account_locked', severity: 'critico', detail: `${r.locked} min por contraseñas incorrectas` });
        notifier.sendEmail(user.email, 'Pausamos el acceso a tu cuenta', [
          `Detectamos ${config.security.maxPasswordAttempts} contraseñas incorrectas seguidas desde la IP ${audit.clientIp(req)}.`,
          `Bloqueamos los intentos durante ${r.locked} minutos para proteger tu cuenta.`,
          'Si no fuiste tú, alguien podría estar intentando adivinar tu contraseña. Tu segundo factor sigue protegiéndote.',
        ]);
        return render(lockMessage(r.locked), 423);
      }
      return render(GENERIC_FAIL + attemptsHint(r.attempts));
    }

    // Contraseña correcta
    users.clearPasswordFailures(user.id);
    const methods = mfa.listMethods(user.id);

    if (methods.length === 0) {
      // Cuenta sin segundo factor (registro sin terminar): se obliga a configurarlo antes de entrar.
      return req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.setup = { userId: user.id, startedAt: Date.now() };
        req.session.flash = [{ type: 'info', text: 'Antes de entrar, configura tu segundo factor de verificación.' }];
        res.redirect('/configurar');
      });
    }

    audit.log(req, { userId: user.id, email, event: 'login_password_ok' });

    // Dispositivo de confianza recordado (cookie aleatoria, guardada con hash, revocable)
    if (mfa.checkTrustedDevice(user.id, readCookie(req, TRUST_COOKIE))) {
      await completeLogin(req, user, { via: 'dispositivo' });
      req.session.flash = [{ type: 'ok', text: 'Entraste desde un dispositivo de confianza.' }];
      return res.redirect('/panel');
    }

    const primary = methods.find((m) => m.is_primary) || methods[0];
    req.session.regenerate(async (err) => {
      if (err) return next(err);
      req.session.pending = { userId: user.id, method: primary.type, startedAt: Date.now(), attempts: 0 };
      if (primary.type !== 'totp') {
        await mfa.issueOtp(user.id, `login_${primary.type}`, primary.type, primary.destination);
        audit.log(req, { userId: user.id, email, event: 'mfa_code_sent', detail: primary.type });
      }
      req.session.save(() => res.redirect('/verificar'));
    });
  } catch (e) {
    next(e);
  }
});

/* ---------------- Inicio de sesión: paso 2 (segundo factor) ---------------- */

function pendingContext(req) {
  const p = req.session.pending;
  if (!p) return null;
  const user = users.findById(p.userId);
  if (!user) return null;
  return { p, user, methods: mfa.listMethods(user.id) };
}

function renderVerify(req, res, { error = null, status = 200 } = {}) {
  const ctx = pendingContext(req);
  if (!ctx) return res.redirect('/login');
  const { p, user, methods } = ctx;
  const current = methods.find((m) => m.type === p.method);
  const purpose = `login_${p.method}`;
  res.status(status).render('verify', {
    title: 'Verifica tu identidad',
    step: 2,
    method: p.method,
    current,
    methods,
    firstName: user.name.split(' ')[0],
    attemptsLeft: config.security.maxMfaAttemptsPerSession - p.attempts,
    expiresAt: p.method === 'email' || p.method === 'sms' ? mfa.otpExpiresAt(user.id, purpose) : null,
    resendWait: p.method === 'email' || p.method === 'sms' ? mfa.resendWait(user.id, purpose) : 0,
    recoveryLeft: mfa.recoveryRemaining(user.id),
    trustDays: config.security.trustedDeviceDays,
    error,
  });
}

router.get('/verificar', (req, res) => {
  if (req.user) return res.redirect('/panel');
  renderVerify(req, res);
});

router.post('/verificar', limits.verify, async (req, res, next) => {
  try {
    const ctx = pendingContext(req);
    if (!ctx) {
      req.flash('info', 'Tu verificación venció. Escribe tu contraseña otra vez.');
      return res.redirect('/login');
    }
    const { p, user } = ctx;
    const code = String(req.body.code || '').trim();
    let result = { ok: false };

    if (p.method === 'totp') result = mfa.verifyTotp(user.id, code);
    else if (p.method === 'respaldo') result = { ok: mfa.useRecoveryCode(user.id, code) };
    else {
      const r = mfa.verifyOtp(user.id, `login_${p.method}`, code);
      result = r;
      if (r.reason === 'expired') {
        return renderVerify(req, res, { error: 'Ese código ya venció. Pide uno nuevo con el botón de reenviar.', status: 401 });
      }
    }

    if (result.ok) {
      const via = p.method;
      const remember = req.body.remember === 'on';
      mfa.touchMethod(user.id, via);
      if (via === 'respaldo') {
        const left = mfa.recoveryRemaining(user.id);
        audit.log(req, { userId: user.id, email: user.email, event: 'recovery_used', severity: 'aviso', detail: `quedan ${left}` });
        notifier.sendEmail(user.email, 'Se usó un código de respaldo', [
          'Alguien entró a tu cuenta con uno de tus códigos de respaldo.',
          `Te quedan ${left} códigos. Si no fuiste tú, cambia tu contraseña y regenera los códigos.`,
        ]);
      }
      await completeLogin(req, user, { via });
      if (remember) {
        const t = mfa.trustDevice(user.id, req.get('user-agent'), audit.clientIp(req));
        setTrustCookie(res, t.token, t.maxAge);
      }
      return res.redirect('/panel');
    }

    // Código incorrecto
    p.attempts += 1;
    const replay = !!result.replay;
    audit.log(req, {
      userId: user.id,
      email: user.email,
      event: replay ? 'totp_replay' : 'mfa_fail',
      severity: replay ? 'alerta' : 'aviso',
      detail: `${p.method}, intento ${p.attempts}`,
    });
    const lock = users.registerMfaFailure(user);

    if (p.attempts >= config.security.maxMfaAttemptsPerSession || result.reason === 'exhausted' || lock.locked) {
      delete req.session.pending;
      audit.log(req, { userId: user.id, email: user.email, event: 'mfa_session_killed', severity: 'alerta' });
      if (lock.locked) {
        audit.log(req, { userId: user.id, email: user.email, event: 'account_locked', severity: 'critico', detail: `${lock.locked} min por códigos incorrectos` });
        notifier.sendEmail(user.email, 'Alguien conoce tu contraseña', [
          'Se escribió tu contraseña correctamente, pero el código de verificación falló muchas veces.',
          'Esto suele significar que tu contraseña fue robada o filtrada. Tu segundo factor detuvo el acceso.',
          `Pausamos la cuenta ${lock.locked} minutos. Cuando vuelvas, cambia tu contraseña.`,
        ]);
        req.flash('error', lockMessage(lock.locked));
      } else {
        req.flash('error', 'Hubo demasiados códigos incorrectos. Por seguridad, vuelve a escribir tu contraseña.');
      }
      return req.session.save(() => res.redirect('/login'));
    }

    const left = config.security.maxMfaAttemptsPerSession - p.attempts;
    const msg = replay
      ? 'Ese código ya se usó. Espera a que tu app muestre uno nuevo.'
      : p.method === 'respaldo'
        ? `Ese código de respaldo no es válido o ya se usó. Te quedan ${left} intentos.`
        : `El código no es correcto. Te quedan ${left} ${left === 1 ? 'intento' : 'intentos'}.`;
    renderVerify(req, res, { error: msg, status: 401 });
  } catch (e) {
    next(e);
  }
});

router.post('/verificar/metodo', limits.verify, async (req, res, next) => {
  try {
    const ctx = pendingContext(req);
    if (!ctx) return res.redirect('/login');
    const wanted = String(req.body.metodo || '');
    const target = ctx.methods.find((m) => m.type === wanted);
    if (wanted === 'respaldo' || target) {
      ctx.p.method = wanted;
      if (target && target.type !== 'totp') {
        const r = await mfa.issueOtp(ctx.user.id, `login_${target.type}`, target.type, target.destination);
        if (r.ok) audit.log(req, { userId: ctx.user.id, email: ctx.user.email, event: 'mfa_code_sent', detail: target.type });
      }
    }
    req.session.save(() => res.redirect('/verificar'));
  } catch (e) {
    next(e);
  }
});

router.post('/verificar/reenviar', limits.verify, async (req, res, next) => {
  try {
    const ctx = pendingContext(req);
    if (!ctx) return res.redirect('/login');
    const m = ctx.methods.find((x) => x.type === ctx.p.method);
    if (!m || m.type === 'totp') return res.redirect('/verificar');
    const r = await mfa.issueOtp(ctx.user.id, `login_${m.type}`, m.type, m.destination);
    if (r.ok) {
      audit.log(req, { userId: ctx.user.id, email: ctx.user.email, event: 'mfa_code_sent', detail: `${m.type} (reenvío)` });
      req.flash('ok', `Enviamos un código nuevo a ${m.masked}. El anterior ya no funciona.`);
    } else {
      req.flash('info', `Espera ${r.wait} segundos para pedir otro código.`);
    }
    res.redirect('/verificar');
  } catch (e) {
    next(e);
  }
});

router.post('/verificar/cancelar', (req, res) => {
  delete req.session.pending;
  res.redirect('/login');
});

/* ---------------- Registro ---------------- */

router.get('/registro', guestOnly, (req, res) => {
  res.render('register', { title: 'Crear cuenta', step: 0, values: {}, errors: [] });
});

router.post('/registro', guestOnly, limits.register, async (req, res, next) => {
  try {
    const values = {
      name: String(req.body.name || '').trim().slice(0, 80),
      email: users.normEmail(req.body.email).slice(0, 254),
    };
    const plain = String(req.body.password || '');
    const errors = [];
    if (values.name.length < 3) errors.push('Escribe tu nombre completo.');
    if (!EMAIL_RE.test(values.email)) errors.push('Escribe un correo válido, por ejemplo nombre@empresa.com.');
    if (plain !== String(req.body.password2 || '')) errors.push('Las contraseñas no coinciden.');
    const evalr = password.evaluate(plain, values);
    errors.push(...evalr.errors);
    if (!errors.length) {
      const pwned = await password.timesPwned(plain);
      if (pwned > 0) errors.push(`Esa contraseña apareció ${pwned.toLocaleString('es-GT')} veces en filtraciones públicas. Elige otra.`);
    }
    if (!errors.length && users.findByEmail(values.email)) {
      // Mensaje neutro: no confirma de forma explícita que la cuenta existe para terceros
      errors.push('No pudimos crear la cuenta con ese correo. Si ya tienes una, inicia sesión.');
    }
    if (errors.length) return res.status(400).render('register', { title: 'Crear cuenta', step: 0, values, errors });

    const user = await users.create({ name: values.name, email: values.email, plainPassword: plain });
    audit.log(req, { userId: user.id, email: user.email, event: 'register' });
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.setup = { userId: user.id, startedAt: Date.now() };
      req.session.flash = [{ type: 'ok', text: 'Cuenta creada. Falta un paso: elige cómo vas a confirmar que eres tú.' }];
      res.redirect('/configurar');
    });
  } catch (e) {
    next(e);
  }
});

/* ---------------- Cerrar sesión ---------------- */

router.post('/salir', (req, res) => {
  const userId = req.session.userId;
  if (userId) audit.log(req, { userId, event: 'logout' });
  req.session.destroy(() => {
    res.clearCookie('ceiba.sid');
    res.redirect('/login');
  });
});

module.exports = router;
