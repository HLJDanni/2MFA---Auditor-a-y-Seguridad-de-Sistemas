'use strict';
const path = require('path');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const config = require('./config');
const db = require('./db');
const sec = require('./middleware/security');

async function createApp() {
  await db.init();
  await require('./seed').run();

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 'loopback');
  app.set('view engine', 'ejs');
  app.set('views', path.join(config.root, 'views'));

  // Cabeceras de seguridad: CSP estricta (sin scripts en línea), anti-clickjacking, HSTS, etc.
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          baseUri: ["'self'"],
          objectSrc: ["'none'"],
        },
      },
      hsts: config.secureCookies ? undefined : false,
      referrerPolicy: { policy: 'same-origin' },
      frameguard: { action: 'deny' },
    })
  );
  app.use((req, res, next) => {
    res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });

  app.use('/static', express.static(path.join(config.root, 'public'), { maxAge: config.env === 'production' ? '7d' : 0 }));
  app.use(express.urlencoded({ extended: false, limit: '20kb' }));
  app.use(express.json({ limit: '20kb' }));

  app.use(
    session({
      name: 'ceiba.sid',
      secret: config.sessionSecret,
      resave: false,
      saveUninitialized: false,
      rolling: true,
      cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: config.secureCookies,
        maxAge: 8 * 60 * 60 * 1000,
      },
    })
  );

  app.use(sec.noStore);
  app.use(sec.flash);
  app.use(sec.loadUser);
  app.use(sec.csrf);

  // Utilidades para las vistas
  app.locals.appName = config.appName;
  app.locals.demoMode = config.demoMode;
  app.locals.idleMinutes = config.security.sessionIdleMinutes;
  app.locals.flash = [];
  app.locals.csrf = '';
  app.locals.path = '';
  app.locals.fmtDate = (ms) =>
    ms
      ? new Intl.DateTimeFormat('es-GT', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'America/Guatemala' }).format(new Date(ms))
      : '—';
  app.locals.timeAgo = (ms) => {
    if (!ms) return 'nunca';
    const s = Math.round((Date.now() - ms) / 1000);
    if (s < 60) return 'hace un momento';
    if (s < 3600) return `hace ${Math.round(s / 60)} min`;
    if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
    return `hace ${Math.round(s / 86400)} d`;
  };
  app.locals.initials = (name = '') =>
    name
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((p) => p[0].toUpperCase())
      .join('');

  app.use(require('./routes/auth'));
  app.use(require('./routes/enroll'));
  app.use(require('./routes/account'));
  app.use(require('./routes/admin'));
  if (config.demoMode) app.use(require('./routes/demo'));

  app.use((req, res) => res.status(404).render('error', { title: 'Página no encontrada', message: 'La dirección que buscas no existe o cambió de lugar.', code: 404 }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).render('error', { title: 'Algo falló de nuestro lado', message: 'Registramos el error. Intenta de nuevo en unos segundos.', code: 500 });
  });

  return app;
}

if (require.main === module) {
  createApp().then((app) => {
    app.listen(config.port, () => {
      console.log(`\n  ${config.appName} · autenticación multifactor`);
      console.log(`  ➜ ${config.baseUrl}`);
      if (config.demoMode) console.log(`  ➜ Bandeja de demostración: ${config.baseUrl}/demo/bandeja`);
      console.log('');
    });
  });
}

module.exports = { createApp };
