'use strict';
const rateLimit = require('express-rate-limit');
const config = require('../config');
const audit = require('../services/audit');

function limiter(limit, windowMinutes, name, extra = {}) {
  return rateLimit({
    ...extra,
    windowMs: windowMinutes * 60000,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: (req, res) => {
      audit.log(req, { event: 'rate_limited', severity: 'alerta', detail: `${name}: ${req.originalUrl}` });
      res.status(429).render('error', {
        title: 'Demasiados intentos',
        message: `Recibimos muchas solicitudes desde tu conexión. Espera ${windowMinutes} minutos antes de intentarlo de nuevo.`,
        code: 429,
      });
    },
  });
}

module.exports = {
  // Solo cuentan los intentos fallidos: un usuario que entra bien no consume su cupo.
  login: limiter(config.security.loginRateLimit, config.security.loginRateWindowMinutes, 'login', { skipSuccessfulRequests: true }),
  verify: limiter(40, 15, 'verificación'),
  register: limiter(10, 60, 'registro'),
  sensitive: limiter(30, 15, 'operación sensible'),
};
