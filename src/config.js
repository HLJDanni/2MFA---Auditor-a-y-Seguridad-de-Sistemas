'use strict';
const path = require('path');
const crypto = require('crypto');
require('dotenv').config({ path: process.env.DOTENV_PATH || path.join(__dirname, '..', '.env') });

const bool = (v, def) => (v === undefined || v === '' ? def : /^(1|true|yes|si|sí)$/i.test(v));
const int = (v, def) => (Number.isFinite(parseInt(v, 10)) ? parseInt(v, 10) : def);

const ROOT = path.join(__dirname, '..');

// Clave maestra para cifrar secretos TOTP (AES-256-GCM).
// En producción DEBE venir de variable de entorno; en modo demo se genera y se guarda en data/.
function resolveKey(name, envVal) {
  if (envVal && envVal.length >= 32) return envVal;
  const fs = require('fs');
  const keyFile = path.join(ROOT, 'data', `.${name}`);
  try {
    return fs.readFileSync(keyFile, 'utf8').trim();
  } catch {
    const k = crypto.randomBytes(32).toString('hex');
    fs.mkdirSync(path.dirname(keyFile), { recursive: true });
    fs.writeFileSync(keyFile, k, { mode: 0o600 });
    return k;
  }
}

const config = {
  root: ROOT,
  appName: process.env.APP_NAME || 'Ceiba',
  port: int(process.env.PORT, 3000),
  env: process.env.NODE_ENV || 'development',
  demoMode: bool(process.env.DEMO_MODE, true),
  baseUrl: process.env.BASE_URL || `http://localhost:${int(process.env.PORT, 3000)}`,
  dbPath: process.env.DB_PATH || path.join(ROOT, 'data', 'ceiba.db'),
  sessionSecret: resolveKey('session_secret', process.env.SESSION_SECRET),
  encryptionKey: resolveKey('encryption_key', process.env.ENCRYPTION_KEY),
  secureCookies: bool(process.env.SECURE_COOKIES, false),

  security: {
    bcryptRounds: int(process.env.BCRYPT_ROUNDS, 12),
    maxPasswordAttempts: int(process.env.MAX_PASSWORD_ATTEMPTS, 5),
    lockMinutes: int(process.env.LOCK_MINUTES, 15),
    maxMfaAttemptsPerSession: int(process.env.MAX_MFA_ATTEMPTS, 5),
    maxMfaFailuresBeforeLock: int(process.env.MAX_MFA_FAILURES_LOCK, 10),
    otpTtlSeconds: int(process.env.OTP_TTL_SECONDS, 300),
    otpResendSeconds: int(process.env.OTP_RESEND_SECONDS, 60),
    mfaPendingMinutes: int(process.env.MFA_PENDING_MINUTES, 10),
    sessionIdleMinutes: int(process.env.SESSION_IDLE_MINUTES, 30),
    trustedDeviceDays: int(process.env.TRUSTED_DEVICE_DAYS, 30),
    loginRateLimit: int(process.env.LOGIN_RATE_LIMIT, 20),
    loginRateWindowMinutes: int(process.env.LOGIN_RATE_WINDOW, 15),
    checkPwned: bool(process.env.CHECK_PWNED_PASSWORDS, true),
  },

  smtp: {
    host: process.env.SMTP_HOST || '',
    port: int(process.env.SMTP_PORT, 587),
    secure: bool(process.env.SMTP_SECURE, false),
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || 'Ceiba Seguridad <no-reply@ceiba.local>',
  },

  twilio: {
    sid: process.env.TWILIO_ACCOUNT_SID || '',
    token: process.env.TWILIO_AUTH_TOKEN || '',
    from: process.env.TWILIO_FROM || '',
  },
};

module.exports = config;
