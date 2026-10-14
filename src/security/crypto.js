'use strict';
const crypto = require('crypto');
const config = require('../config');

const KEY = crypto.createHash('sha256').update(config.encryptionKey).digest(); // 32 bytes
const HMAC_KEY = crypto.createHash('sha256').update('hmac:' + config.encryptionKey).digest();

/** Cifra texto con AES-256-GCM (confidencialidad + integridad). Formato: iv.tag.ciphertext (base64url) */
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, enc].map((b) => b.toString('base64url')).join('.');
}

function decrypt(payload) {
  const [iv, tag, enc] = String(payload).split('.').map((s) => Buffer.from(s, 'base64url'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

/** Hash con llave (HMAC-SHA256) para códigos de un solo uso y tokens: nunca se guardan en texto plano. */
function hmac(value) {
  return crypto.createHmac('sha256', HMAC_KEY).update(String(value)).digest('hex');
}

/** Comparación en tiempo constante: evita ataques de temporización. */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** Código numérico uniforme usando el generador criptográfico del sistema. */
function numericCode(digits = 6) {
  const max = 10 ** digits;
  return String(crypto.randomInt(0, max)).padStart(digits, '0');
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Código de respaldo legible: XXXX-XXXX sin caracteres ambiguos (0/O, 1/I/L). */
function recoveryCode() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  let out = '';
  for (let i = 0; i < 8; i++) out += alphabet[crypto.randomInt(0, alphabet.length)];
  return out.slice(0, 4) + '-' + out.slice(4);
}

module.exports = { encrypt, decrypt, hmac, safeEqual, numericCode, randomToken, recoveryCode };
