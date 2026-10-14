'use strict';
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const config = require('../config');

// Contraseñas más filtradas en brechas públicas (muestra). Se rechazan siempre.
const COMMON = new Set(`123456 123456789 12345678 password qwerty123 qwerty 1q2w3e4r 111111 123123 abc123
password1 1234567890 000000 iloveyou admin admin123 welcome letmein monkey dragon football
contraseña contrasena guatemala guatemala1 guatemala123 chapin chapin123 12345 1234 654321
superman batman sunshine princess qwertyuiop asdfghjk zxcvbnm passw0rd p@ssw0rd p@ssword
master hello freedom whatever trustno1 starwars shadow michael jennifer jordan23 tequiero
teamo amor amorcito barcelona realmadrid messi cristiano 987654321 1qaz2wsx changeme
seguridad seguridad123 umg umg123 universidad clave clave123 secreto mipassword`.split(/\s+/));

const POLICY = {
  minLength: 10,
  maxLength: 128,
};

/**
 * Evalúa la contraseña: devuelve { ok, errors[], score 0-4 }.
 * El servidor es la fuente de verdad; el medidor del navegador solo orienta al usuario.
 */
function evaluate(password, context = {}) {
  const errors = [];
  const pw = String(password || '');
  if (pw.length < POLICY.minLength) errors.push(`Usa al menos ${POLICY.minLength} caracteres.`);
  if (pw.length > POLICY.maxLength) errors.push(`Usa como máximo ${POLICY.maxLength} caracteres.`);
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw)) errors.push('Combina mayúsculas y minúsculas.');
  if (!/\d/.test(pw)) errors.push('Incluye al menos un número.');
  if (!/[^A-Za-z0-9]/.test(pw)) errors.push('Incluye al menos un símbolo, por ejemplo # o !.');
  if (COMMON.has(pw.toLowerCase())) errors.push('Esa contraseña aparece en listas de contraseñas filtradas.');
  if (/(.)\1{3,}/.test(pw)) errors.push('Evita repetir el mismo carácter muchas veces.');

  const lower = pw.toLowerCase();
  const personal = [context.email && context.email.split('@')[0], ...(String(context.name || '').split(/\s+/))]
    .filter((t) => t && t.length >= 4)
    .map((t) => t.toLowerCase());
  if (personal.some((t) => lower.includes(t))) errors.push('No uses tu nombre ni tu correo dentro de la contraseña.');

  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  const bits = pw.length * Math.log2(pool || 1);
  const score = errors.length ? Math.min(1, Math.floor(bits / 40)) : bits < 60 ? 2 : bits < 80 ? 3 : 4;

  return { ok: errors.length === 0, errors, score, bits: Math.round(bits) };
}

/**
 * Consulta Have I Been Pwned con k-anonimato: solo se envían los 5 primeros
 * caracteres del SHA-1, nunca la contraseña. Si no hay internet, no bloquea.
 */
async function timesPwned(password) {
  if (!config.security.checkPwned || typeof fetch !== 'function') return null;
  const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 2500);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      signal: ctrl.signal,
      headers: { 'Add-Padding': 'true' },
    });
    clearTimeout(t);
    if (!res.ok) return null;
    const text = await res.text();
    for (const line of text.split('\n')) {
      const [suf, count] = line.trim().split(':');
      if (suf === suffix) return parseInt(count, 10) || 0;
    }
    return 0;
  } catch {
    return null;
  }
}

function hash(password) {
  return bcrypt.hash(password, config.security.bcryptRounds);
}

// Hash ficticio para comparar aunque el usuario no exista (mismo tiempo de respuesta).
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', config.security.bcryptRounds);

function verify(password, passwordHash) {
  return bcrypt.compare(String(password || ''), passwordHash || DUMMY_HASH);
}

module.exports = { evaluate, timesPwned, hash, verify, POLICY };
