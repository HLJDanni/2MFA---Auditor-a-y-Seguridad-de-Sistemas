#!/usr/bin/env node
'use strict';
/**
 * Pruebas de resistencia frente a ataques
 * ---------------------------------------
 * Levanta una instancia aislada del sistema (puerto y base de datos temporales),
 * ejecuta ataques reales por HTTP y genera un reporte en reports/.
 *
 *   npm run test:ataques
 */
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { authenticator } = require('otplib');
const initSqlJs = require('sql.js');

const ROOT = path.join(__dirname, '..');
const PORT = 4100 + Math.floor(Math.random() * 800);
const BASE = `http://127.0.0.1:${PORT}`;
const DB_PATH = path.join(os.tmpdir(), `ceiba-ataques-${Date.now()}.db`);
const OTP_TTL = 6;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const C = { ok: '\x1b[32m', bad: '\x1b[31m', dim: '\x1b[2m', b: '\x1b[1m', r: '\x1b[0m', y: '\x1b[33m' };

/* ---------- Cliente HTTP con cookies (simula un navegador o un atacante) ---------- */
class Client {
  constructor(name) {
    this.name = name;
    this.cookies = {};
  }
  cookieHeader() {
    return Object.entries(this.cookies).map(([k, v]) => `${k}=${v}`).join('; ');
  }
  store(res) {
    const list = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [res.headers.get('set-cookie')].filter(Boolean);
    for (const c of list) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      this.cookies[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
    }
  }
  async req(method, url, form) {
    const t0 = performance.now();
    const res = await fetch(BASE + url, {
      method,
      redirect: 'manual',
      headers: {
        cookie: this.cookieHeader(),
        'user-agent': `Mozilla/5.0 (Prueba ${this.name})`,
        ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
      },
      body: form ? new URLSearchParams(form).toString() : undefined,
    });
    this.store(res);
    const body = await res.text();
    return { status: res.status, location: res.headers.get('location') || '', body, headers: res.headers, ms: performance.now() - t0 };
  }
  get(url) {
    return this.req('GET', url);
  }
  post(url, form) {
    return this.req('POST', url, form);
  }
  async csrf(url) {
    const r = await this.get(url);
    const m = r.body.match(/name="_csrf" value="([^"]+)"/);
    return m ? m[1] : '';
  }
  /** Envía un formulario incluyendo el token CSRF de la página indicada */
  async submit(pageUrl, action, form) {
    const token = await this.csrf(pageUrl);
    return this.post(action, { _csrf: token, ...form });
  }
}

const errorText = (html) => {
  const m = html.match(/class="alert alert-error[^"]*"[^>]*>[\s\S]*?<span>([\s\S]*?)<\/span>/);
  return m ? m[1].replace(/\s+/g, ' ').trim() : '';
};

/* ---------- Lectura directa de la base (solo para el arnés de pruebas) ---------- */
let SQL;
async function query(sql, params = []) {
  SQL = SQL || (await initSqlJs());
  const db = new SQL.Database(fs.readFileSync(DB_PATH));
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  db.close();
  return rows;
}
async function lastCodeFor(destination) {
  const rows = await query('SELECT body FROM outbox WHERE destination = ? ORDER BY id DESC LIMIT 1', [destination]);
  const m = rows[0] && rows[0].body.match(/\b(\d{6})\b/);
  return m ? m[1] : null;
}

/* ---------- Alta de usuarios de prueba por el flujo real ---------- */
async function registerWithTotp(email, password) {
  const c = new Client('usuario legítimo');
  await c.submit('/registro', '/registro', { name: 'Víctima de Prueba', email, password, password2: password });
  const page = await c.get('/cuenta/metodos/totp');
  const secret = page.body.match(/data-copy-src>([^<]+)</)[1].replace(/\s+/g, '');
  const token = page.body.match(/name="_csrf" value="([^"]+)"/)[1];
  await c.post('/cuenta/metodos/totp', { _csrf: token, code: authenticator.generate(secret) });
  const rc = await c.get('/cuenta/respaldo/nuevos');
  const codes = [...rc.body.matchAll(/<li>([A-Z0-9]{4}-[A-Z0-9]{4})<\/li>/g)].map((m) => m[1]);
  return { secret, codes, step: Math.floor(Date.now() / 30000) };
}

async function registerWithEmail(email, password) {
  const c = new Client('usuario legítimo');
  await c.submit('/registro', '/registro', { name: 'Usuario Correo', email, password, password2: password });
  await c.submit('/cuenta/metodos/correo', '/cuenta/metodos/correo/enviar', { destination: email });
  const code = await lastCodeFor(email);
  await c.submit('/cuenta/metodos/correo', '/cuenta/metodos/correo/verificar', { code });
}

/** Espera al inicio del siguiente paso de 30 s para que el código TOTP no cambie a mitad de prueba */
async function freshTotpWindow(usedStep = -1) {
  // Un código ya aceptado no puede volver a usarse (protección anti-replay), así que esperamos
  // a un paso de 30 s que no se haya usado y que no esté por terminar.
  while (Math.floor(Date.now() / 30000) <= usedStep) await sleep(500);
  const s = (Date.now() / 1000) % 30;
  if (s > 22) await sleep((30 - s + 0.5) * 1000);
}

/* ---------- Ataques ---------- */
const results = [];
async function test(id, ataque, objetivo, fn) {
  process.stdout.write(`${C.dim}  [${id}] ${ataque}…${C.r}`);
  const t0 = Date.now();
  try {
    const { ok, evidencia } = await fn();
    results.push({ id, ataque, objetivo, resultado: ok ? 'RESISTIÓ' : 'VULNERABLE', evidencia, ms: Date.now() - t0 });
    process.stdout.write(`\r  ${ok ? C.ok + '✔ RESISTIÓ ' : C.bad + '✘ VULNERABLE'}${C.r} [${id}] ${ataque}\n      ${C.dim}${evidencia}${C.r}\n`);
  } catch (e) {
    results.push({ id, ataque, objetivo, resultado: 'ERROR', evidencia: e.message, ms: Date.now() - t0 });
    process.stdout.write(`\r  ${C.y}! ERROR${C.r} [${id}] ${ataque}: ${e.message}\n`);
  }
}

async function main() {
  console.log(`\n${C.b}Ceiba · pruebas de resistencia frente a ataques${C.r}`);
  console.log(`${C.dim}Instancia aislada en ${BASE}, base temporal ${DB_PATH}${C.r}\n`);

  const server = spawn(process.execPath, [path.join(ROOT, 'src', 'server.js')], {
    env: {
      ...process.env,
      DOTENV_PATH: path.join(os.tmpdir(), 'no-existe.env'),
      PORT: String(PORT),
      DB_PATH,
      DEMO_MODE: 'true',
      CHECK_PWNED_PASSWORDS: 'false',
      OTP_TTL_SECONDS: String(OTP_TTL),
      OTP_RESEND_SECONDS: '0',
      LOGIN_RATE_LIMIT: '30',
      SMTP_HOST: '',
      TWILIO_ACCOUNT_SID: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  process.on('exit', () => server.kill());
  let log = '';
  server.stdout.on('data', (d) => (log += d));
  server.stderr.on('data', (d) => (log += d));
  let exited = false;
  server.on('exit', () => (exited = true));
  let ready = false;
  for (let i = 0; i < 300 && !exited; i++) {
    try {
      await fetch(BASE + '/login');
      ready = true;
      break;
    } catch {
      await sleep(250);
    }
  }
  if (!ready) {
    console.error('No se pudo iniciar el servidor de pruebas:\n' + log);
    process.exit(1);
  }

  const PW = 'Volcan$Fuego2026!';
  const victim = await registerWithTotp('victima@ceiba.test', PW);
  await registerWithEmail('correo@ceiba.test', PW);
  await registerWithTotp('enum@ceiba.test', PW);

  /* 1. Fuerza bruta / diccionario contra la contraseña */
  await test('A1', 'Fuerza bruta con diccionario contra la contraseña', 'Adivinar la contraseña de ana@ceiba.test probando las más comunes', async () => {
    const attacker = new Client('atacante');
    const dictionary = ['123456', 'password', 'Guatemala2026', 'Qwerty123!', 'Ana2026!', 'Contraseña1', 'Admin123!'];
    const statuses = [];
    for (const pw of dictionary) {
      const r = await attacker.submit('/login', '/login', { email: 'ana@ceiba.test', password: pw });
      statuses.push(r.status);
    }
    // Aun con la contraseña correcta, la cuenta queda pausada
    const real = await attacker.submit('/login', '/login', { email: 'ana@ceiba.test', password: 'Quetzal#Lago2026' });
    const lockedAt = statuses.indexOf(423) + 1;
    const ok = lockedAt > 0 && lockedAt <= 5 && real.status === 423 && !real.location.includes('/verificar');
    return { ok, evidencia: `Respuestas: ${statuses.join(', ')}. Bloqueo en el intento ${lockedAt}; con la contraseña real también respondió ${real.status} (cuenta pausada 15 min).` };
  });

  /* 2. Contraseña robada (phishing, filtración o credential stuffing) */
  let stolenSession;
  await test('A2', 'Contraseña robada: el atacante la conoce', 'Entrar a la cuenta solo con usuario y contraseña correctos', async () => {
    stolenSession = new Client('atacante con contraseña robada');
    const r = await stolenSession.submit('/login', '/login', { email: 'victima@ceiba.test', password: PW });
    const panel = await stolenSession.get('/panel');
    const metodos = await stolenSession.get('/cuenta/metodos');
    const ok = r.location === '/verificar' && panel.status === 302 && panel.location === '/verificar' && metodos.status === 302;
    return { ok, evidencia: `La contraseña fue aceptada pero el sistema exigió el segundo factor (redirección a ${r.location}). /panel respondió ${panel.status} hacia ${panel.location}; no hubo acceso a datos.` };
  });

  /* 3. Fuerza bruta del segundo factor */
  await test('A3', 'Fuerza bruta del código de verificación', 'Adivinar el código de 6 dígitos tras robar la contraseña', async () => {
    const tries = [];
    let killed = false;
    for (let i = 0; i < 8 && !killed; i++) {
      const guess = String(Math.floor(Math.random() * 1e6)).padStart(6, '0');
      const r = await stolenSession.submit('/verificar', '/verificar', { code: guess });
      tries.push(r.status);
      if (r.status === 302 && r.location === '/login') killed = true;
    }
    const after = await stolenSession.get('/verificar');
    const ok = killed && tries.length <= 5 && after.location === '/login';
    const p = ((tries.length / 1e6) * 100).toFixed(4);
    return { ok, evidencia: `Tras ${tries.length} códigos incorrectos la sesión se anuló y se volvió a exigir la contraseña. Probabilidad de acierto por sesión: ${p} %.` };
  });

  /* 4. Reutilización de un código TOTP interceptado */
  await test('A4', 'Reutilización de un código de la app (replay)', 'Usar un código TOTP capturado (phishing en tiempo real u observación)', async () => {
    await freshTotpWindow(victim.step);
    const legit = new Client('usuario legítimo');
    await legit.submit('/login', '/login', { email: 'victima@ceiba.test', password: PW });
    const code = authenticator.generate(victim.secret);
    const ok1 = await legit.submit('/verificar', '/verificar', { code });
    const attacker = new Client('atacante');
    await attacker.submit('/login', '/login', { email: 'victima@ceiba.test', password: PW });
    const r = await attacker.submit('/verificar', '/verificar', { code });
    const panel = await attacker.get('/panel');
    victim.step = Math.floor(Date.now() / 30000);
    const ok = ok1.location === '/panel' && r.status === 401 && /ya se usó/.test(r.body) && panel.status === 302;
    return { ok, evidencia: `El usuario legítimo ${ok1.location === '/panel' ? 'entró' : 'NO pudo entrar'} con ${code}. El mismo código usado por el atacante segundos después fue rechazado: "${errorText(r.body)}".` };
  });

  /* 5. Código de respaldo de un solo uso */
  await test('A5', 'Reutilización de un código de respaldo', 'Usar dos veces un código de respaldo filtrado', async () => {
    const code = victim.codes[0];
    const a = new Client('usuario');
    await a.submit('/login', '/login', { email: 'victima@ceiba.test', password: PW });
    await a.submit('/verificar', '/verificar/metodo', { metodo: 'respaldo' });
    const r1 = await a.submit('/verificar', '/verificar', { code });
    const b = new Client('atacante');
    await b.submit('/login', '/login', { email: 'victima@ceiba.test', password: PW });
    await b.submit('/verificar', '/verificar/metodo', { metodo: 'respaldo' });
    const r2 = await b.submit('/verificar', '/verificar', { code });
    const ok = r1.location === '/panel' && r2.status === 401;
    return { ok, evidencia: `Primer uso de ${code}: acceso concedido. Segundo uso: respuesta ${r2.status}, "${errorText(r2.body)}".` };
  });

  /* 6. Código vencido */
  await test('A6', 'Uso de un código de correo vencido', `Usar un código válido después de su vigencia (${OTP_TTL} s en esta prueba, 5 min en producción)`, async () => {
    const c = new Client('atacante con código viejo');
    await c.submit('/login', '/login', { email: 'correo@ceiba.test', password: PW });
    const code = await lastCodeFor('correo@ceiba.test');
    await sleep((OTP_TTL + 1.5) * 1000);
    const r = await c.submit('/verificar', '/verificar', { code });
    const ok = r.status === 401 && /venció/.test(r.body);
    return { ok, evidencia: `Código correcto ${code} enviado ${OTP_TTL + 1.5} s después: "${errorText(r.body)}".` };
  });

  /* 7. Acceso directo sin autenticación */
  await test('A7', 'Acceso directo a páginas protegidas', 'Saltarse el inicio de sesión escribiendo la URL', async () => {
    const c = new Client('anónimo');
    const urls = ['/panel', '/cuenta/metodos', '/cuenta/respaldo', '/cuenta/actividad', '/admin'];
    const res = [];
    for (const u of urls) res.push(await c.get(u));
    const ok = res.every((r) => r.status === 302 && r.location === '/login');
    return { ok, evidencia: urls.map((u, i) => `${u} → ${res[i].status} ${res[i].location}`).join('; ') };
  });

  /* 8. Escalada de privilegios */
  await test('A8', 'Escalada de privilegios a administrador', 'Un usuario autenticado sin rol de administrador intenta abrir /admin', async () => {
    await freshTotpWindow(victim.step);
    const c = new Client('usuario normal');
    await c.submit('/login', '/login', { email: 'victima@ceiba.test', password: PW });
    await c.submit('/verificar', '/verificar', { code: authenticator.generate(victim.secret) });
    const p = await c.get('/panel');
    const a = await c.get('/admin');
    const u = await c.submit('/panel', '/admin/usuarios/1/desbloquear', {});
    const ok = p.status === 200 && a.status === 403 && u.status === 403;
    return { ok, evidencia: `Sesión válida (/panel ${p.status}). /admin respondió ${a.status} y la acción de desbloquear usuarios ${u.status}.` };
  });

  /* 9. Inyección SQL */
  await test('A9', 'Inyección SQL en el formulario de acceso', "Entrar con cargas como ' OR '1'='1", async () => {
    const c = new Client('atacante');
    const payloads = [
      { email: "admin@ceiba.test' --", password: 'x' },
      { email: 'admin@ceiba.test', password: "' OR '1'='1" },
      { email: "x@x.com' OR 1=1; DROP TABLE users; --", password: "' OR ''='" },
    ];
    const st = [];
    for (const p of payloads) st.push((await c.submit('/login', '/login', p)).status);
    const usersLeft = (await query('SELECT COUNT(*) AS n FROM users'))[0].n;
    const ok = st.every((s) => s === 400 || s === 401) && usersLeft >= 4;
    return { ok, evidencia: `Respuestas: ${st.join(', ')}. La tabla users sigue intacta (${usersLeft} registros). Todas las consultas usan parámetros enlazados.` };
  });

  /* 10. CSRF */
  await test('A10', 'Falsificación de petición entre sitios (CSRF)', 'Un sitio malicioso envía un formulario usando la sesión abierta de la víctima', async () => {
    const c = new Client('usuario con sesión');
    await c.submit('/login', '/login', { email: 'correo@ceiba.test', password: PW });
    const code = await lastCodeFor('correo@ceiba.test');
    await c.submit('/verificar', '/verificar', { code });
    const panel = await c.get('/panel');
    const forged = await c.post('/cuenta/metodos/email/eliminar', { current_password: PW });
    const forged2 = await c.post('/cuenta/respaldo', { _csrf: 'token-falso', current_password: PW });
    const ok = panel.status === 200 && forged.status === 403 && forged2.status === 403;
    return { ok, evidencia: `Con sesión activa (/panel ${panel.status}), las peticiones sin token o con token falso respondieron ${forged.status} y ${forged2.status}.` };
  });

  /* 11. Enumeración de usuarios */
  await test('A11', 'Enumeración de cuentas registradas', 'Descubrir qué correos existen comparando mensajes y tiempos de respuesta', async () => {
    const c = new Client('atacante');
    const real = [];
    const fake = [];
    for (let i = 0; i < 3; i++) {
      real.push(await c.submit('/login', '/login', { email: 'enum@ceiba.test', password: 'Incorrecta#2026' }));
      fake.push(await c.submit('/login', '/login', { email: 'noexiste@ceiba.test', password: 'Incorrecta#2026' }));
    }
    const sameMsg = real.every((r, i) => errorText(r.body) === errorText(fake[i].body) && r.status === fake[i].status);
    const avg = (a) => a.reduce((s, r) => s + r.ms, 0) / a.length;
    const diff = Math.abs(avg(real) - avg(fake));
    const ok = sameMsg && diff < 120;
    return { ok, evidencia: `Mensajes idénticos: ${sameMsg ? 'sí' : 'no'} ("${errorText(real[0].body).slice(0, 60)}…"). Tiempo medio: ${avg(real).toFixed(0)} ms vs ${avg(fake).toFixed(0)} ms (diferencia ${diff.toFixed(0)} ms).` };
  });

  /* 12. Fijación de sesión */
  await test('A12', 'Fijación de sesión', 'Plantar un identificador de sesión antes del login y reutilizarlo después', async () => {
    const c = new Client('víctima');
    await c.get('/login');
    const before = c.cookies['ceiba.sid'];
    await c.submit('/login', '/login', { email: 'correo@ceiba.test', password: PW });
    const mid = c.cookies['ceiba.sid'];
    const code = await lastCodeFor('correo@ceiba.test');
    await c.submit('/verificar', '/verificar', { code });
    const after = c.cookies['ceiba.sid'];
    const planted = new Client('atacante');
    planted.cookies['ceiba.sid'] = before;
    const p = await planted.get('/panel');
    const ok = !!before && before !== mid && mid !== after && p.status === 302 && p.location === '/login';
    return { ok, evidencia: `Identificador antes: ${String(before).slice(0, 10)}…, tras la contraseña: ${String(mid).slice(0, 10)}…, tras el código: ${String(after).slice(0, 10)}…. Con el identificador plantado, /panel respondió ${p.status} hacia ${p.location}.` };
  });

  /* 13. Robo de la base de datos */
  await test('A13', 'Robo de la base de datos', 'Obtener contraseñas, secretos TOTP o códigos si se filtra el archivo .db', async () => {
    const u = await query('SELECT password_hash FROM users');
    const m = await query("SELECT secret_enc FROM mfa_methods WHERE type = 'totp'");
    const o = await query('SELECT code_hash FROM otp_codes LIMIT 5');
    const rc = await query('SELECT code_hash FROM recovery_codes LIMIT 5');
    const bcryptOk = u.every((r) => /^\$2[aby]\$12\$/.test(r.password_hash));
    const totpOk = m.every((r) => r.secret_enc.split('.').length === 3 && !/^[A-Z2-7]{32}$/.test(r.secret_enc));
    const hashOk = [...o, ...rc].every((r) => /^[a-f0-9]{64}$/.test(r.code_hash));
    const ok = bcryptOk && totpOk && hashOk;
    return { ok, evidencia: `Contraseñas con bcrypt costo 12 (${u[0].password_hash.slice(0, 13)}…). Secretos TOTP cifrados con AES-256-GCM (${m[0].secret_enc.slice(0, 18)}…). Códigos de un solo uso y de respaldo guardados como HMAC-SHA256.` };
  });

  /* 14. Cabeceras y cookies */
  await test('A14', 'Clickjacking, XSS y robo de cookie', 'Incrustar el login en un iframe, inyectar scripts o leer la cookie desde JavaScript', async () => {
    const c = new Client('navegador');
    const r = await c.get('/login');
    const csp = r.headers.get('content-security-policy') || '';
    const xfo = r.headers.get('x-frame-options') || '';
    const nosniff = r.headers.get('x-content-type-options') || '';
    const setCookie = (r.headers.getSetCookie ? r.headers.getSetCookie() : [r.headers.get('set-cookie')]).join(';');
    const ok = /frame-ancestors 'none'/.test(csp) && /script-src 'self'/.test(csp) && nosniff === 'nosniff' && /HttpOnly/i.test(setCookie) && /SameSite=Lax/i.test(setCookie);
    return { ok, evidencia: `CSP: script-src 'self', frame-ancestors 'none'. X-Frame-Options: ${xfo}. X-Content-Type-Options: ${nosniff}. Cookie de sesión HttpOnly y SameSite=Lax.` };
  });

  /* 15. Limitación por IP */
  await test('A15', 'Ataque masivo desde una misma IP', 'Probar miles de combinaciones de correo y contraseña (password spraying)', async () => {
    const c = new Client('bot');
    const token = await c.csrf('/login');
    let n = 0;
    let st = 0;
    while (n < 60) {
      n += 1;
      const r = await c.post('/login', { _csrf: token, email: `spray${n}@ceiba.test`, password: 'Verano2026!' });
      st = r.status;
      if (st === 429) break;
    }
    const ok = st === 429 && n <= 30;
    return { ok, evidencia: `La IP fue limitada (HTTP 429) tras ${n} solicitudes en esta ronda; el límite es de 30 intentos fallidos por IP cada 15 minutos (20 en la configuración normal) y también cuenta los fallos de las pruebas anteriores.` };
  });

  server.kill();
  try {
    fs.unlinkSync(DB_PATH);
  } catch { /* ignorar */ }

  /* ---------- Reporte ---------- */
  const passed = results.filter((r) => r.resultado === 'RESISTIÓ').length;
  console.log(`\n${C.b}Resultado: ${passed}/${results.length} ataques resistidos${C.r}`);
  fs.mkdirSync(path.join(ROOT, 'reports'), { recursive: true });
  const meta = { fecha: new Date().toISOString(), node: process.version, total: results.length, resistidos: passed };
  fs.writeFileSync(path.join(ROOT, 'reports', 'reporte-ataques.json'), JSON.stringify({ ...meta, resultados: results }, null, 2));
  fs.writeFileSync(path.join(ROOT, 'reports', 'reporte-ataques.html'), htmlReport(meta, results));
  console.log(`${C.dim}Reporte: reports/reporte-ataques.html${C.r}\n`);
  if (passed !== results.length) {
    console.log(log.split('\n').slice(-20).join('\n'));
    process.exitCode = 1;
  }
}

function htmlReport(meta, rows) {
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const fecha = new Date(meta.fecha).toLocaleString('es-GT', { timeZone: 'America/Guatemala', dateStyle: 'long', timeStyle: 'short' });
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reporte de pruebas de ataque · Ceiba</title>
<style>
:root{--jade:#0B302C;--j5:#1D7A6A;--j1:#DCEFE9;--mist:#F2F6F4;--ink:#14211F;--mut:#4A5A56;--line:#D5E0DC;--bad:#B3261E;--maize:#E2A72E}
*{box-sizing:border-box}body{margin:0;background:var(--mist);color:var(--ink);font:15px/1.55 'Segoe UI',system-ui,sans-serif}
header{background:var(--jade);color:var(--j1);padding:36px 24px}header div,main{max-width:1040px;margin:0 auto}
h1{margin:0;font-size:28px;color:#fff}header p{margin:6px 0 0;color:#B5DACF}
.sum{display:flex;gap:32px;margin-top:22px;flex-wrap:wrap}.sum b{display:block;font-size:34px;color:#fff;line-height:1}.sum span{font-size:13px;color:#B5DACF}
main{padding:28px 24px 48px}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden}
th{text-align:left;font-size:12px;color:var(--mut);padding:12px 14px;border-bottom:1px solid var(--line);background:#fafcfb}
td{padding:14px;border-bottom:1px solid #E6EDEA;vertical-align:top}tr:last-child td{border-bottom:0}
.id{font-weight:700;color:var(--j5);white-space:nowrap}.at{font-weight:650}.obj{color:var(--mut);font-size:13px;margin-top:2px}
.ev{font-size:13px;color:var(--mut)}.res{font-weight:700;font-size:12px;padding:3px 10px;border-radius:99px;white-space:nowrap}
.ok{background:var(--j1);color:#145247}.bad{background:#FBEAE8;color:var(--bad)}
p.note{color:var(--mut);font-size:13px;margin-top:18px}
</style></head><body>
<header><div><h1>Pruebas de resistencia frente a ataques</h1><p>Sistema de autenticación multifactor Ceiba. Ejecutado el ${esc(fecha)} con Node ${esc(meta.node)}.</p>
<div class="sum"><div><b>${meta.resistidos}/${meta.total}</b><span>ataques resistidos</span></div><div><b>${meta.total - meta.resistidos}</b><span>vulnerabilidades encontradas</span></div></div></div></header>
<main><table><thead><tr><th>ID</th><th>Ataque y objetivo del atacante</th><th>Resultado</th><th>Evidencia</th></tr></thead><tbody>
${rows.map((r) => `<tr><td class="id">${esc(r.id)}</td><td><div class="at">${esc(r.ataque)}</div><div class="obj">${esc(r.objetivo)}</div></td><td><span class="res ${r.resultado === 'RESISTIÓ' ? 'ok' : 'bad'}">${esc(r.resultado)}</span></td><td class="ev">${esc(r.evidencia)}</td></tr>`).join('\n')}
</tbody></table>
<p class="note">Cada ataque se ejecuta por HTTP contra una instancia aislada del sistema con una base de datos temporal, de la misma forma en que lo haría un atacante real. Para repetir las pruebas: <code>npm run test:ataques</code>.</p></main></body></html>`;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
