'use strict';
/**
 * Envío de correos (SMTP con Nodemailer) y SMS (API REST de Twilio).
 * Si no hay credenciales configuradas, el mensaje se guarda en la "bandeja de
 * demostración" (tabla outbox) para poder presentar el sistema sin servicios externos.
 */
const nodemailer = require('nodemailer');
const config = require('../config');
const db = require('../db');

let transporter = null;
if (config.smtp.host) {
  transporter = nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.secure,
    auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined,
  });
}

function saveOutbox(channel, destination, subject, body, delivered) {
  db.run('INSERT INTO outbox (channel, destination, subject, body, delivered, created_at) VALUES (?,?,?,?,?,?)', [
    channel,
    destination,
    subject,
    body,
    delivered,
    Date.now(),
  ]);
}

function emailHtml(title, lines, code) {
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  return `<!doctype html><html><body style="margin:0;background:#EEF3F1;font-family:Segoe UI,Arial,sans-serif;color:#14211F">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:32px 12px"><tr><td align="center">
  <table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:14px;overflow:hidden">
    <tr><td style="background:#0E3B36;color:#DCEFE9;padding:20px 28px;font-size:18px;font-weight:700">${esc(config.appName)}</td></tr>
    <tr><td style="padding:28px">
      <h1 style="font-size:20px;margin:0 0 12px">${esc(title)}</h1>
      ${lines.map((l) => `<p style="margin:0 0 12px;line-height:1.55;color:#3C4B48">${esc(l)}</p>`).join('')}
      ${code ? `<p style="font-family:Consolas,monospace;font-size:32px;letter-spacing:8px;font-weight:700;background:#DCEFE9;color:#0E3B36;border-radius:10px;padding:14px 0;text-align:center;margin:20px 0">${esc(code)}</p>` : ''}
      <p style="margin:20px 0 0;font-size:13px;color:#6B7A76">Si no fuiste tú, cambia tu contraseña de inmediato. Nunca te pediremos este código por teléfono.</p>
    </td></tr>
  </table></td></tr></table></body></html>`;
}

async function sendEmail(to, subject, lines, code = null) {
  const text = lines.join('\n\n') + (code ? `\n\nCódigo: ${code}` : '');
  let delivered = 'simulado';
  if (transporter) {
    try {
      await transporter.sendMail({ from: config.smtp.from, to, subject, text, html: emailHtml(subject, lines, code) });
      delivered = 'enviado';
    } catch (err) {
      console.error('[correo] error SMTP:', err.message);
      delivered = 'error';
    }
  }
  if (config.demoMode || delivered !== 'enviado') saveOutbox('email', to, subject, text, delivered);
  if (delivered !== 'enviado') console.log(`\n✉  [correo ${delivered}] para ${to} — ${subject}${code ? ` — código ${code}` : ''}`);
  return delivered;
}

async function sendSms(to, body) {
  let delivered = 'simulado';
  const { sid, token, from } = config.twilio;
  if (sid && token && from && typeof fetch === 'function') {
    try {
      const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
        method: 'POST',
        headers: {
          Authorization: 'Basic ' + Buffer.from(`${sid}:${token}`).toString('base64'),
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ To: to, From: from, Body: body }),
      });
      delivered = res.ok ? 'enviado' : 'error';
      if (!res.ok) console.error('[sms] Twilio respondió', res.status, await res.text());
    } catch (err) {
      console.error('[sms] error:', err.message);
      delivered = 'error';
    }
  }
  if (config.demoMode || delivered !== 'enviado') saveOutbox('sms', to, null, body, delivered);
  if (delivered !== 'enviado') console.log(`\n📱 [sms ${delivered}] para ${to} — ${body}`);
  return delivered;
}

function outbox(limit = 40) {
  return db.all('SELECT * FROM outbox ORDER BY id DESC LIMIT ?', [limit]);
}

module.exports = { sendEmail, sendSms, outbox, emailConfigured: () => !!transporter, smsConfigured: () => !!config.twilio.sid };
