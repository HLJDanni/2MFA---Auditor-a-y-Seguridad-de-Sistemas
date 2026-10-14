'use strict';
const express = require('express');
const db = require('../db');
const users = require('../services/users');
const audit = require('../services/audit');
const { requireAuth, requireAdmin } = require('../middleware/security');

const router = express.Router();

router.get('/admin', requireAuth, requireAdmin, (req, res) => {
  // Eventos por hora en las últimas 12 horas para el gráfico
  const now = Date.now();
  const hours = [];
  for (let i = 11; i >= 0; i--) {
    const from = now - (i + 1) * 3600000;
    const to = now - i * 3600000;
    const count = (events) =>
      db.get(`SELECT COUNT(*) AS n FROM audit_log WHERE created_at > ? AND created_at <= ? AND event IN (${events.map(() => '?').join(',')})`, [from, to, ...events]).n;
    hours.push({
      label: new Intl.DateTimeFormat('es-GT', { hour: 'numeric', hourCycle: 'h23', timeZone: 'America/Guatemala' }).format(new Date(to)) + ' h',
      ok: count(['mfa_success', 'mfa_trusted_device']),
      blocked: count(['login_password_fail', 'login_unknown_user', 'mfa_fail', 'totp_replay', 'account_locked', 'rate_limited', 'csrf_blocked', 'login_blocked_locked', 'mfa_session_killed']),
    });
  }
  res.render('admin', {
    title: 'Monitoreo de seguridad',
    stats: users.stats(),
    list: users.list(),
    events: audit.recent(50),
    label: audit.label,
    hours,
  });
});

router.post('/admin/usuarios/:id/desbloquear', requireAuth, requireAdmin, (req, res) => {
  const u = users.findById(parseInt(req.params.id, 10));
  if (u) {
    users.unlock(u.id);
    audit.log(req, { userId: u.id, email: u.email, event: 'account_unlocked', detail: `por ${req.user.email}` });
    req.flash('ok', `Desbloqueamos la cuenta de ${u.name}.`);
  }
  res.redirect('/admin');
});

module.exports = router;
