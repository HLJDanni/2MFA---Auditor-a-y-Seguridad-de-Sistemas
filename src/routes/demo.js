'use strict';
/**
 * Bandeja de demostración: muestra los correos y SMS "enviados" cuando no hay
 * SMTP ni Twilio configurados. SOLO existe con DEMO_MODE=true; en producción se desactiva.
 */
const express = require('express');
const notifier = require('../services/notifier');

const router = express.Router();

router.get('/demo/bandeja', (req, res) => {
  const items = notifier.outbox(40);
  res.render('outbox', {
    title: 'Bandeja de demostración',
    emails: items.filter((i) => i.channel === 'email'),
    sms: items.filter((i) => i.channel === 'sms'),
    emailReal: notifier.emailConfigured(),
    smsReal: notifier.smsConfigured(),
  });
});

router.get('/demo/bandeja.json', (req, res) => {
  const last = notifier.outbox(1)[0];
  res.json({ lastId: last ? last.id : 0 });
});

module.exports = router;
