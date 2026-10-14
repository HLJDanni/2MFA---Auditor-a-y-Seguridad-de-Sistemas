'use strict';
/** Usuarios de demostración (solo si la base está vacía y DEMO_MODE=true). */
const config = require('./config');
const db = require('./db');
const users = require('./services/users');
const mfa = require('./services/mfa');

const DEMO_USERS = [
  { name: 'Administración Ceiba', email: 'admin@ceiba.test', password: 'Jade#Volcan2026', role: 'admin', methods: ['email'] },
  { name: 'Ana Lucía Pérez', email: 'ana@ceiba.test', phone: '+50255550101', password: 'Quetzal#Lago2026', role: 'usuario', methods: ['email', 'sms'] },
];

async function run() {
  if (!config.demoMode) return;
  if (db.get('SELECT COUNT(*) AS n FROM users').n > 0) return;
  for (const u of DEMO_USERS) {
    const created = await users.create({ name: u.name, email: u.email, phone: u.phone, plainPassword: u.password, role: u.role });
    for (const type of u.methods) mfa.addMethod(created.id, type, { destination: type === 'sms' ? u.phone : u.email });
    mfa.generateRecoveryCodes(created.id);
  }
  console.log('  Usuarios de demostración creados (ver README).');
}

module.exports = { run, DEMO_USERS };
