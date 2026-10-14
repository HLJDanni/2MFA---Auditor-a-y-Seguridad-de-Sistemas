'use strict';
// Borra la base de datos para empezar la demostración desde cero (se recrea al iniciar).
const fs = require('fs');
const path = require('path');
const db = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'ceiba.db');
if (fs.existsSync(db)) fs.unlinkSync(db);
console.log('Base de datos eliminada. Ejecuta "npm start" para recrearla con los usuarios de demostración.');
