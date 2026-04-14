// src/routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
const userModel = require('../models/userModel');
const db = require('../db');
const { randomBytes } = require('node:crypto');
const { sendEmail } = require('../mail');

const SALT_ROUNDS = 10;

// Promisify db helpers
function dbGet(sql, params) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

function dbRun(sql, params) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function findByEmail(email) {
  return new Promise((resolve, reject) => {
    userModel.findByEmail(email, (err, row) => (err ? reject(err) : resolve(row)));
  });
}

function createUser(userData) {
  return new Promise((resolve, reject) => {
    userModel.createUser(userData, (err, id) => (err ? reject(err) : resolve(id)));
  });
}

// POST /api/register
router.post('/register', async (req, res) => {
  const { name, dob, email, password } = req.body;

  if (!name || !dob || !email || !password) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
  }

  try {
    const existing = await findByEmail(email);
    if (existing) return res.status(400).json({ error: 'El correo ya está registrado' });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const newUserId = await createUser({ name, dob, email, password: hash });

    const token = randomBytes(24).toString('hex');
    const payload = JSON.stringify({ userId: newUserId, token });
    const qr = await QRCode.toDataURL(payload, { errorCorrectionLevel: 'H' });

    await dbRun('INSERT INTO sessions (user_id, token) VALUES (?, ?)', [newUserId, token]).catch((err) =>
      console.error('Error creando sesión:', err)
    );

    try {
      await sendEmail(
        email,
        'Tu acceso SmartLock QR 🔐',
        `<h2>Hola ${name} 👋</h2>
         <p>Gracias por registrarte en <b>SmartLock</b>.</p>
         <p>Tu código QR está adjunto como archivo.</p>
         <p>⚠ No lo compartas con nadie.</p>`,
        qr
      );
    } catch (mailError) {
      console.error('Error al enviar el correo con QR:', mailError);
    }

    return res.json({ ok: true, message: 'Usuario creado y correo enviado' });
  } catch (err) {
    console.error('Error en /register:', err);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// POST /api/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Faltan credenciales' });

  try {
    const user = await findByEmail(email);
    if (!user) return res.status(400).json({ error: 'Credenciales inválidas' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Credenciales inválidas' });

    const token = randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();

    await dbRun(
      'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)',
      [user.id, token, expiresAt]
    );

    const payload = JSON.stringify({ userId: user.id, token });
    const url = await QRCode.toDataURL(payload, { errorCorrectionLevel: 'H' });

    return res.json({ token, qr: url, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error('Error en /login:', err);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// GET /api/users → Listar todos los usuarios
router.get('/users', (req, res) => {
  db.all('SELECT id, name, email, dob, created_at FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Error al obtener usuarios' });
    res.json({ users: rows });
  });
});

// DELETE /api/users/:id → Eliminar un usuario y limpiar sus datos
router.delete('/users/:id', (req, res) => {
  const { id } = req.params;

  // 1. Liberar el locker asignado (si tiene uno)
  db.run('UPDATE lockers SET assigned_user_id = NULL, status = "free" WHERE assigned_user_id = ?', [id]);

  // 2. Eliminar sesiones
  db.run('DELETE FROM sessions WHERE user_id = ?', [id]);

  // 3. Eliminar usuario
  db.run('DELETE FROM users WHERE id = ?', [id], function (err) {
    if (err) return res.status(500).json({ error: 'Error al eliminar usuario' });
    res.json({ ok: true, message: 'Usuario eliminado correctamente' });
  });
});

module.exports = router;
