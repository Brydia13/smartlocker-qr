// src/routes/lockers.js
const express = require('express');
const router = express.Router();
const db = require('../db');
const { sendEmail } = require('../mail');


// 🔹 GET /api/lockers → lista todos los lockers
router.get('/', (req, res) => {
  db.all('SELECT id, code, assigned_user_id, status, created_at FROM lockers', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ lockers: rows });
  });
});

// 🔹 POST /api/lockers → crear locker nuevo
router.post('/', (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'code requerido' });

  db.run('INSERT INTO lockers (code, status) VALUES (?, ?)', [code, 'free'], function (err) {
    if (err) return res.status(500).json({ error: 'DB error o code duplicado' });
    res.json({ ok: true, id: this.lastID, code });
  });
});

// 🔹 POST /api/lockers/assign → asignar locker a usuario
router.post('/assign', (req, res) => {
  const { lockerId, userId } = req.body;
  if (!lockerId || !userId) return res.status(400).json({ error: 'Faltan datos' });

  db.run(
    'UPDATE lockers SET assigned_user_id = ?, status = ? WHERE id = ?',
    [userId, 'occupied', lockerId],
    function (err) {
      if (err) return res.status(500).json({ error: 'DB error' });

      // Registrar acción en el log
      db.run(
        'INSERT INTO access_logs (user_id, locker_id, action, success) VALUES (?, ?, ?, ?)',
        [userId, lockerId, 'assign', 1]
      );

      return res.json({ ok: true, lockerId, userId });
    }
  );
});

// 🔹 GET /api/lockers/my-locker?token=...
router.get('/my-locker', (req, res) => {
  const token = req.query.token || req.headers['x-access-token'];
  if (!token) return res.status(400).json({ error: 'Token requerido' });

  db.get('SELECT user_id FROM sessions WHERE token = ?', [token], (err, session) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!session) return res.status(401).json({ error: 'Sesión inválida' });

    db.get(
      'SELECT id, code, assigned_user_id, status FROM lockers WHERE assigned_user_id = ?',
      [session.user_id],
      (err, locker) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        if (!locker) return res.json({ locker: null });
        return res.json({ locker });
      }
    );
  });
});

// 🔹 POST /api/open-with-qr →(Mantenimiento Sprint 2)
router.post('/open-with-qr', (req, res) => {
  const { userId, token } = req.body;

  // Validación de entrada 
  if (!userId || !token) {
    return res.status(400).json({ ok: false, error: 'Datos incompletos' });
  }

  // Verificar sesión primero
  db.get('SELECT * FROM sessions WHERE user_id = ? AND token = ?', [userId, token], (err, session) => {
    if (err) return res.status(500).json({ ok: false, error: 'Error de DB en sesión' });
    if (!session) return res.status(401).json({ ok: false, error: 'Sesión inválida' });

    // Verificar locker 
    db.get('SELECT * FROM lockers WHERE assigned_user_id = ?', [userId], (err, locker) => {
      if (err) return res.status(500).json({ ok: false, error: 'Error de DB en lockers' });
      if (!locker) return res.status(404).json({ ok: false, error: 'No hay locker asignado' });

      // Simular apertura 
      db.run('UPDATE lockers SET status = ? WHERE id = ?', ['open', locker.id], (err) => {
        if (err) return res.status(500).json({ ok: false, error: 'Error al abrir locker' });

        // --- INICIO DE PROCESOS POST-APERTURA ---

        // Notificación por Correo (Mantenimiento Correctivo)
        db.get('SELECT email, name FROM users WHERE id = ?', [userId], async (err, user) => {
          if (!err && user) {
            try {
              const html = `
                <h2>Locker abierto correctamente</h2>
                <p>Hola ${user.name},</p>
                <p>Se registró la apertura del locker <strong>${locker.code}</strong>.</p>
                <p>Fecha: ${new Date().toLocaleString()}</p>
                <br><small>SmartLock System</small>`;
              // Usamos try/catch para que si falla el correo, no afecte la respuesta del usuario
              await sendEmail(user.email, 'Notificación de apertura', html);
            } catch (mailError) {
              console.error("Fallo envío de email, pero el locker se abrió:", mailError);
            }
          }
        });

        // Cierre automático tras 3 segundos
        setTimeout(() => {
          db.run('UPDATE lockers SET status = ? WHERE id = ?', ['occupied', locker.id]);
        }, 3000);

        // Registro en Logs
        db.run('INSERT INTO access_logs (user_id, locker_id, action, success) VALUES (?, ?, ?, ?)',
          [userId, locker.id, 'open', 1]);

        // Respuesta final al cliente
        res.json({
          ok: true,
          message: `Locker ${locker.code} abierto (simulado)`,
          lockerId: locker.id
        });
      });
    });
  });
});

// 🔹 GET /api/lockers/logs → historial de accesos
router.get('/logs', (req, res) => {
  db.all(
    `SELECT 
        access_logs.id,
        users.name AS user_name,
        lockers.code AS locker_code,
        access_logs.action,
        access_logs.success,
        access_logs.created_at
     FROM access_logs
     LEFT JOIN users ON access_logs.user_id = users.id
     LEFT JOIN lockers ON access_logs.locker_id = lockers.id
     ORDER BY access_logs.created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'DB error al obtener logs' });
      res.json({ logs: rows });
    }
  );
});

module.exports = router;

