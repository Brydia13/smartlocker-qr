// src/routes/lockers.js
const express = require("express");
const router = express.Router();
const db = require("../db");
const { sendEmail } = require("../mail");

// 🔹 GET /api/lockers → lista todos los lockers con nombres de usuario
router.get('/', (req, res) => {
  const query = `
    SELECT 
      lockers.id, 
      lockers.code, 
      lockers.assigned_user_id, 
      lockers.status, 
      lockers.created_at,
      users.name AS user_name
    FROM lockers
    LEFT JOIN users ON lockers.assigned_user_id = users.id
  `;
  db.all(query, [], (err, rows) => {
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

// 🔹 POST /api/open-with-qr → Escaneo de QR (Usuario o ESP32)
router.post('/open-with-qr', (req, res) => {
  const { userId, token } = req.body;

  // Validación de entrada 
  if (!userId || !token) {
    return res.status(400).json({ ok: false, error: "Datos incompletos" });
  }

  // 1. Verificar sesión primero
  db.get('SELECT * FROM sessions WHERE user_id = ? AND token = ?', [userId, token], (err, session) => {
    if (err) return res.status(500).json({ ok: false, error: 'Error de DB en sesión' });
    if (!session) return res.status(401).json({ ok: false, error: 'Sesión inválida' });

    // 2. Verificar si ya tiene un locker asignado
    db.get('SELECT * FROM lockers WHERE assigned_user_id = ?', [userId], (err, locker) => {
      if (err) return res.status(500).json({ ok: false, error: 'Error de DB en lockers' });

      if (locker) {
        // --- CASO A: YA TIENE LOCKER ---
        openLocker(locker, userId, res);
      } else {
        // --- CASO B: NO TIENE LOCKER -> AUTO-ASIGNACIÓN (Self-Service) ---
        db.get('SELECT * FROM lockers WHERE status = ? LIMIT 1', ['free'], (err, freeLocker) => {
          if (err) return res.status(500).json({ ok: false, error: 'Error buscando locker libre' });
          if (!freeLocker) {
            return res.status(404).json({ ok: false, error: 'No hay lockers libres disponibles' });
          }

          // Asignar el locker al usuario
          db.run(
            'UPDATE lockers SET assigned_user_id = ?, status = ? WHERE id = ?',
            [userId, 'occupied', freeLocker.id],
            (err) => {
              if (err) return res.status(500).json({ ok: false, error: 'Error al auto-asignar locker' });
              
              // Abrir el locker recién asignado
              openLocker(freeLocker, userId, res, true);
            }
          );
        });
      }
    });
  });
});

/**
 * Función auxiliar para abrir el locker y manejar logs/emails
 */
function openLocker(locker, userId, res, isFirstTime = false) {
  // Simular apertura (Estado 'open' por 3 segundos)
  db.run('UPDATE lockers SET status = ? WHERE id = ?', ['open', locker.id], (err) => {
    if (err) return res.status(500).json({ ok: false, error: 'Error al abrir locker' });

    // Enviar Correo de Notificación
    db.get('SELECT email, name FROM users WHERE id = ?', [userId], async (err, user) => {
      if (!err && user) {
        try {
          const html = `
            <h2>Locker abierto correctamente</h2>
            <p>Hola ${user.name},</p>
            <p>Se registró la apertura del locker <strong>${locker.code}</strong>.</p>
            <p>${isFirstTime ? '<b>¡Bienvenido!</b> Este locker te ha sido asignado automáticamente.' : 'Vía escaneo de código QR.'}</p>
            <p>Fecha: ${new Date().toLocaleString()}</p>
            <br><small>SmartLock System</small>`;
          await sendEmail(user.email, isFirstTime ? 'Bienvenida y Apertura' : 'Notificación de apertura', html);
        } catch (mailError) {
          console.error("Fallo envío de email:", mailError);
        }
      }
    });

    // Cierre automático tras 3 segundos
    setTimeout(() => {
      db.run('UPDATE lockers SET status = ? WHERE id = ?', ['occupied', locker.id]);
    }, 3000);

    // Registro en Logs
    db.run('INSERT INTO access_logs (user_id, locker_id, action, success) VALUES (?, ?, ?, ?)',
      [userId, locker.id, isFirstTime ? 'self_assign' : 'open', 1]);

    // Respuesta al cliente
    res.json({
      ok: true,
      message: isFirstTime 
        ? `Locker ${locker.code} asignado y abierto automáticamente.` 
        : `Locker ${locker.code} abierto (simulado)`,
      lockerId: locker.id,
      newlyAssigned: isFirstTime
    });
  });
}

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
      if (err)
        return res.status(500).json({ error: "DB error al obtener logs" });

      res.json({ logs: rows });
    },
  );
});

// 🔹 GET /api/lockers/my-locker → obtener locker del usuario actual
router.get('/my-locker', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token requerido' });

  // 1. Buscar la sesión para obtener el userId
  db.get('SELECT user_id FROM sessions WHERE token = ?', [token], (err, session) => {
    if (err || !session) return res.status(401).json({ error: 'Sesión inválida' });

    // 2. Buscar el locker asignado a ese user_id
    db.get('SELECT * FROM lockers WHERE assigned_user_id = ?', [session.user_id], (err, locker) => {
      if (err) return res.status(500).json({ error: 'Error de DB' });
      res.json({ locker: locker || null });
    });
  });
});

// 🔹 GET /api/admin/stats → Obtener métricas generales para el panel
router.get('/admin/stats', (req, res) => {
  const stats = {};
  
  db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
    stats.totalUsers = row ? row.count : 0;
    
    db.get('SELECT COUNT(*) as total, SUM(CASE WHEN status="free" THEN 1 ELSE 0 END) as free FROM lockers', [], (err, row) => {
      stats.totalLockers = row ? row.total : 0;
      stats.freeLockers = row ? row.free : 0;
      stats.occupiedLockers = stats.totalLockers - stats.freeLockers;
      
      db.get('SELECT COUNT(*) as count FROM access_logs', [], (err, row) => {
        stats.totalLogs = row ? row.count : 0;
        res.json(stats);
      });
    });
  });
});

// 🔹 DELETE /api/lockers/:id → Eliminar un locker
router.delete('/:id', (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM lockers WHERE id = ?', [id], (err) => {
    if (err) return res.status(500).json({ error: 'Error al eliminar locker' });
    res.json({ ok: true, message: 'Locker eliminado' });
  });
});

// 🔹 POST /api/lockers/reset/:id → Liberar un locker manualmente
router.post('/reset/:id', (req, res) => {
  const { id } = req.params;
  db.run(
    'UPDATE lockers SET assigned_user_id = NULL, status = "free" WHERE id = ?',
    [id],
    (err) => {
      if (err) return res.status(500).json({ error: 'Error al resetear locker' });
      res.json({ ok: true, message: 'Locker liberado correctamente' });
    }
  );
});

module.exports = router;
