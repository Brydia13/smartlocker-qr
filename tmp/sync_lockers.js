const db = require('../src/db');

/**
 * Script de Sincronización Total - SmartLock
 * 1. Limpia lockers.
 * 2. Crea exactamente 30 lockers (LCK-01 al LCK-30).
 * 3. Asigna los primeros 11 lockers a los usuarios reales.
 */
async function syncLockers() {
  console.log('🧹 Iniciando limpieza y sincronización profunda...');

  try {
    // 1. Obtener todos los usuarios reales
    const users = await new Promise((resolve, reject) => {
      db.all('SELECT id FROM users ORDER BY id ASC', [], (err, rows) => {
        if (err) reject(err); else resolve(rows);
      });
    });
    console.log(`👤 Usuarios encontrados: ${users.length}`);

    // 2. Limpiar la tabla de lockers por completo
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM lockers', (err) => {
        if (err) reject(err); else resolve();
      });
    });
    console.log('🗑️ Tabla de lockers vaciada.');

    // 3. Crear los 30 lockers fijos y asignar a los usuarios
    for (let i = 1; i <= 30; i++) {
      const code = `LCK-${i.toString().padStart(2, '0')}`;
      const userId = users[i - 1] ? users[i - 1].id : null;
      const status = userId ? 'occupied' : 'free';

      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO lockers (code, assigned_user_id, status) VALUES (?, ?, ?)',
          [code, userId, status],
          (err) => {
            if (err) reject(err); else resolve();
          }
        );
      });
    }
    console.log('✅ 30 lockers creados y sincronizados.');

    // 4. Limpiar los logs de "lockers fantasmas" para que la actividad reciente sea limpia (Opcional pero recomendado)
    // No borramos logs de usuarios, solo los que tienen códigos de locker inexistentes si fuera necesario.

    console.log('\n--- RESULTADO FINAL ---');
    console.log(`Totales: 30`);
    console.log(`Ocupados: ${users.length}`);
    console.log(`Libres: ${30 - users.length}`);
    console.log('-----------------------');

  } catch (error) {
    console.error('❌ Error crítico durante la sincronización:', error);
  } finally {
    process.exit(0);
  }
}

syncLockers();
