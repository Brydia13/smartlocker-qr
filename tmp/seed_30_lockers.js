const db = require('../src/db');

/**
 * Script para sembrar (seed) 30 lockers iniciales en la base de datos.
 * Utiliza INSERT OR IGNORE para no duplicar si ya existen.
 */
async function seedLockers() {
  console.log('🚀 Iniciando carga de 30 lockers...');

  for (let i = 1; i <= 30; i++) {
    const code = `LCK-${i.toString().padStart(2, '0')}`;
    
    // Insertamos el locker con estado 'free' si el código no existe
    await new Promise((resolve, reject) => {
      db.run(
        'INSERT OR IGNORE INTO lockers (code, status) VALUES (?, ?)',
        [code, 'free'],
        (err) => {
          if (err) {
            console.error(`❌ Error al crear ${code}:`, err.message);
            reject(err);
          } else {
            resolve();
          }
        }
      );
    });
  }

  console.log('✅ ¡Carga de 30 lockers completada con éxito!');
  process.exit(0);
}

seedLockers();
