const db = require('../db');

const userModel = {
  // Buscar un usuario por su correo
  findByEmail: (email, callback) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
      callback(err, row);
    });
  },

  // Crear un usuario nuevo (¡Aquí guardamos el dob!)
  createUser: (userData, callback) => {
    const { name, dob, email, password } = userData;
    db.run(
      'INSERT INTO users (name, dob, email, password) VALUES (?, ?, ?, ?)',
      [name, dob, email, password],
      function (err) {
        callback(err, this.lastID);
      }
    );
  },

  // Buscar un usuario por su ID
  findById: (id, callback) => {
    db.get('SELECT id, name, email, dob, created_at FROM users WHERE id = ?', [id], (err, row) => {
      callback(err, row);
    });
  }
};

module.exports = userModel;