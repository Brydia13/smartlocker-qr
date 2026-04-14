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
        if (err) {
          return callback(err);
        }
        callback(null, { id: this.lastID, name, dob, email });
      }
    );
  }
};

module.exports = userModel;