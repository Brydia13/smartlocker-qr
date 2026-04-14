// __tests__/userModel.test.js
const dbMock = require('./mocks/db.mock');

// Mockear el módulo db antes de requerir userModel
jest.mock('../src/db', () => require('./mocks/db.mock'));

const userModel = require('../src/models/userModel');

describe('userModel - Validaciones e integraciones críticas', () => {
  
  beforeEach(() => {
    // Limpiar datos y mocks antes de cada test
    dbMock.data = {
      users: [],
      lockers: [],
      sessions: [],
      access_logs: [],
      logs: []
    };
    jest.clearAllMocks();
  });

  describe('createUser - Validación de email único', () => {
    it('debería rechazar usuario con email duplicado', (done) => {
      const userData = {
        name: 'Juan',
        email: 'juan@example.com',
        password: 'hash123'
      };

      // Crear primer usuario
      userModel.createUser(userData, (err) => {
        expect(err).toBeNull();

        // Intentar crear usuario con mismo email
        userModel.createUser(userData, (err) => {
          expect(err).toBeDefined();
          expect(err.message).toContain('UNIQUE constraint failed');
          done();
        });
      });
    });

    it('debería permitir múltiples usuarios con emails diferentes', (done) => {
      const user1 = { name: 'Juan', email: 'juan@example.com', password: 'hash1' };
      const user2 = { name: 'María', email: 'maria@example.com', password: 'hash2' };

      userModel.createUser(user1, (err1) => {
        expect(err1).toBeNull();
        
        userModel.createUser(user2, (err2) => {
          expect(err2).toBeNull();
          expect(dbMock.data.users.length).toBe(2);
          done();
        });
      });
    });
  });

  describe('findByEmail - Búsqueda y recuperación', () => {
    it('debería encontrar usuario por email', (done) => {
      const userData = { name: 'Carlos', email: 'carlos@example.com', password: 'pass123' };

      userModel.createUser(userData, () => {
        userModel.findByEmail('carlos@example.com', (err, user) => {
          expect(err).toBeNull();
          expect(user).toBeDefined();
          expect(user.email).toBe('carlos@example.com');
          expect(user.name).toBe('Carlos');
          done();
        });
      });
    });

    it('debería retornar null si no encuentra usuario', (done) => {
      userModel.findByEmail('noexiste@example.com', (err, user) => {
        expect(err).toBeNull();
        expect(user).toBeNull();
        done();
      });
    });

    it('debería retornar la contraseña hasheada', (done) => {
      const userData = {
        name: 'Test',
        email: 'test@example.com',
        password: '$2b$10$hashedpassword'
      };

      userModel.createUser(userData, () => {
        userModel.findByEmail('test@example.com', (err, user) => {
          expect(user.password).toBe('$2b$10$hashedpassword');
          done();
        });
      });
    });
  });

  describe('findById - Búsqueda por ID', () => {
    it('debería retornar null si usuario no existe', (done) => {
      userModel.findById(999, (err, user) => {
        expect(err).toBeNull();
        expect(user).toBeNull();
        done();
      });
    });

    it('debería llamar a db.get con el ID correcto', (done) => {
      userModel.findById(123, () => {
        // Verificar que se llamó a db.get con el ID
        expect(dbMock.get).toHaveBeenCalledWith(
          expect.stringContaining('WHERE id = ?'),
          [123],
          expect.any(Function)
        );
        done();
      });
    });
  });

  describe('Protección de datos sensibles', () => {
    it('findById no debería retornar la contraseña', (done) => {
      userModel.findById(1, (err, user) => {
        if (user) {
          // El SELECT en findById no incluye password
          expect(user).not.toHaveProperty('password');
        }
        done();
      });
    });
  });

  describe('Integración con base de datos', () => {
    it('debería llamar a db.run para INSERT', (done) => {
      userModel.createUser({
        name: 'Test',
        email: 'test@example.com',
        password: 'hash'
      }, () => {
        expect(dbMock.run).toHaveBeenCalled();
        done();
      });
    });

    it('debería llamar a db.get para SELECT en findByEmail', (done) => {
      userModel.findByEmail('test@example.com', () => {
        expect(dbMock.get).toHaveBeenCalled();
        done();
      });
    });
  });
});

