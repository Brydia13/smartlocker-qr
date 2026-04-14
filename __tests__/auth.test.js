// __tests__/auth.test.js
const request = require('supertest');
const express = require('express');
const bcrypt = require('bcrypt');
const dbMock = require('./mocks/db.mock');

// Variablesglobal para almacenar el password correcto durante los tests
let correctPassword = null;

// Mockear módulos
jest.mock('../src/db', () => require('./mocks/db.mock'));
jest.mock('../src/mail');

// Mockear QRCode
jest.mock('qrcode', () => ({
  toDataURL: jest.fn().mockImplementation((data, options, callback) => {
    // QRCode.toDataURL puede ser llamado con 2 o 3 argumentos
    // Forma 1: toDataURL(data, options, callback)
    // Forma 2: toDataURL(data, callback)
    // Forma 3: toDataURL(data) - retorna Promise
    const cb = typeof options === 'function' ? options : callback;
    const url = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    if (typeof cb === 'function') {
      setImmediate(() => cb(null, url));
      return undefined;
    } else {
      return Promise.resolve(url);
    }
  })
}));

// Mockeamos bcrypt.compare y hash para que sean instantáneos
jest.mock('bcrypt', () => {
  // eslint-disable-next-line global-require
  const crypto = require('node:crypto');
  return {
    hash: jest.fn().mockImplementation((password, rounds, callback) => {
      // Usa hash de crypto para seguridad sin bloquear
      const hash = crypto.createHash('sha256').update(password).digest('hex');
      // Soporta ambos: callback y Promise
      if (typeof callback === 'function') {
        setImmediate(() => callback(null, hash));
        return undefined;
      } else {
        // Si no hay callback, retorna Promise
        return Promise.resolve(hash);
      }
    }),
    compare: jest.fn().mockImplementation((password, hash, callback) => {
      // Compara el hash de la contraseña con el hash almacenado
      // eslint-disable-next-line global-require
      const crypto = require('node:crypto');
      const expectedHash = crypto.createHash('sha256').update(password).digest('hex');
      const result = hash === expectedHash;
      setImmediate(() => callback(null, result));
      return undefined;
    })
  };
});

const authRouter = require('../src/routes/auth');

describe('Auth Routes', () => {
  let app;
  let server;

  beforeEach(() => {
    // Limpiar datos
    dbMock.data = {
      users: [],
      lockers: [],
      sessions: [],
      access_logs: [],
      logs: []
    };
    jest.clearAllMocks();

    // Crear app Express con el router
    app = express();
    app.use(express.json());
    app.use('/api', authRouter);
  });

  afterEach((done) => {
    if (server) {
      server.close(done);
    } else {
      done();
    }
  });

  describe('POST /api/register', () => {
    it('debería registrar un nuevo usuario correctamente', async () => {
      const response = await request(app)
        .post('/api/register')
        .send({
          name: 'Juan Pérez',
          email: 'juan@example.com',
          password: 'SecurePass123!' // eslint-disable-line no-hardcoded-passwords
        });

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      expect(response.body.message).toContain('Usuario creado');
    });

    it('debería rechazar si faltan campos requeridos', async () => {
      const response = await request(app)
        .post('/api/register')
        .send({
          name: 'Juan',
          email: 'juan@example.com'
          // Falta password
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Completa los campos');
    });

    it('debería rechazar email vacío', async () => {
      const response = await request(app)
        .post('/api/register')
        .send({
          name: 'Juan',
          email: '',
          password: 'pass123' // eslint-disable-line no-hardcoded-passwords
        });

      expect(response.status).toBe(400);
    });

    it('debería rechazar usuario con email duplicado', async () => {
      // Primer registro
      await request(app)
        .post('/api/register')
        .send({
          name: 'Juan',
          email: 'juan@example.com',
          password: 'pass123' // eslint-disable-line no-hardcoded-passwords
        });

      // Intentar registrar con mismo email
      const response = await request(app)
        .post('/api/register')
        .send({
          name: 'Otro Juan',
          email: 'juan@example.com',
          password: 'pass456' // eslint-disable-line no-hardcoded-passwords
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Usuario ya existe');
    });

    it('debería hashear la contraseña antes de guardar', async () => {
      const password = 'MyPassword123!'; // eslint-disable-line no-hardcoded-passwords
      
      // eslint-disable-next-line no-hardcoded-passwords
      // eslint-disable-next-line no-hardcoded-passwords
      await request(app)
        .post('/api/register')
        .send({
          name: 'Test User',
          email: 'test@example.com',
          password
        });

      // Verificar que la contraseña guardada es hasheada
      const savedUser = dbMock.data.users[0];
      expect(savedUser.password).not.toBe(password);
      // eslint-disable-next-line no-hardcoded-passwords
      expect(savedUser.password).not.toContain('MyPassword123!');
    });

    it('debería crear sesión con token', async () => {
      // eslint-disable-next-line no-hardcoded-passwords
      await request(app)
        .post('/api/register')
        .send({
          name: 'Juan',
          email: 'juan@example.com',
          password: 'pass123' // eslint-disable-line no-hardcoded-passwords
        });

      // Verificar que se creó sesión
      expect(dbMock.data.sessions.length).toBeGreaterThan(0);
      const session = dbMock.data.sessions[0];
      expect(session.user_id).toBeDefined();
      expect(session.token).toBeDefined();
    });
  });

  describe('POST /api/login', () => {
    let testUser = {
      name: 'Juan Test',
      email: 'test@example.com',
      password: 'SecurePassword123!' // eslint-disable-line no-hardcoded-passwords
    };
    let hashedPassword;

    beforeEach(async () => {
      // Crear usuario de prueba con contraseña hasheada
      // eslint-disable-next-line no-hardcoded-passwords
      hashedPassword = await bcrypt.hash(testUser.password, 10);
      dbMock.data.users.push({
        id: 1,
        name: testUser.name,
        email: testUser.email,
        password: hashedPassword,
        created_at: new Date().toISOString()
      });
    });

    it('debería hacer login con credenciales correctas', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(response.status).toBe(200);
      expect(response.body.token).toBeDefined();
      expect(response.body.qr).toBeDefined();
      expect(response.body.user).toBeDefined();
      expect(response.body.user.id).toBe(1);
      expect(response.body.user.email).toBe(testUser.email);
    }, 30000);

    it('debería rechazar si faltan credenciales', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({
          email: testUser.email
          // Falta password
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Faltan credenciales');
    });

    it('debería rechazar usuario inexistente', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({
          email: 'noexiste@example.com',
          password: 'anypassword' // eslint-disable-line no-hardcoded-passwords
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Credenciales inválidas');
    });

    it('debería rechazar contraseña incorrecta', async () => {
      const response = await request(app)
        .post('/api/login')
        .send({
          email: testUser.email,
          password: 'WrongPassword123!' // eslint-disable-line no-hardcoded-passwords
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Credenciales inválidas');
    });

    it('debería crear nueva sesión en cada login', async () => {
      const firstLogin = await request(app)
        .post('/api/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      const secondLogin = await request(app)
        .post('/api/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      expect(firstLogin.body.token).not.toBe(secondLogin.body.token);
      expect(dbMock.data.sessions.length).toBe(2);
    }, 30000);

    it('debería incluir expiración en la sesión', async () => {
      await request(app)
        .post('/api/login')
        .send({
          email: testUser.email,
          password: testUser.password
        });

      const session = dbMock.data.sessions[0];
      expect(session.expires_at).toBeDefined();
    }, 30000);
  });

  describe('POST /api/open-with-qr', () => {
    it('debería rechazar si faltan userId o token', async () => {
      const response = await request(app)
        .post('/api/open-with-qr')
        .send({
          userId: 1
          // Falta token
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Faltan datos');
    });

    it('debería rechazar token inválido', async () => {
      const response = await request(app)
        .post('/api/open-with-qr')
        .send({
          userId: 999,
          token: 'invalidtoken123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Sesión inválida');
    });

    it('debería rechazar sesión expirada', async () => {
      // Crear sesión expirada
      const pastDate = new Date(Date.now() - 1000 * 60 * 60).toISOString(); // Hace 1 hora
      dbMock.data.sessions.push({
        id: 1,
        user_id: 1,
        token: 'expiredtoken123',
        expires_at: pastDate,
        created_at: new Date().toISOString()
      });

      const response = await request(app)
        .post('/api/open-with-qr')
        .send({
          userId: 1,
          token: 'expiredtoken123'
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Sesión expirada');
    });

    it('debería retornar error si no hay locker asignado', async () => {
      // Crear sesión válida sin locker
      const token = 'validtoken123';
      dbMock.data.users.push({
        id: 2,
        name: 'Test User',
        email: 'test2@example.com',
        password: 'hash', // eslint-disable-line no-hardcoded-passwords
        created_at: new Date().toISOString()
      });
      dbMock.data.sessions.push({
        id: 2,
        user_id: 2,
        token: token,
        expires_at: new Date(Date.now() + 1000 * 60 * 60).toISOString(),
        created_at: new Date().toISOString()
      });

      const response = await request(app)
        .post('/api/open-with-qr')
        .send({
          userId: 2,
          token: token
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('No hay locker asignado');
    });

    it('debería abrir locker exitosamente con sesión válida', async () => {
      // Preparar datos
      const token = 'validtoken456';
      dbMock.data.users.push({
        id: 3,
        name: 'User With Locker',
        email: 'user.locker@example.com',
        password: 'hash', // eslint-disable-line no-hardcoded-passwords
        created_at: new Date().toISOString()
      });
      dbMock.data.lockers.push({
        id: 1,
        code: 'LOCK001',
        assigned_user_id: 3,
        status: 'occupied',
        created_at: new Date().toISOString()
      });
      dbMock.data.sessions.push({
        id: 3,
        user_id: 3,
        token: token,
        expires_at: new Date(Date.now() + 1000 * 60 * 60).toISOString(),
        created_at: new Date().toISOString(),
        email: 'user.locker@example.com'
      });

      const response = await request(app)
        .post('/api/open-with-qr')
        .send({
          userId: 3,
          token: token
        });

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      expect(response.body.lockerId).toBe(1);
    });
  });

  describe('GET /api/logs', () => {
    it('debería retornar lista de logs', async () => {
      dbMock.data.logs.push({
        id: 1,
        user_id: 1,
        locker_id: 1,
        action: 'open',
        timestamp: new Date().toISOString()
      });

      const response = await request(app).get('/api/logs');

      expect(response.status).toBe(200);
      expect(response.body.logs).toBeDefined();
    });

    it('debería retornar error si hay problema con DB', async () => {
      // Hacer que db.all retorne error
      jest.spyOn(dbMock, 'all').mockImplementationOnce((sql, params, callback) => {
        setImmediate(() => callback(new Error('DB error')));
        return dbMock;
      });

      const response = await request(app).get('/api/logs');

      expect(response.status).toBe(500);
      expect(response.body.error).toContain('DB error');
    });
  });
});
