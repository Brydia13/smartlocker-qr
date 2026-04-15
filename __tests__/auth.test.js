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
      const crypto = require('node:crypto');
      const expectedHash = crypto.createHash('sha256').update(password).digest('hex');
      const result = hash === expectedHash;
      if (typeof callback === 'function') {
        setImmediate(() => callback(null, result));
        return undefined;
      } else {
        return Promise.resolve(result);
      }
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
          dob: '1990-01-01',
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
      expect(response.body.error).toContain('Todos los campos son obligatorios');
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
          dob: '1990-01-01',
          email: 'juan@example.com',
          password: 'pass123' // eslint-disable-line no-hardcoded-passwords
        });

      // Intentar registrar con mismo email
      const response = await request(app)
        .post('/api/register')
        .send({
          name: 'Otro Juan',
          dob: '1990-01-01',
          email: 'juan@example.com',
          password: 'pass456' // eslint-disable-line no-hardcoded-passwords
        });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('El correo ya está registrado');
    });

    it('debería hashear la contraseña antes de guardar', async () => {
      const password = 'MyPassword123!'; // eslint-disable-line no-hardcoded-passwords
      
      // eslint-disable-next-line no-hardcoded-passwords
      // eslint-disable-next-line no-hardcoded-passwords
      await request(app)
        .post('/api/register')
        .send({
          name: 'Test User',
          dob: '1990-01-01',
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
          dob: '1990-01-01',
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
});
