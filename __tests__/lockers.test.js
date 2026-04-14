// __tests__/lockers.test.js
const request = require('supertest');
const express = require('express');
const dbMock = require('./mocks/db.mock');

// Mockear módulos
jest.mock('../src/db', () => require('./mocks/db.mock'));
jest.mock('../src/mail');

const lockersRouter = require('../src/routes/lockers');

describe('Lockers Routes', () => {
  let app;

  beforeEach(() => {
    // Limpiar datos
    dbMock.data = {
      users: [
        {
          id: 1,
          name: 'Juan Test',
          email: 'juan@test.com',
          password: 'hashed123',
          created_at: new Date().toISOString()
        }
      ],
      lockers: [
        {
          id: 1,
          code: 'L001',
          assigned_user_id: null,
          status: 'free',
          created_at: new Date().toISOString()
        },
        {
          id: 2,
          code: 'L002',
          assigned_user_id: 1,
          status: 'occupied',
          created_at: new Date().toISOString()
        }
      ],
      sessions: [],
      access_logs: [],
      logs: []
    };
    jest.clearAllMocks();

    // Crear app Express con el router
    app = express();
    app.use(express.json());
    app.use('/api/lockers', lockersRouter);
  });

  describe('Validación de entrada', () => {
    it('POST /lockers debería rechazar si falta el código', async () => {
      const response = await request(app)
        .post('/api/lockers')
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('code requerido');
    });

    it('POST /lockers/assign debería rechazar si faltan lockerId o userId', async () => {
      const response = await request(app)
        .post('/api/lockers/assign')
        .send({ lockerId: 1 });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Faltan datos');
    });

    it('POST /open-with-qr debería rechazar si faltan userId o token', async () => {
      const response = await request(app)
        .post('/api/lockers/open-with-qr')
        .send({ userId: 1 });

      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Datos incompletos');
    });
  });

  describe('POST /api/lockers/assign - Lógica de negocio', () => {
    it('debería retornar ok: true cuando se asigna correctamente', async () => {
      const response = await request(app)
        .post('/api/lockers/assign')
        .send({
          lockerId: 1,
          userId: 1
        });

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      expect(response.body.lockerId).toBe(1);
      expect(response.body.userId).toBe(1);
    });
  });

  describe('POST /api/lockers/open-with-qr - Validación de sesión', () => {
    beforeEach(() => {
      // Crear sesión válida
      dbMock.data.sessions.push({
        id: 1,
        user_id: 1,
        token: 'validtoken123',
        expires_at: new Date(Date.now() + 3600000).toISOString(),
        created_at: new Date().toISOString()
      });
    });

    it('debería rechazar sesión inválida', async () => {
      const response = await request(app)
        .post('/api/lockers/open-with-qr')
        .send({
          userId: 1,
          token: 'invalidtoken'
        });

      expect(response.status).toBe(401);
      expect(response.body.error).toContain('Sesión inválida');
    });

    it('debería rechazar si no hay locker asignado', async () => {
      // Usuario sin locker
      dbMock.data.sessions.push({
        id: 2,
        user_id: 99,
        token: 'token99',
        expires_at: new Date(Date.now() + 3600000).toISOString()
      });

      const response = await request(app)
        .post('/api/lockers/open-with-qr')
        .send({
          userId: 99,
          token: 'token99'
        });

      expect(response.status).toBe(404);
      expect(response.body.error).toContain('No hay locker asignado');
    });

    it('debería abrir locker con credenciales válidas', async () => {
      const response = await request(app)
        .post('/api/lockers/open-with-qr')
        .send({
          userId: 1,
          token: 'validtoken123'
        });

      expect(response.status).toBe(200);
      expect(response.body.ok).toBe(true);
      expect(response.body.message).toContain('abierto');
    });
  });
});
