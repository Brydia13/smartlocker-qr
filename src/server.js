// src/server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("node:path");

require('./db'); // inicializa DB y tablas

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos (public/)
app.use(express.static(path.join(__dirname, '..', 'public')));

// Rutas API
const authRoutes = require('./routes/auth');
app.use('/api', authRoutes);

const lockerRoutes = require('./routes/lockers');
app.use('/api/lockers', lockerRoutes);

// NUEVO — Logs
const logsRoutes = require('./routes/logs');
app.use('/api/logs', logsRoutes);

// Ruta simple de salud
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Error handler básico
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en: http://localhost:${PORT}`);
});
