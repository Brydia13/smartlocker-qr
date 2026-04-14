// Mock de la base de datos SQLite para testing
const sqlite3 = require('sqlite3').verbose();

// Funciones auxiliares para reducir complejidad cognitiva
const handleInsertUsers = (params, callback) => {
  const user = {
    id: dbMock.data.users.length + 1,
    name: params[0],
    email: params[1],
    password: params[2],
    created_at: new Date().toISOString()
  };
  if (dbMock.data.users.some(u => u.email === params[1])) {
    callback(new Error('UNIQUE constraint failed: users.email'));
  } else {
    dbMock.data.users.push(user);
    callback.call({ lastID: user.id, changes: 1 }, null);
  }
};

const handleUpdateLockers = (sql, params, callback) => {
  const lockerId = sql.includes('WHERE id = ?') ? params.at(-1) : null;
  const locker = dbMock.data.lockers.find(l => l.id === lockerId);
  if (locker) {
    if (sql.includes('assigned_user_id')) {
      locker.assigned_user_id = params[0];
      locker.status = params[1];
    } else if (sql.includes('status')) {
      locker.status = params[0];
    }
  }
  callback.call({ changes: 1 }, null);
};

const handleInsertSessions = (params, callback) => {
  const session = {
    id: dbMock.data.sessions.length + 1,
    user_id: params[0],
    token: params[1],
    expires_at: params[2] || null,
    created_at: new Date().toISOString()
  };
  dbMock.data.sessions.push(session);
  callback.call({ lastID: session.id, changes: 1 }, null);
};

const handleInsertAccessLogs = (params, callback) => {
  const log = {
    id: dbMock.data.access_logs.length + 1,
    user_id: params[0],
    locker_id: params[1],
    action: params[2],
    success: params[3] || 1,
    created_at: new Date().toISOString()
  };
  dbMock.data.access_logs.push(log);
  callback.call({ lastID: log.id, changes: 1 }, null);
};

const handleInsertLogs = (params, callback) => {
  const log = {
    id: dbMock.data.logs.length + 1,
    user_id: params[0],
    locker_id: params[1],
    action: params[2],
    timestamp: new Date().toISOString()
  };
  dbMock.data.logs.push(log);
  callback.call({ lastID: log.id, changes: 1 }, null);
};

const handleGetUser = (sql, params, callback) => {
  if (sql.includes('WHERE email')) {
    const user = dbMock.data.users.find(u => u.email === params[0]);
    callback(null, user || null);
  } else if (sql.includes('WHERE id')) {
    const user = dbMock.data.users.find(u => u.id === params[0]);
    callback(null, user || null);
  } else {
    callback(null, null);
  }
};

const dbMock = {
  callbacks: {},
  data: {
    users: [],
    lockers: [],
    sessions: [],
    access_logs: [],
    logs: []
  },

  run: jest.fn(function(sql, params, callback) {
    if (typeof callback === 'function') {
      setImmediate(() => {
        if (sql.includes('INSERT INTO users')) {
          handleInsertUsers(params, callback);
        } else if (sql.includes('UPDATE lockers SET status') || sql.includes('UPDATE lockers SET assigned_user_id')) {
          handleUpdateLockers(sql, params, callback);
        } else if (sql.includes('INSERT INTO sessions')) {
          handleInsertSessions(params, callback);
        } else if (sql.includes('INSERT INTO access_logs')) {
          handleInsertAccessLogs(params, callback);
        } else if (sql.includes('INSERT INTO logs')) {
          handleInsertLogs(params, callback);
        } else {
          callback.call({ changes: 0 }, null);
        }
      });
    }
    return dbMock;
  }),

  get: jest.fn(function(sql, params, callback) {
    if (typeof callback === 'function') {
      setImmediate(() => {
        if (sql.includes('FROM users')) {
          handleGetUser(sql, params, callback);
        } else if (sql.includes('FROM sessions')) {
          const session = dbMock.data.sessions.find(s => 
            s.user_id === params[0] && s.token === params[1]
          );
          callback(null, session || null);
        } else if (sql.includes('FROM lockers')) {
          const locker = dbMock.data.lockers.find(l => 
            l.assigned_user_id === params[0]
          );
          callback(null, locker || null);
        } else {
          callback(null, null);
        }
      });
    }
    return dbMock;
  }),

  all: jest.fn(function(sql, params, callback) {
    if (typeof callback === 'function') {
      setImmediate(() => {
        if (sql.includes('FROM lockers')) {
          callback(null, dbMock.data.lockers);
        } else if (sql.includes('FROM logs') || sql.includes('FROM access_logs')) {
          callback(null, dbMock.data.access_logs);
        } else {
          callback(null, []);
        }
      });
    }
    return dbMock;
  }),

  serialize: jest.fn((fn) => {
    if (typeof fn === 'function') {
      fn();
    }
  }),

  close: jest.fn()
};

module.exports = dbMock;