const path = require('node:path');
const Database = require('better-sqlite3');

const databasePath = process.env.AUTH_DB_PATH || path.join(process.cwd(), 'auth.db');
const db = new Database(databasePath);

db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  )
`);

module.exports = db;