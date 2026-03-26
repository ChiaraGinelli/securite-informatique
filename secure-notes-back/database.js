const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./securenotes.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      lock_until INTEGER DEFAULT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      content TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
    )
  `);

  console.log("Base de données SQLite initialisée avec succès.");

  db.run(`ALTER TABLE users ADD COLUMN bio TEXT DEFAULT '';`);
});


module.exports = db;