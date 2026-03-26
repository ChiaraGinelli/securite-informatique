const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./securenotes.db");

db.serialize(() => {
  db.run("PRAGMA foreign_keys = ON");

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      bio TEXT DEFAULT '',
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      lock_until INTEGER DEFAULT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  
  db.run(`UPDATE users SET role = 'admin' WHERE id = 1;`);

  console.log("Base de données SQLite initialisée avec succès.");
});

module.exports = db;