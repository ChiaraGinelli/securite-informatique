const sqlite3 = require("sqlite3").verbose();
const db = new sqlite3.Database("./securenotes.db");
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users ( 
id INTEGER PRIMARY KEY AUTOINCREMENT,  
email TEXT,  
password TEXT,  
role TEXT 
)`);
  //db.run("DELETE FROM users");
  //db.run("INSERT INTO users (email, password, role) VALUES ('admin@test.com', 'azerty','admin')",);
  console.log("Base de données SQLite initialisée avec succès.");
});
module.exports = db;
