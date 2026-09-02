const Database = require("better-sqlite3");
const path = require("path");

// Initialisation de la base SQLite locale
const dbPath = path.join(__dirname, "database.db");
const db = new Database(dbPath);

// Activation des cles etrangeres
db.pragma("foreign_keys = ON");

// Creation de la table des utilisateurs
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'JUSTICIER'
    );
`);

module.exports = db;
