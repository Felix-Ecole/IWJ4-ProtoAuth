// Import des modules requis
const Database = require("better-sqlite3");
const path = require("path");

// Initialisation de la connexion à la base de données SQLite
const dbPath = path.join(__dirname, "database.db");
const db = new Database(dbPath);

// Activation des clés étrangères dans SQLite
db.pragma("foreign_keys = ON");

// Création de la table des utilisateurs (Phase 1.0 & bonus rôle)
db.exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT DEFAULT 'JUSTICIER'
	);
`);

// Création de la table des rapports de mission (Phase 3.1)
db.exec(`
	CREATE TABLE IF NOT EXISTS reports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		title TEXT NOT NULL,
		content TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
`);

// Export de l'instance de la base de données
module.exports = db;
