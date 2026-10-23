// Import des modules requis
const Database = require("better-sqlite3");
const path = require("path");

// Initialisation de la connexion à la base de données SQLite
const dbPath = path.join(__dirname, "..", "database.db");
const db = new Database(dbPath);

// Activation des clés étrangères dans SQLite
db.pragma("foreign_keys = ON");

// Création de la table des utilisateurs (Phase 1.0, bonus rôle & TP4 2FA)
db.exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT DEFAULT 'JUSTICIER',
		two_factor_secret TEXT,
		two_factor_enabled INTEGER DEFAULT 0
	);
`);

// Migration incrémentale : ajout des colonnes 2FA si la table users préexistait (TP4 - Étape 3)
try {
	db.exec("ALTER TABLE users ADD COLUMN two_factor_secret TEXT;");
} catch (e) {
	// Colonne déjà existante
}
try {
	db.exec("ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0;");
} catch (e) {
	// Colonne déjà existante
}

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

// Création de la table des journaux d'audit de sécurité (Phase Bonus)
db.exec(`
	CREATE TABLE IF NOT EXISTS logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		ip TEXT NOT NULL,
		username TEXT,
		success INTEGER NOT NULL
	);
`);

// Table du registre d'audit des connexions et détection de fraude (TP2 - Bonus 3)
db.exec(`
	CREATE TABLE IF NOT EXISTS connexions_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT,
		action TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		user_agent TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);
`);

// Table des jetons de rafraîchissement persistants (TP3 - Étape 2 & Challenge 1)
db.exec(`
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token TEXT UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		is_used INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);
`);

// Migration incrémentale : ajout de is_used si la table préexistait
try {
	db.exec("ALTER TABLE refresh_tokens ADD COLUMN is_used INTEGER DEFAULT 0;");
} catch (e) {
	// Colonne déjà existante
}

// Export de l'instance de la base de données
module.exports = db;
