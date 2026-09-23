// Chargement des variables d'environnement dès le début
require("dotenv").config();

// Import des dépendances nécessaires
const express = require("express");
const session = require("express-session");
const SqliteStore = require("better-sqlite3-session-store")(session);
const path = require("path");
const bcrypt = require("bcrypt");
const db = require("./config/database");

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

// Configuration des middlewares pour traiter les données entrantes (JSON et formulaires)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuration du Session Store persistant SQLite (TP2 - Bonus 1)
const sessionStore = new SqliteStore({
	client: db,
	expired: {
		clear: true,
		intervalMs: 900000, // Nettoyage automatique toutes les 15 minutes
	},
});

// Middleware de session et sécurisation du badge de la Batcave (TP2)
app.use(
	session({
		name: "bat_identity",
		secret: process.env.SESSION_SECRET || "batcave_super_secret_session_key_2026_top_secret_bruce_wayne",
		store: sessionStore,
		resave: false,
		saveUninitialized: false,
		cookie: {
			httpOnly: true, // Protection contre les failles XSS
			sameSite: "strict", // Protection contre les requêtes intersites (CSRF)
			maxAge: 1800000, // Expiration automatique au bout de 30 minutes d'inactivité
			secure: false, // Environnement de développement local HTTP
		},
	})
);

// Mise à disposition des fichiers statiques publics (inscription, scripts, etc.)
app.use(express.static(path.join(__dirname, "public")));

// Phase Bonus : Suivi des tentatives d'authentification pour protection contre le brute-force
// Structure : username -> { count: number, lockedUntil: number }
const loginAttempts = new Map();

// Phase Bonus : Enregistrement d'un événement d'audit dans la table logs
function logAuthAttempt(ip, username, success) {
	try {
		const stmt = db.prepare("INSERT INTO logs (ip, username, success) VALUES (?, ?, ?)");
		stmt.run(ip || "127.0.0.1", username || null, success ? 1 : 0);
	} catch (err) {
		console.error("Erreur lors de l'enregistrement du log :", err);
	}
}

// Phase 3.0 & Bonus : Middleware d'authentification Basic Auth avec audit et limitation
async function basicAuth(req, res, next) {
	const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
	const authHeader = req.headers.authorization;

	// Si l'en-tête est manquant ou n'est pas de type Basic
	if (!authHeader || !authHeader.startsWith("Basic ")) {
		logAuthAttempt(ip, null, false);
		res.setHeader("WWW-Authenticate", 'Basic realm="Batcave"');
		return res
			.status(401)
			.json({ error: "Authentification requise pour entrer dans la Batcave." });
	}

	// Décodage de la chaîne en Base64
	const base64Credentials = authHeader.split(" ")[1];
	const decoded = Buffer.from(base64Credentials, "base64").toString("utf-8");
	const [username, password] = decoded.split(":");

	// Vérification de la présence des identifiants décodés
	if (!username || !password) {
		logAuthAttempt(ip, username || null, false);
		res.setHeader("WWW-Authenticate", 'Basic realm="Batcave"');
		return res.status(401).json({ error: "Identifiants Basic Auth incomplets." });
	}

	// Phase Bonus : Contrôle du blocage temporaire (3 échecs = 30s)
	const attempt = loginAttempts.get(username);
	if (attempt && attempt.lockedUntil > Date.now()) {
		const remaining = Math.ceil((attempt.lockedUntil - Date.now()) / 1000);
		logAuthAttempt(ip, username, false);
		return res.status(429).json({
			error: `Compte temporairement bloqué suite à 3 échecs. Réessayez dans ${remaining} secondes.`,
		});
	}

	// Recherche du compte utilisateur en base SQLite
	const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
	if (!user) {
		logAuthAttempt(ip, username, false);
		res.setHeader("WWW-Authenticate", 'Basic realm="Batcave"');
		return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
	}

	// Comparaison sécurisée du mot de passe fourni avec le hachage stocké
	const isPasswordValid = await bcrypt.compare(password, user.password);
	if (!isPasswordValid) {
		// Phase Bonus : Incrémentation du compteur d'échecs
		const currentCount = (attempt ? attempt.count : 0) + 1;
		if (currentCount >= 3) {
			loginAttempts.set(username, {
				count: currentCount,
				lockedUntil: Date.now() + 30000,
			});
		} else {
			loginAttempts.set(username, {
				count: currentCount,
				lockedUntil: 0,
			});
		}

		logAuthAttempt(ip, username, false);
		res.setHeader("WWW-Authenticate", 'Basic realm="Batcave"');
		return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
	}

	// Réinitialisation des tentatives échouées après succès
	loginAttempts.delete(username);
	logAuthAttempt(ip, username, true);

	// Stockage des données de l'utilisateur authentifié dans l'objet requête
	req.user = user;
	return next();
}

// Phase Bonus : Middleware de vérification de rôle (RBAC)
function requireRole(...allowedRoles) {
	return (req, res, next) => {
		if (!req.user || !allowedRoles.includes(req.user.role)) {
			return res.status(403).json({ error: "403 : Accès refusé" });
		}
		return next();
	};
}

// Phase 2.0 & 2.1 : Route d'enregistrement d'un nouveau justicier
app.post("/register", async (req, res) => {
	// Nettoyage de l'identifiant pour éviter les espaces superflus au début ou à la fin
	const username = req.body.username?.trim();
	const password = req.body.password;
	const requestedRole = req.body.role?.toUpperCase();

	// Vérification de la présence obligatoire des deux champs
	if (!username || !password) {
		return res.status(400).json({ error: "Identifiant et mot de passe requis." });
	}

	// Vérification de la politique de sécurité du mot de passe (minimum 8 caractères)
	if (password.length < 8) {
		return res.status(400).json({
			error: "Le mot de passe doit comporter au moins 8 caractères.",
		});
	}

	// Vérification de l'unicité du nom d'utilisateur dans la base de données
	const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
	if (existingUser) {
		// Renvoi du code 409 Conflict en cas de doublon détecté
		return res.status(409).json({ error: "Ce nom d'utilisateur est déjà utilisé." });
	}

	// Attribution du rôle :
	// 1. Le premier utilisateur créé devient automatiquement ADMIN
	// 2. Sinon, application du rôle demandé si valide, ou JUSTICIER par défaut
	const usersCount = db.prepare("SELECT COUNT(*) as count FROM users").get().count;
	let role = "JUSTICIER";
	if (usersCount === 0) {
		role = "ADMIN";
	} else if (["ADMIN", "ASSISTANT", "JUSTICIER"].includes(requestedRole)) {
		role = requestedRole;
	}

	try {
		// Hachage du mot de passe avec Bcrypt (facteur de coût standard de 10)
		const hashedPassword = await bcrypt.hash(password, 10);

		// Insertion du nouveau justicier dans la table users
		const insertStmt = db.prepare(
			"INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
		);
		insertStmt.run(username, hashedPassword, role);

		// Confirmation de la création du compte
		return res.status(201).json({
			message: `Justicier enregistré avec succès dans la Batcave (Rôle : ${role}).`,
			role,
		});
	} catch (err) {
		// Gestion des erreurs internes du serveur
		console.error("Erreur lors de l'enregistrement :", err);
		return res
			.status(500)
			.json({ error: "Erreur interne du serveur lors de l'enregistrement." });
	}
});

// Phase 3.0 : Route protégée servant l'interface du Bat-Ordinateur
// Accessible aux rôles ADMIN, ASSISTANT et JUSTICIER
app.get("/bat-computer", basicAuth, (req, res) => {
	res.sendFile(path.join(__dirname, "private", "bat-computer.html"));
});

// Phase 3.1 : Route protégée renvoyant l'identité du justicier authentifié
app.get("/api/me", basicAuth, (req, res) => {
	res.json({
		id: req.user.id,
		username: req.user.username,
		role: req.user.role,
	});
});

// Phase 3.0 : Route protégée renvoyant l'arsenal secret de Batman en JSON
app.get("/api/secrets", basicAuth, (req, res) => {
	const secrets = [
		{ name: "Batarang", desc: "Arme de jet emblématique et rétractable.", icon: "fa-shuriken" },
		{
			name: "Grappin",
			desc: "Propulseur d'escalade à câble ultra-résistant.",
			icon: "fa-anchor",
		},
		{ name: "Batmobile", desc: "Blindé furtif équipé de turboréacteurs.", icon: "fa-car" },
		{
			name: "Gel explosif",
			desc: "Aérosol de détonation commandé à distance.",
			icon: "fa-bomb",
		},
		{
			name: "Cryptographe",
			desc: "Décodeur portable de terminaux et fréquences radio.",
			icon: "fa-walkie-talkie",
		},
		{
			name: "Vision détective",
			desc: "Visière à analyse thermique et balistique avancée.",
			icon: "fa-glasses",
		},
	];

	res.json(secrets);
});

// Phase 3.1 : Enregistrement d'un rapport de mission lié au justicier
app.post("/api/reports", basicAuth, (req, res) => {
	const title = req.body.title?.trim();
	const content = req.body.content?.trim();

	// Vérification de la présence des informations du rapport
	if (!title || !content) {
		return res.status(400).json({ error: "Titre et contenu du rapport obligatoires." });
	}

	// Insertion du rapport avec liaison de clé étrangère vers users.id
	const insertStmt = db.prepare("INSERT INTO reports (user_id, title, content) VALUES (?, ?, ?)");
	const result = insertStmt.run(req.user.id, title, content);

	return res.status(201).json({
		message: "Rapport de mission consigné avec succès.",
		reportId: result.lastInsertRowid,
	});
});

// Phase 3.1 : Consultation de l'historique des rapports du justicier
app.get("/api/reports", basicAuth, (req, res) => {
	// Un ADMIN voit tous les rapports, les autres uniquement les leurs
	const query =
		req.user.role === "ADMIN"
			? "SELECT reports.*, users.username FROM reports JOIN users ON users.id = reports.user_id ORDER BY created_at DESC"
			: "SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC";

	const reports =
		req.user.role === "ADMIN" ? db.prepare(query).all() : db.prepare(query).all(req.user.id);

	res.json(reports);
});

// Phase Bonus : Route protégée réservée exclusivement aux administrateurs (RBAC 403)
app.get("/api/admin/logs", basicAuth, requireRole("ADMIN"), (req, res) => {
	const logs = db.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT 50").all();
	res.json(logs);
});

// Phase Bonus : Route de déconnexion ordonnant au client d'oublier la session
app.get("/logout", (req, res) => {
	res.setHeader("WWW-Authenticate", 'Basic realm="Batcave-LoggedOut"');
	res.status(401).send(`
		<!doctype html>
		<html lang="fr">
			<head>
				<meta charset="UTF-8" />
				<title>Déconnexion - Batcave</title>
				<script src="https://cdn.tailwindcss.com"></script>
			</head>
			<body class="bg-zinc-950 text-zinc-100 flex items-center justify-center min-h-screen p-4">
				<div class="max-w-sm w-full bg-zinc-900 border border-zinc-800 rounded-lg p-6 text-center shadow-xl">
					<h1 class="text-lg font-bold text-amber-400 mb-2">Session terminée</h1>
					<p class="text-xs text-zinc-400 mb-6">Vos identifiants ont été purgés de la mémoire locale.</p>
					<a href="/bat-computer" class="inline-block px-4 py-2 bg-amber-500 hover:bg-amber-400 text-zinc-950 font-semibold rounded text-xs transition">
						Se reconnecter
					</a>
				</div>
			</body>
		</html>
	`);
});

// Démarrage du serveur web de la Batcave
if (require.main === module) {
	app.listen(PORT, () => {
		console.log(`Batcave Security Server en ligne sur http://localhost:${PORT}`);
	});
}

// Export pour les tests ou la modularité
module.exports = app;
