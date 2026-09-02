// Import des dépendances nécessaires
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const db = require("./database");

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

// Configuration des middlewares pour traiter les données entrantes (JSON et formulaires)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Mise à disposition des fichiers statiques publics (inscription, scripts, etc.)
app.use(express.static(path.join(__dirname, "public")));

// Phase 3.0 : Middleware d'authentification Basic Auth
async function basicAuth(req, res, next) {
	// Extraction de l'en-tête Authorization
	const authHeader = req.headers.authorization;

	// Si l'en-tête est manquant ou n'est pas de type Basic
	if (!authHeader || !authHeader.startsWith("Basic ")) {
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
		res.setHeader("WWW-Authenticate", 'Basic realm="Batcave"');
		return res.status(401).json({ error: "Identifiants Basic Auth incomplets." });
	}

	// Recherche du compte utilisateur en base SQLite
	const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
	if (!user) {
		res.setHeader("WWW-Authenticate", 'Basic realm="Batcave"');
		return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
	}

	// Comparaison sécurisée du mot de passe fourni avec le hachage stocké
	const isPasswordValid = await bcrypt.compare(password, user.password);
	if (!isPasswordValid) {
		res.setHeader("WWW-Authenticate", 'Basic realm="Batcave"');
		return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
	}

	// Stockage des données de l'utilisateur authentifié dans l'objet requête
	req.user = user;
	return next();
}

// Phase 2.0 & 2.1 : Route d'enregistrement d'un nouveau justicier
app.post("/register", async (req, res) => {
	// Nettoyage de l'identifiant pour éviter les espaces superflus au début ou à la fin
	const username = req.body.username?.trim();
	const password = req.body.password;

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

	try {
		// Hachage du mot de passe avec Bcrypt (facteur de coût standard de 10)
		const hashedPassword = await bcrypt.hash(password, 10);

		// Insertion du nouveau justicier dans la table users
		const insertStmt = db.prepare(
			"INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
		);
		insertStmt.run(username, hashedPassword, "JUSTICIER");

		// Confirmation de la création du compte
		return res
			.status(201)
			.json({ message: "Justicier enregistré avec succès dans la Batcave." });
	} catch (err) {
		// Gestion des erreurs internes du serveur
		console.error("Erreur lors de l'enregistrement :", err);
		return res
			.status(500)
			.json({ error: "Erreur interne du serveur lors de l'enregistrement." });
	}
});

// Phase 3.0 : Route protégée servant l'interface du Bat-Ordinateur
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
	const reports = db
		.prepare("SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC")
		.all(req.user.id);
	res.json(reports);
});

// Démarrage du serveur web de la Batcave
if (require.main === module) {
	app.listen(PORT, () => {
		console.log(`Batcave Security Server en ligne sur http://localhost:${PORT}`);
	});
}

// Export pour les tests ou la modularité
module.exports = app;
