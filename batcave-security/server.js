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

// Démarrage du serveur web de la Batcave
if (require.main === module) {
	app.listen(PORT, () => {
		console.log(`Batcave Security Server en ligne sur http://localhost:${PORT}`);
	});
}

// Export pour les tests ou la modularité
module.exports = app;
