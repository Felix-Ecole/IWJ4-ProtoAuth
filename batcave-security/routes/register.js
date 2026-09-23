// Routeur d'enregistrement des agents de la Batcave
const express = require("express");
const bcrypt = require("bcrypt");
const db = require("../config/database");

const router = express.Router();

// POST /register - Enregistrement d'un nouvel agent
router.post("/register", async (req, res) => {
	const username = req.body.username?.trim();
	const password = req.body.password;
	const requestedRole = req.body.role ? String(req.body.role).toUpperCase() : null;

	// Vérification de la présence des champs requis
	if (!username || !password) {
		return res.status(400).json({ error: "Identifiant et mot de passe requis." });
	}

	// Politique de mot de passe : au moins 8 caractères
	if (password.length < 8) {
		return res.status(400).json({
			error: "Le mot de passe doit comporter au moins 8 caractères.",
		});
	}

	try {
		// Vérification de l'unicité du nom d'utilisateur
		const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
		if (existingUser) {
			return res.status(409).json({ error: "Ce nom d'utilisateur est déjà utilisé." });
		}

		// Attribution du rôle :
		// 1. Premier utilisateur promu automatiquement ADMIN
		// 2. Sinon, application du rôle demandé si valide (ADMIN, ASSISTANT, JUSTICIER)
		// 3. JUSTICIER par défaut
		const totalUsers = db.prepare("SELECT COUNT(*) as count FROM users").get().count;
		let role = "JUSTICIER";
		const validRoles = ["ADMIN", "ASSISTANT", "JUSTICIER"];

		if (totalUsers === 0) {
			role = "ADMIN";
		} else if (requestedRole && validRoles.includes(requestedRole)) {
			role = requestedRole;
		}

		// Hachage du mot de passe avec Bcrypt (10 tours)
		const hashedPassword = await bcrypt.hash(password, 10);

		// Insertion du compte en base de données SQLite
		const stmt = db.prepare(
			"INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
		);
		const result = stmt.run(username, hashedPassword, role);

		return res.status(201).json({
			message: "Compte agent créé avec succès.",
			user: {
				id: result.lastInsertRowid,
				username: username,
				role: role,
			},
		});
	} catch (err) {
		console.error("Erreur enregistrement agent :", err);
		return res.status(500).json({ error: "Erreur serveur lors de la création du compte." });
	}
});

module.exports = router;
