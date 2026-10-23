// Gestionnaire du parcours de connexion et du verrouillage Zéro-Confiance
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("../../config/database");
const { JWT_SECRET, auditLog } = require("./helpers");

const router = express.Router();

// GET /login - Page de connexion sécurisée de la Batcave
router.get("/login", (req, res) => {
	const token = req.cookies?.token;
	if (token) {
		try {
			jwt.verify(token, JWT_SECRET);
			return res.redirect("/bat-computer");
		} catch {
			// Jeton absent ou invalide, affichage normal du formulaire
		}
	}
	res.sendFile(path.join(__dirname, "..", "..", "views", "login.html"));
});

// POST /login - Authentification primaire et politique Zéro-Confiance
router.post("/login", async (req, res) => {
	const { username, password } = req.body || {};

	if (!username || !password) {
		if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
			return res.status(400).json({ error: "Identifiant et mot de passe requis." });
		}
		return res.redirect("/auth/login?error=" + encodeURIComponent("Champs incomplets"));
	}

	// Recherche de l'agent en base SQLite
	const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
	if (!user) {
		auditLog(username.trim(), "LOGIN_FAILED", req);
		if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
			return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
		}
		return res
			.status(401)
			.redirect(
				"/auth/login?error=" + encodeURIComponent("Identifiant ou mot de passe incorrect"),
			);
	}

	// Validation de la clé secrète avec Bcrypt
	const isValid = await bcrypt.compare(password, user.password);
	if (!isValid) {
		auditLog(username.trim(), "LOGIN_FAILED", req);
		if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
			return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
		}
		return res
			.status(401)
			.redirect(
				"/auth/login?error=" + encodeURIComponent("Identifiant ou mot de passe incorrect"),
			);
	}

	// POLITIQUE ZÉRO-CONFIANCE (TP4 - Étape 6)
	// Si la 2FA n'est pas encore activée, refus strict 403 Forbidden sans émettre de jeton
	if (!user.two_factor_enabled || user.two_factor_enabled === 0) {
		auditLog(user.username, "LOGIN_BLOCKED_NO_2FA", req);
		if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
			return res.status(403).json({
				error: "Accès refusé : l'activation de l'authentification double facteur (2FA) est obligatoire sur le terminal Batcave.",
				code: "2FA_ENROLLMENT_REQUIRED",
				requiresEnrollment: true,
				userId: user.id,
				username: user.username,
			});
		}
		return res
			.status(403)
			.redirect(
				"/auth/login?error=" +
					encodeURIComponent("Activation du double facteur (2FA) obligatoire."),
			);
	}

	// Si la 2FA est active : arrêt de la fonction sans émettre de jeton
	auditLog(user.username, "LOGIN_STEP1_SUCCESS", req);
	return res.json({
		requires2FA: true,
		message: "Étape 1 validée. Veuillez fournir votre code TOTP.",
		username: user.username,
	});
});

module.exports = router;
