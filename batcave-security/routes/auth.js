// Routeur d'authentification stateless JWT pour la Batcave (TP3)
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const db = require("../config/database");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || "batcave_jwt_secret_token_key_2026_super_secure";

// Helper d'audit sécurité pour enregistrer les actions dans connexions_audit
function auditLog(username, action, req) {
	try {
		const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
		const userAgent = req.headers["user-agent"] || "inconnu";
		const stmt = db.prepare(
			"INSERT INTO connexions_audit (username, action, ip_address, user_agent) VALUES (?, ?, ?, ?)"
		);
		stmt.run(username || "anonyme", action, ip, userAgent);
	} catch (e) {
		// Table audit optionnelle
	}
}

// GET /auth/login - Formulaire de connexion sécurisé Batcave
router.get("/login", (req, res) => {
	// Si un token JWT valide est déjà présent dans les cookies, redirection directe
	const token = req.cookies?.token;
	if (token) {
		try {
			jwt.verify(token, JWT_SECRET);
			return res.redirect("/bat-computer");
		} catch {
			// Token absent ou expiré, affichage du formulaire
		}
	}
	res.sendFile(path.join(__dirname, "..", "views", "login.html"));
});

// POST /auth/login - Authentification stateless par JWT et émission des cookies
router.post("/login", async (req, res) => {
	const { username, password } = req.body || {};

	if (!username || !password) {
		if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
			return res.status(400).json({ error: "Identifiant et mot de passe requis." });
		}
		return res.redirect("/auth/login?error=" + encodeURIComponent("Champs incomplets"));
	}

	// Recherche de l'utilisateur en base SQLite
	const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
	if (!user) {
		auditLog(username.trim(), "LOGIN_FAILED", req);
		if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
			return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
		}
		return res.status(401).redirect("/auth/login?error=" + encodeURIComponent("Identifiant ou mot de passe incorrect"));
	}

	// Vérification du mot de passe avec Bcrypt
	const isValid = await bcrypt.compare(password, user.password);
	if (!isValid) {
		auditLog(username.trim(), "LOGIN_FAILED", req);
		if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
			return res.status(401).json({ error: "Identifiant ou mot de passe incorrect." });
		}
		return res.status(401).redirect("/auth/login?error=" + encodeURIComponent("Identifiant ou mot de passe incorrect"));
	}

	// Génération de l'accessToken JWT (durée courte de 15 secondes pour les démonstrations de rafraîchissement)
	const accessToken = jwt.sign(
		{
			id: user.id,
			username: user.username,
			role: user.role,
		},
		JWT_SECRET,
		{ expiresIn: "15s" }
	);

	// Génération du refreshToken opaque (chaîne cryptographique aléatoire de 64 octets)
	const refreshToken = crypto.randomBytes(64).toString("hex");

	// Calcul de la date d'expiration à 7 jours
	const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

	// Enregistrement du refreshToken dans la table SQLite
	try {
		const stmt = db.prepare(
			"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)"
		);
		stmt.run(user.id, refreshToken, expiresAt);
	} catch (err) {
		console.error("Erreur lors du stockage du refreshToken :", err);
		return res.status(500).json({ error: "Erreur serveur lors de la création du jeton." });
	}

	// Envoi des deux cookies sécurisés distincts au client
	res.cookie("token", accessToken, {
		httpOnly: true, // Protection XSS
		sameSite: "strict", // Protection CSRF
		maxAge: 15 * 1000, // 15 secondes d'espérance de vie
		secure: false, // Environnement de test local HTTP
	});

	res.cookie("refreshToken", refreshToken, {
		httpOnly: true, // Inaccessible aux scripts client
		sameSite: "strict", // Confinement strict
		maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
		secure: false,
	});

	// Journalisation de la connexion réussie
	auditLog(user.username, "LOGIN", req);

	if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
		return res.json({
			success: true,
			message: "Connexion autorisée.",
			redirect: "/bat-computer",
			user: {
				id: user.id,
				username: user.username,
				role: user.role,
			},
		});
	}

	return res.redirect("/bat-computer");
});

// GET /auth/logout - Déconnexion initiale
router.get("/logout", (req, res) => {
	res.clearCookie("token");
	res.clearCookie("refreshToken");
	res.redirect("/auth/login");
});

module.exports = router;
