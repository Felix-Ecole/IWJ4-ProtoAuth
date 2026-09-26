// Routeur d'authentification stateless JWT pour la Batcave (TP3)
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const db = require("../config/database");
const { checkJWT } = require("../middlewares/authCheck");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || "batcave_jwt_secret_token_key_2026_super_secure";

// Helper d'audit sécurité pour enregistrer les actions dans connexions_audit
function auditLog(username, action, req) {
	try {
		const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
		const userAgent = req.headers["user-agent"] || "inconnu";
		const stmt = db.prepare(
			"INSERT INTO connexions_audit (username, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
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
		return res
			.status(401)
			.redirect(
				"/auth/login?error=" + encodeURIComponent("Identifiant ou mot de passe incorrect"),
			);
	}

	// Vérification du mot de passe avec Bcrypt
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

	// Génération de l'accessToken JWT (durée courte de 15 secondes pour les démonstrations de rafraîchissement)
	const accessToken = jwt.sign(
		{
			id: user.id,
			username: user.username,
			role: user.role,
		},
		JWT_SECRET,
		{ expiresIn: "15s" },
	);

	// Génération du refreshToken opaque (chaîne cryptographique aléatoire de 64 octets)
	const refreshToken = crypto.randomBytes(64).toString("hex");

	// Calcul de la date d'expiration à 7 jours
	const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

	// Enregistrement du refreshToken dans la table SQLite
	try {
		const stmt = db.prepare(
			"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
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

// POST /refresh (et /api/auth/refresh) - Renouvellement avec rotation et détection de réutilisation (Challenge 1)
const handleRefresh = async (req, res) => {
	const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

	if (!refreshToken) {
		return res.status(401).json({
			error: "Jeton de rafraîchissement (refreshToken) manquant.",
			code: "NO_REFRESH_TOKEN",
		});
	}

	// Recherche du refreshToken dans la table SQLite
	const record = db.prepare("SELECT * FROM refresh_tokens WHERE token = ?").get(refreshToken);

	if (!record) {
		res.clearCookie("token");
		res.clearCookie("refreshToken");
		return res.status(401).json({
			error: "Jeton de rafraîchissement invalide ou révoqué.",
			code: "INVALID_REFRESH_TOKEN",
		});
	}

	// CHALLENGE 1 : Détection d'attaque par rejeu (Reuse Detection)
	// Si le jeton présenté a déjà été consommé, tentative de vol/rejeu suspectée
	if (record.is_used === 1) {
		const compromisedUser = db
			.prepare("SELECT username FROM users WHERE id = ?")
			.get(record.user_id);
		const username = compromisedUser?.username || "inconnu";

		console.warn(
			`[ALERTE SÉCURITÉ BATCAVE] Réutilisation frauduleuse de refresh token détectée pour l'agent "${username}" !`,
		);

		// Sanction maximale : révocation immédiate de TOUS les jetons de cet utilisateur
		try {
			db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?").run(record.user_id);
			auditLog(username, "FRAUD", req);
		} catch (err) {
			console.error("Erreur lors de la révocation en cascade :", err);
		}

		res.clearCookie("token");
		res.clearCookie("refreshToken");

		return res.status(403).json({
			error:
				"Alerte de sécurité critique : tentative de réutilisation d'un jeton déjà consommé. Toutes les sessions de l'agent ont été immédiatement révoquées.",
			code: "TOKEN_REUSE_DETECTED",
		});
	}

	// Vérification de la date d'expiration
	const now = new Date();
	const expiresAt = new Date(record.expires_at);

	if (expiresAt <= now) {
		// Purge du jeton expiré en base de données
		try {
			db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
		} catch (err) {
			console.error("Erreur suppression token expiré :", err);
		}

		res.clearCookie("token");
		res.clearCookie("refreshToken");
		return res.status(401).json({
			error: "Jeton de rafraîchissement expiré. Reconnexion requise.",
			code: "REFRESH_TOKEN_EXPIRED",
		});
	}

	// Récupération des informations de l'agent associé
	const user = db
		.prepare("SELECT id, username, role FROM users WHERE id = ?")
		.get(record.user_id);
	if (!user) {
		db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
		res.clearCookie("token");
		res.clearCookie("refreshToken");
		return res.status(401).json({
			error: "Agent associé au jeton introuvable.",
			code: "USER_NOT_FOUND",
		});
	}

	// Rotation : marquage de l'ancien refreshToken comme consommé (pour détection de rejeu futur)
	db.prepare("UPDATE refresh_tokens SET is_used = 1 WHERE id = ?").run(record.id);

	// Génération d'un NOUVEAU refreshToken cryptographique (Rotation)
	const newRefreshToken = crypto.randomBytes(64).toString("hex");
	const newExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

	try {
		db.prepare(
			"INSERT INTO refresh_tokens (user_id, token, expires_at, is_used) VALUES (?, ?, ?, 0)",
		).run(user.id, newRefreshToken, newExpiresAt);
	} catch (err) {
		console.error("Erreur insertion nouveau refreshToken lors de la rotation :", err);
		return res.status(500).json({ error: "Erreur serveur lors de la rotation des jetons." });
	}

	// Émission d'un nouvel accessToken JWT de 15 secondes
	const newAccessToken = jwt.sign(
		{
			id: user.id,
			username: user.username,
			role: user.role,
		},
		JWT_SECRET,
		{ expiresIn: "15s" },
	);

	// Renouvellement des deux cookies sécurisés avec le nouveau couple de jetons
	res.cookie("token", newAccessToken, {
		httpOnly: true,
		sameSite: "strict",
		maxAge: 15 * 1000,
		secure: false,
	});

	res.cookie("refreshToken", newRefreshToken, {
		httpOnly: true,
		sameSite: "strict",
		maxAge: 7 * 24 * 60 * 60 * 1000,
		secure: false,
	});

	return res.json({
		success: true,
		message: "Rotation réussie des jetons de sécurité.",
		accessToken: newAccessToken,
		refreshToken: newRefreshToken,
		expiresIn: 15,
	});
};

router.post("/refresh", handleRefresh);

// Déconnexion avec révocation immédiate du refreshToken en base SQLite
const handleLogout = (req, res) => {
	const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

	if (refreshToken) {
		try {
			const record = db
				.prepare("SELECT user_id FROM refresh_tokens WHERE token = ?")
				.get(refreshToken);
			if (record) {
				const user = db
					.prepare("SELECT username FROM users WHERE id = ?")
					.get(record.user_id);
				if (user) {
					auditLog(user.username, "LOGOUT", req);
				}
			}
			// Révocation définitive du jeton en BDD
			db.prepare("DELETE FROM refresh_tokens WHERE token = ?").run(refreshToken);
		} catch (err) {
			console.error("Erreur révocation refreshToken en BDD :", err);
		}
	}

	res.clearCookie("token");
	res.clearCookie("refreshToken");

	if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
		return res.json({ success: true, message: "Déconnexion et révocation réussies." });
	}

	return res.redirect("/auth/login");
};

router.post("/logout", handleLogout);
router.get("/logout", handleLogout);

// Regex de validation de la politique de sécurité des mots de passe (recommandation ANSSI)
// Minimum 12 caractères, incluant majuscule, minuscule, chiffre et caractère spécial
const ANSSI_PASSWORD_REGEX =
	/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{12,}$/;

// POST /change-password (et /api/auth/change-password) - Modification sécurisée du mot de passe (Étape 5)
router.post("/change-password", checkJWT, async (req, res) => {
	const { oldPassword, newPassword, confirmPassword } = req.body || {};
	const userId = req.user?.id;

	if (!userId) {
		return res.status(401).json({ error: "Session non authentifiée." });
	}

	if (!oldPassword || !newPassword || !confirmPassword) {
		return res.status(400).json({ error: "Tous les champs de sécurité sont obligatoires." });
	}

	if (newPassword !== confirmPassword) {
		return res.status(400).json({
			error: "Le nouveau mot de passe et sa confirmation ne correspondent pas.",
		});
	}

	if (oldPassword === newPassword) {
		return res.status(400).json({
			error: "Le nouveau mot de passe doit être différent de l'ancienne clé.",
		});
	}

	// Validation stricte des critères de robustesse ANSSI
	if (!ANSSI_PASSWORD_REGEX.test(newPassword)) {
		return res.status(400).json({
			error:
				"Le mot de passe ne respecte pas les critères ANSSI : minimum 12 caractères, avec au moins une majuscule, une minuscule, un chiffre et un caractère spécial.",
		});
	}

	// Recherche de l'utilisateur dans la base SQLite
	const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
	if (!user) {
		return res.status(404).json({ error: "Agent introuvable en base de données." });
	}

	// Contrôle de l'ancien mot de passe via Bcrypt
	const isOldValid = await bcrypt.compare(oldPassword, user.password);
	if (!isOldValid) {
		return res.status(401).json({ error: "L'ancienne clé de sécurité saisie est incorrecte." });
	}

	// Hachage du nouveau mot de passe avec Bcrypt (coût 10)
	const saltRounds = 10;
	const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

	// Enregistrement de la nouvelle clé en base
	try {
		db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashedPassword, userId);
		auditLog(user.username, "PASSWORD_CHANGED", req);

		return res.json({
			success: true,
			message: "Clé de sécurité mise à jour avec succès selon les critères ANSSI.",
		});
	} catch (err) {
		console.error("Erreur lors de la mise à jour du mot de passe :", err);
		return res.status(500).json({
			error: "Erreur serveur lors de l'enregistrement de la nouvelle clé.",
		});
	}
});

module.exports = router;
