// Gestion du cycle de vie des jetons : rafraîchissement, rotation et révocation
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const db = require("../../config/database");
const { JWT_SECRET, getUserScopes, auditLog } = require("./helpers");

const router = express.Router();

// POST /refresh - Rotation du jeton et détection d'attaque par rejeu (Challenge 1)
const handleRefresh = async (req, res) => {
	const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

	if (!refreshToken) {
		return res.status(401).json({
			error: "Jeton de rafraîchissement (refreshToken) manquant.",
			code: "NO_REFRESH_TOKEN",
		});
	}

	// Recherche du refreshToken en base SQLite
	const record = db.prepare("SELECT * FROM refresh_tokens WHERE token = ?").get(refreshToken);

	if (!record) {
		res.clearCookie("token");
		res.clearCookie("refreshToken");
		return res.status(401).json({
			error: "Jeton de rafraîchissement invalide ou révoqué.",
			code: "INVALID_REFRESH_TOKEN",
		});
	}

	// CHALLENGE 1 : Détection de vol de session par réutilisation (Reuse Detection)
	if (record.is_used === 1) {
		const compromisedUser = db
			.prepare("SELECT username FROM users WHERE id = ?")
			.get(record.user_id);
		const username = compromisedUser?.username || "inconnu";

		console.warn(
			`[ALERTE SÉCURITÉ BATCAVE] Réutilisation frauduleuse de refresh token détectée pour l'agent "${username}" !`,
		);

		// Révocation immédiate de TOUTES les sessions actives de l'utilisateur compromis
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

	// Contrôle de l'expiration temporelle
	const now = new Date();
	const expiresAt = new Date(record.expires_at);

	if (expiresAt <= now) {
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

	// Récupération des informations de l'agent
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

	// Rotation : marquage de l'ancien jeton comme consommé
	db.prepare("UPDATE refresh_tokens SET is_used = 1 WHERE id = ?").run(record.id);

	// Génération d'un nouveau refreshToken cryptographique (Rotation)
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

	// Maintien du statut 2FA vérifié
	let is2FA = false;
	const currentToken =
		req.cookies?.token ||
		(req.headers.authorization?.startsWith("Bearer ")
			? req.headers.authorization.split(" ")[1]
			: null);
	if (currentToken) {
		const decodedPrev = jwt.decode(currentToken);
		if (decodedPrev && decodedPrev.is2FAVerified) {
			is2FA = true;
		}
	}

	// Attribution des scopes OAuth2 selon le profil
	const userScopes = getUserScopes(user.username, user.role);

	// Émission de l'accessToken JWT de 15 minutes (TP4 - Étape 2)
	const newAccessToken = jwt.sign(
		{
			id: user.id,
			username: user.username,
			role: user.role,
			scopes: userScopes,
			is2FAVerified: is2FA,
		},
		JWT_SECRET,
		{ expiresIn: "15m" },
	);

	// Renouvellement des cookies HTTP-Only SameSite=Strict
	res.cookie("token", newAccessToken, {
		httpOnly: true,
		sameSite: "strict",
		maxAge: 15 * 60 * 1000,
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
		expiresIn: 900,
		scopes: userScopes,
	});
};

router.post("/refresh", handleRefresh);

// Déconnexion et révocation définitive du refreshToken
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

module.exports = router;
