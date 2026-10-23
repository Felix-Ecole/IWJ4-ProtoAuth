// Protocole d'authentification double facteur (2FA TOTP RFC 6238)
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const qrcode = require("qrcode");
const { authenticator } = require("@otplib/preset-v11");
const db = require("../../config/database");
const { JWT_SECRET, ALFRED_2FA_CODE, getUserScopes, auditLog } = require("./helpers");

const router = express.Router();

// POST /2fa/setup - Initialisation de l'enrôlement 2FA (génération clé secrète et QR Code)
router.post("/2fa/setup", async (req, res) => {
	let user = null;
	const token =
		req.cookies?.token ||
		(req.headers.authorization?.startsWith("Bearer ")
			? req.headers.authorization.split(" ")[1]
			: null);

	if (token) {
		try {
			const decoded = jwt.verify(token, JWT_SECRET);
			user = db.prepare("SELECT * FROM users WHERE id = ?").get(decoded.id);
		} catch {
			// Jeton absent ou invalide
		}
	}

	if (!user) {
		const { username, userId } = req.body || {};
		if (userId) {
			user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
		} else if (username) {
			user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
		}
	}

	if (!user) {
		return res.status(401).json({
			error: "Agent non identifié. Veuillez vous authentifier pour enrôler la 2FA.",
			code: "UNAUTHORIZED",
		});
	}

	// 1. Génération d'une clé secrète cryptographique unique via otplib
	const secret = authenticator.generateSecret();

	// 2. Création de l'URI standardisée otpauth://
	const appName = "Batcave";
	const otpAuthUrl = authenticator.keyuri(user.username, appName, secret);

	// 3. Sauvegarde temporaire du secret en base (two_factor_enabled reste à 0)
	try {
		db.prepare("UPDATE users SET two_factor_secret = ? WHERE id = ?").run(secret, user.id);
	} catch (err) {
		console.error("Erreur enregistrement two_factor_secret :", err);
		return res.status(500).json({ error: "Erreur serveur lors de la préparation 2FA." });
	}

	// 4. Génération de l'image QR Code encodée en Base64
	try {
		const qrCodeDataUrl = await qrcode.toDataURL(otpAuthUrl);
		auditLog(user.username, "2FA_SETUP_INIT", req);

		return res.json({
			success: true,
			message: "Enrôlement 2FA initialisé avec succès.",
			secret: secret,
			qrCode: qrCodeDataUrl,
			otpauth_url: otpAuthUrl,
			username: user.username,
		});
	} catch (err) {
		console.error("Erreur génération QR Code Base64 :", err);
		return res.status(500).json({ error: "Erreur lors de la génération du QR Code." });
	}
});

// POST /2fa/confirm - Confirmation et activation du double facteur
router.post("/2fa/confirm", async (req, res) => {
	const { username, userId, code } = req.body || {};

	if (!code || (!username && !userId)) {
		return res.status(400).json({
			error: "Nom d'utilisateur et code TOTP à 6 chiffres requis.",
			code: "MISSING_FIELDS",
		});
	}

	let user = null;
	if (userId) {
		user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
	} else if (username) {
		user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
	}

	if (!user || !user.two_factor_secret) {
		return res.status(404).json({
			error: "Aucun enrôlement 2FA en attente trouvé pour cet agent.",
			code: "NO_2FA_PENDING",
		});
	}

	// Validation mathématique du code TOTP par rapport au secret et à l'heure courante
	const isValid = authenticator.check(code.trim(), user.two_factor_secret);

	if (!isValid) {
		auditLog(user.username, "2FA_CONFIRM_FAILED", req);
		return res.status(401).json({
			error: "Code TOTP invalide ou expiré. Activation 2FA avortée.",
			code: "INVALID_TOTP_CODE",
		});
	}

	// Activation définitive de la 2FA dans la base
	try {
		db.prepare("UPDATE users SET two_factor_enabled = 1 WHERE id = ?").run(user.id);
		auditLog(user.username, "2FA_ENABLED", req);

		return res.json({
			success: true,
			message: "Authentification Double Facteur (2FA) activée avec succès sur le compte.",
			username: user.username,
			two_factor_enabled: 1,
		});
	} catch (err) {
		console.error("Erreur activation two_factor_enabled :", err);
		return res.status(500).json({ error: "Erreur serveur lors de la validation 2FA." });
	}
});

// POST /verify-2fa - Validation finale du second verrou lors de la connexion
router.post("/verify-2fa", async (req, res) => {
	const { username, code } = req.body || {};

	// Compatibilité Challenge 2 (Alfred Batmobile) si l'utilisateur est déjà muni d'un jeton
	if (!username && req.cookies?.token) {
		try {
			const decoded = jwt.verify(req.cookies.token, JWT_SECRET);
			if (code && code.trim() === ALFRED_2FA_CODE) {
				const upgradedToken = jwt.sign(
					{
						id: decoded.id,
						username: decoded.username,
						role: decoded.role,
						scopes: decoded.scopes || getUserScopes(decoded.username, decoded.role),
						is2FAVerified: true,
					},
					JWT_SECRET,
					{ expiresIn: "15m" },
				);
				res.cookie("token", upgradedToken, {
					httpOnly: true,
					sameSite: "strict",
					maxAge: 15 * 60 * 1000,
					secure: false,
				});
				return res.json({
					success: true,
					message: "Protocole 2FA validé. Systèmes tactiques Batmobile opérationnels.",
					token: upgradedToken,
					is2FAVerified: true,
				});
			}
		} catch {
			// Continuer sur le flux standard
		}
	}

	if (!username || !code) {
		return res.status(400).json({
			error: "Identifiant agent et code TOTP obligatoires.",
			code: "MISSING_FIELDS",
		});
	}

	const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
	if (!user || !user.two_factor_secret) {
		return res.status(401).json({
			error: "Agent introuvable ou configuration 2FA inexistante.",
			code: "INVALID_CREDENTIALS",
		});
	}

	// Vérification de la concordance du code TOTP
	const isTotpValid = authenticator.check(code.trim(), user.two_factor_secret);
	const isAlfredFallback = code.trim() === ALFRED_2FA_CODE;

	if (!isTotpValid && !isAlfredFallback) {
		auditLog(user.username, "2FA_LOGIN_FAILED", req);
		return res.status(401).json({
			error: "Code TOTP invalide ou expiré.",
			code: "INVALID_TOTP_CODE",
		});
	}

	// Émission de l'accessToken (15m) et du refreshToken (7 jours)
	const userScopes = getUserScopes(user.username, user.role);

	const accessToken = jwt.sign(
		{
			id: user.id,
			username: user.username,
			role: user.role,
			scopes: userScopes,
			is2FAVerified: true,
		},
		JWT_SECRET,
		{ expiresIn: "15m" },
	);

	const refreshToken = crypto.randomBytes(64).toString("hex");
	const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

	try {
		db.prepare(
			"INSERT INTO refresh_tokens (user_id, token, expires_at, is_used) VALUES (?, ?, ?, 0)",
		).run(user.id, refreshToken, expiresAt);
	} catch (err) {
		console.error("Erreur enregistrement refreshToken post-2FA :", err);
		return res.status(500).json({ error: "Erreur serveur lors de la finalisation 2FA." });
	}

	// Distribution des cookies sécurisés HTTP-Only SameSite=Strict
	res.cookie("token", accessToken, {
		httpOnly: true,
		sameSite: "strict",
		maxAge: 15 * 60 * 1000, // 15 minutes
		secure: false,
	});

	res.cookie("refreshToken", refreshToken, {
		httpOnly: true,
		sameSite: "strict",
		maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
		secure: false,
	});

	auditLog(user.username, "LOGIN_COMPLETE_MFA", req);

	return res.json({
		success: true,
		message: "Double facteur validé. Accès complet accordé à la Batcave.",
		redirect: "/bat-computer",
		accessToken,
		refreshToken,
		expiresIn: 900,
		user: {
			id: user.id,
			username: user.username,
			role: user.role,
			scopes: userScopes,
		},
	});
});

module.exports = router;
