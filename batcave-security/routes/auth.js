// Routeur d'authentification par session pour la Batcave
const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const db = require("../config/database");

const router = express.Router();

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
		// Table connexions_audit créée lors de la phase bonus
	}
}

// GET /auth/login - Formulaire de connexion sécurisé Batcave
router.get("/login", (req, res) => {
	// Si l'agent possède déjà une session active valide, redirection directe
	if (req.session && req.session.user) {
		return res.redirect("/bat-computer");
	}
	res.sendFile(path.join(__dirname, "..", "views", "login.html"));
});

// POST /auth/login - Vérification des identifiants et création de la session
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

	// Protection anti-fixation de session : régénération obligatoire du session ID
	req.session.regenerate((err) => {
		if (err) {
			console.error("Erreur lors de la régénération de session :", err);
			return res.status(500).json({ error: "Erreur interne de session." });
		}

		// Initialisation du badge de session
		req.session.user = {
			id: user.id,
			username: user.username,
			role: user.role,
		};

		// Enregistrement de l'empreinte client pour l'anti-hijacking (Bonus 2)
		req.session.clientIp = req.ip || req.socket.remoteAddress || "127.0.0.1";
		req.session.userAgent = req.headers["user-agent"] || "";

		// Journalisation de la connexion réussie dans le registre d'audit (Bonus 3)
		auditLog(user.username, "LOGIN", req);

		// Sauvegarde explicite avant la réponse
		req.session.save((saveErr) => {
			if (saveErr) {
				console.error("Erreur de sauvegarde de session :", saveErr);
				return res.status(500).json({ error: "Erreur de persistance de session." });
			}

			if (req.accepts("json") && (req.xhr || req.headers["content-type"]?.includes("json"))) {
				return res.json({
					success: true,
					message: "Connexion autorisée.",
					redirect: "/bat-computer",
					user: req.session.user,
				});
			}

			return res.redirect("/bat-computer");
		});
	});
});

// GET /auth/logout - Destruction de la session et purge du cookie
router.get("/logout", (req, res) => {
	const username = req.session && req.session.user ? req.session.user.username : null;

	if (username) {
		auditLog(username, "LOGOUT", req);
	}

	req.session.destroy((err) => {
		if (err) {
			console.error("Erreur lors de la destruction de la session :", err);
		}
		// Suppression explicite du cookie de session côté client
		res.clearCookie("bat_identity");
		res.redirect("/auth/login");
	});
});

module.exports = router;
