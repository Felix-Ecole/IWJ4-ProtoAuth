// Middleware de vérification du jeton d'accès JWT pour la Batcave (TP3)
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "batcave_jwt_secret_token_key_2026_super_secure";

function checkJWT(req, res, next) {
	// Extraction du jeton depuis les cookies ou depuis l'en-tête Authorization (Bearer)
	let token = req.cookies?.token;

	const authHeader = req.headers.authorization;
	if (!token && authHeader && authHeader.startsWith("Bearer ")) {
		token = authHeader.split(" ")[1];
	}

	if (!token) {
		res.status(401);
		res.setHeader("Location", "/auth/login");

		if (req.accepts("html") && !req.xhr && !req.path.startsWith("/api/")) {
			return res.send(
				`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/auth/login"></head><body style="background:#09090b;color:#f4f4f5;font-family:sans-serif;padding:2rem;"><p>401 Non autorisé. Redirection vers <a href="/auth/login" style="color:#fbbf24;">/auth/login</a>...</p></body></html>`,
			);
		}

		return res.status(401).json({
			error: "Jeton d'accès manquant ou non fourni.",
			code: "TOKEN_EXPIRED",
			redirect: "/auth/login",
		});
	}

	try {
		// Validation cryptographique de l'accessToken
		const decoded = jwt.verify(token, JWT_SECRET);
		req.user = decoded;
		return next();
	} catch (err) {
		res.status(401);
		res.setHeader("Location", "/auth/login");

		if (req.accepts("html") && !req.xhr && !req.path.startsWith("/api/")) {
			return res.send(
				`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/auth/login"></head><body style="background:#09090b;color:#f4f4f5;font-family:sans-serif;padding:2rem;"><p>401 Session expirée. Redirection vers <a href="/auth/login" style="color:#fbbf24;">/auth/login</a>...</p></body></html>`,
			);
		}

		return res.status(401).json({
			error: "Jeton d'accès expiré ou invalide.",
			code: "TOKEN_EXPIRED",
			redirect: "/auth/login",
		});
	}
}

// Middleware de contrôle du second facteur d'authentification 2FA (Challenge 2)
function require2FA(req, res, next) {
	if (!req.user || !req.user.is2FAVerified) {
		return res.status(403).json({
			error: "Accès refusé : validation du second facteur (2FA) requise pour ce système critique.",
			code: "2FA_REQUIRED",
		});
	}
	return next();
}

// Alias de compatibilité pour les routeurs existants
const isAuthenticated = checkJWT;

module.exports = { checkJWT, isAuthenticated, require2FA };
