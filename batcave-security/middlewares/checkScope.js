// Middleware de contrôle fin des privilèges par scopes OAuth2 (TP4 - Challenge 2)

/**
 * Middleware vérifiant si l'agent dispose du scope requis dans son jeton JWT
 * @param {string} requiredScope - Scope nécessaire pour exécuter l'action (ex: 'batmobile:control')
 */
function checkScope(requiredScope) {
	return (req, res, next) => {
		// Vérification de la présence de l'utilisateur authentifié
		if (!req.user) {
			return res.status(401).json({
				error: "Non authentifié : jeton d'accès manquant ou invalide.",
				code: "UNAUTHENTICATED",
			});
		}

		const scopes = Array.isArray(req.user.scopes) ? req.user.scopes : [];

		// Contrôle de présence du scope requis ou du passe-partout administrateur
		const hasAccess =
			scopes.includes(requiredScope) ||
			scopes.includes("all:admin") ||
			scopes.includes("computers:admin");

		if (!hasAccess) {
			return res.status(403).json({
				error: `Accès refusé : privilège manquant. Le scope '${requiredScope}' est requis pour cette opération tactique.`,
				code: "INSUFFICIENT_SCOPE",
				requiredScope,
			});
		}

		return next();
	};
}

module.exports = { checkScope };
