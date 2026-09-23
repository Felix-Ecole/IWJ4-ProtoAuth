// Middleware de contrôle d'accès pour vérifier la présence d'une session active
function isAuthenticated(req, res, next) {
	if (req.session && req.session.user) {
		return next();
	}

	// Si l'utilisateur n'est pas connecté, renvoi du statut 401 avec en-tête de redirection
	res.status(401);
	res.setHeader("Location", "/auth/login");

	// Réponse adaptée selon le type de contenu attendu par le client
	if (req.accepts("html") && !req.xhr && !req.path.startsWith("/api/")) {
		return res.send(
			`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/auth/login"></head><body style="background:#09090b;color:#f4f4f5;font-family:sans-serif;padding:2rem;"><p>401 Non autorisé. Redirection vers <a href="/auth/login" style="color:#fbbf24;">/auth/login</a>...</p></body></html>`
		);
	}

	return res.json({
		error: "Accès refusé : badge d'accès ou session invalide.",
		redirect: "/auth/login",
	});
}

module.exports = { isAuthenticated };
