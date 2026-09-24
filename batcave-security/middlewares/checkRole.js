// Middleware de contrôle d'accès basé sur les rôles (RBAC) pour JWT
function checkRole(...allowedRoles) {
	return (req, res, next) => {
		const user = req.user || req.session?.user;

		if (!user || !allowedRoles.includes(user.role)) {
			return res.status(403).json({
				error: "403 : Accès refusé. Privilèges insuffisants pour cette opération.",
			});
		}

		next();
	};
}

module.exports = { checkRole };
