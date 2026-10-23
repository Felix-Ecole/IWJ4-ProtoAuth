// Helpers et constantes partagées pour le module d'authentification de la Batcave
const db = require("../../config/database");

const JWT_SECRET = process.env.JWT_SECRET || "batcave_jwt_secret_token_key_2026_super_secure";
const ALFRED_2FA_CODE = process.env.ALFRED_2FA_CODE || "BAT-2026";

// Recommandation ANSSI : 12 caractères min, majuscule, minuscule, chiffre et caractère spécial
const ANSSI_PASSWORD_REGEX =
	/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{12,}$/;

// Détermination des scopes OAuth2 selon le profil et les accréditations de l'agent
function getUserScopes(username, role) {
	const normalizedUser = (username || "").toLowerCase().trim();
	const normalizedRole = (role || "").toUpperCase().trim();

	if (
		normalizedUser === "batman" ||
		normalizedUser.startsWith("batman") ||
		normalizedUser === "bruce" ||
		normalizedUser.startsWith("bruce") ||
		normalizedRole === "ADMIN"
	) {
		return ["computers:admin", "batmobile:control", "armory:weapons", "reports:write"];
	}
	if (
		normalizedUser === "nightwing" ||
		normalizedUser.startsWith("nightwing") ||
		normalizedUser === "oracle" ||
		normalizedUser.startsWith("oracle")
	) {
		return ["computers:read", "batmobile:status", "reports:read"];
	}
	// Rôle JUSTICIER standard
	return ["computers:read", "armory:weapons"];
}

// Journalisation de sécurité des actions critiques dans connexions_audit
function auditLog(username, action, req) {
	try {
		const ip = req.ip || req.socket.remoteAddress || "127.0.0.1";
		const userAgent = req.headers["user-agent"] || "inconnu";
		const stmt = db.prepare(
			"INSERT INTO connexions_audit (username, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
		);
		stmt.run(username || "anonyme", action, ip, userAgent);
	} catch (e) {
		// Table d'audit optionnelle
	}
}

module.exports = {
	JWT_SECRET,
	ALFRED_2FA_CODE,
	ANSSI_PASSWORD_REGEX,
	getUserScopes,
	auditLog,
};
