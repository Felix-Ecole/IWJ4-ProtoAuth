// Middleware anti-usurpation d'identité et détection de vol de session (TP2 - Bonus 2)
const db = require("../config/database");

// Normalisation des adresses IP locales pour éviter les faux positifs ::1 vs 127.0.0.1
function normalizeIp(ip) {
	if (!ip) return "127.0.0.1";
	if (ip === "::1" || ip === "::ffff:127.0.0.1") return "127.0.0.1";
	return ip;
}

function antiHijack(req, res, next) {
	// Le contrôle ne s'applique que si une session utilisateur est déjà établie
	if (!req.session || !req.session.user) {
		return next();
	}

	const currentIp = normalizeIp(req.ip || req.socket.remoteAddress);
	const currentUserAgent = req.headers["user-agent"] || "";

	const sessionIp = normalizeIp(req.session.clientIp);
	const sessionUserAgent = req.session.userAgent || "";

	// Vérification de la correspondance stricte de l'empreinte client
	const isIpMismatch = sessionIp && sessionIp !== currentIp;
	const isUserAgentMismatch = sessionUserAgent && sessionUserAgent !== currentUserAgent;

	if (isIpMismatch || isUserAgentMismatch) {
		const username = req.session.user.username;
		console.warn(
			`[ALERTE SÉCURITÉ BATCAVE] Usurpation de session détectée pour l'agent "${username}" !`
		);
		console.warn(`  Attendu : IP=${sessionIp}, UA="${sessionUserAgent}"`);
		console.warn(`  Reçu    : IP=${currentIp}, UA="${currentUserAgent}"`);

		// Journalisation immédiate de la tentative frauduleuse dans connexions_audit (Bonus 3)
		try {
			const stmt = db.prepare(
				"INSERT INTO connexions_audit (username, action, ip_address, user_agent) VALUES (?, 'FRAUD', ?, ?)"
			);
			stmt.run(username, currentIp, currentUserAgent);
		} catch (err) {
			console.error("Erreur enregistrement log FRAUD :", err);
		}

		// Destruction immédiate de la session compromise
		req.session.destroy((err) => {
			if (err) {
				console.error("Erreur destruction session compromise :", err);
			}

			// Invalidation du cookie côté client
			res.clearCookie("bat_identity");

			// Blocage strict de la requête avec code 403 Forbidden
			if (req.accepts("html") && !req.xhr && !req.path.startsWith("/api/")) {
				return res.status(403).send(
					`<!doctype html><html><body style="background:#09090b;color:#ef4444;font-family:sans-serif;padding:2rem;"><h1>403 : Alerte Intrusion Batcave</h1><p>Tentative d'usurpation de badge détectée. Session révoquée d'urgence.</p><p><a href="/auth/login" style="color:#fbbf24;">Retour à la page d'authentification</a></p></body></html>`
				);
			}

			return res.status(403).json({
				error: "Alerte sécurité Batcave : tentative de rejeu ou vol de session détectée (empreinte divergente).",
				fraud: true,
			});
		});
		return;
	}

	next();
}

module.exports = { antiHijack, normalizeIp };
