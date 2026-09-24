// Routeur pour l'arsenal tactique et les informations de profil de session
const express = require("express");
const db = require("../config/database");
const { isAuthenticated } = require("../middlewares/authCheck");
const { checkRole } = require("../middlewares/checkRole");

const router = express.Router();

// GET /api/me - Profil de l'agent authentifié
router.get("/me", isAuthenticated, (req, res) => {
	const user = req.user || req.session?.user;
	res.json({
		id: user.id,
		username: user.username,
		role: user.role,
	});
});

// GET /api/secrets - Arsenal tactique de la Batcave
router.get("/secrets", isAuthenticated, (req, res) => {
	const arsenal = [
		{
			nom: "Batmobile",
			description: "Véhicule d'intervention lourd avec blindage militaire et turboréacteurs.",
			statut: "Opérationnel",
			quantite: 2,
		},
		{
			nom: "Batarang",
			description:
				"Projectiles équilibrés à haute précision avec pointes en alliage de titane.",
			statut: "Opérationnel",
			quantite: 48,
		},
		{
			nom: "Batwing",
			description:
				"Appareil aérien furtif supersonique pour déploiement aéroportuaire rapide.",
			statut: "En maintenance",
			quantite: 1,
		},
		{
			nom: "Grappin Tactique",
			description: "Propulseur d'escalade pneumatique avec câble en nanofibres de carbone.",
			statut: "Opérationnel",
			quantite: 6,
		},
	];

	res.json({ arsenal });
});

// GET /api/admin/logs - Journaux d'audit système (accès restreint ADMIN)
router.get("/admin/logs", isAuthenticated, checkRole("ADMIN"), (req, res) => {
	try {
		const logs = db.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT 50").all();
		res.json(logs);
	} catch (err) {
		console.error("Erreur récupération logs admin :", err);
		res.status(500).json({ error: "Erreur lecture des journaux d'audit." });
	}
});

module.exports = router;
