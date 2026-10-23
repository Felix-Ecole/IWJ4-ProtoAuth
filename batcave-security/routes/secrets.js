const express = require("express");
const db = require("../config/database");
const { isAuthenticated, require2FA } = require("../middlewares/authCheck");
const { checkRole } = require("../middlewares/checkRole");
const { checkScope } = require("../middlewares/checkScope");

const router = express.Router();

// GET /api/me - Profil de l'agent authentifié
router.get("/me", isAuthenticated, (req, res) => {
	const user = req.user || req.session?.user;
	res.json({
		id: user.id,
		username: user.username,
		role: user.role,
		scopes: user.scopes || [],
	});
});

// GET /api/secrets - Arsenal tactique de la Batcave (requiert le scope armory:weapons)
router.get("/secrets", isAuthenticated, checkScope("armory:weapons"), (req, res) => {
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

// GET /api/batmobile/systems - Commandes tactiques Batmobile (Challenge 2 - 2FA requis & scope batmobile:control)
router.get(
	"/batmobile/systems",
	isAuthenticated,
	require2FA,
	checkScope("batmobile:control"),
	(req, res) => {
	res.json({
		status: "ACTIF",
		agent: req.user.username,
		twoFactorCertified: true,
		systems: {
			turboreacteurs: "100% de puissance",
			blindageActif: "Alliage titane renforce - Actif",
			contreMesures: "Leurres thermiques et brouillage radar armes",
			autodestruction: "Desactivee (code Alfred requis)",
		},
	});
});

// GET /api/suit/status - Télémétrie de la Bat-Armure (Challenge 3 - Support Authorization Bearer)
router.get("/suit/status", isAuthenticated, (req, res) => {
	res.json({
		suit: "Bat-Armure Mk-VII",
		pilot: req.user.username,
		authMode: req.headers.authorization ? "BEARER_TOKEN" : "HTTP_COOKIE",
		telemetry: {
			armorIntegrity: "98.4%",
			energyReserve: "94.2%",
			stealthCloak: "OPERATIONNEL",
			hudLink: "CONNECTE",
		},
	});
});

module.exports = router;
