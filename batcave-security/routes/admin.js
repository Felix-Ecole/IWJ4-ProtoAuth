// Routeur d'administration et consultation du registre d'audit des connexions (Bonus 3)
const express = require("express");
const path = require("path");
const db = require("../config/database");
const { isAuthenticated } = require("../middlewares/authCheck");
const { checkRole } = require("../middlewares/checkRole");

const router = express.Router();

// Protection globale : réservation stricte aux agents dotés du rôle ADMIN
router.use(isAuthenticated);
router.use(checkRole("ADMIN"));

// GET /admin/audit - Interface visuelle de la console d'audit des connexions
router.get("/audit", (req, res) => {
	res.sendFile(path.join(__dirname, "..", "views", "audit.html"));
});

// GET /admin/api/audit-logs - API JSON du journal d'audit filtrable et triable
router.get("/api/audit-logs", (req, res) => {
	const { action, limit = 100 } = req.query;

	try {
		let query = "SELECT * FROM connexions_audit";
		const params = [];

		if (action && ["LOGIN", "LOGOUT", "FRAUD"].includes(action.toUpperCase())) {
			query += " WHERE action = ?";
			params.push(action.toUpperCase());
		}

		query += " ORDER BY id DESC LIMIT ?";
		params.push(Number(limit) || 100);

		const logs = db.prepare(query).all(...params);

		// Statistiques agrégées pour la console d'audit
		const stats = {
			total: db.prepare("SELECT COUNT(*) as count FROM connexions_audit").get().count,
			login: db.prepare("SELECT COUNT(*) as count FROM connexions_audit WHERE action = 'LOGIN'").get().count,
			logout: db.prepare("SELECT COUNT(*) as count FROM connexions_audit WHERE action = 'LOGOUT'").get().count,
			fraud: db.prepare("SELECT COUNT(*) as count FROM connexions_audit WHERE action = 'FRAUD'").get().count,
		};

		res.json({ stats, logs });
	} catch (err) {
		console.error("Erreur lecture audit-logs :", err);
		res.status(500).json({ error: "Erreur interne lors de la récupération des logs d'audit." });
	}
});

module.exports = router;
