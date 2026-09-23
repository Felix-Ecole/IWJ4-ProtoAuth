// Routeur de gestion des rapports de mission de la Batcave
const express = require("express");
const db = require("../config/database");
const { isAuthenticated } = require("../middlewares/authCheck");

const router = express.Router();

// Application du vigile d'authentification sur toutes les routes de rapports
router.use(isAuthenticated);

// POST /api/reports - Enregistrement d'un rapport de mission
router.post("/", (req, res) => {
	const user = req.session.user;
	const { title, content } = req.body || {};

	if (!title || !title.trim() || !content || !content.trim()) {
		return res.status(400).json({ error: "Titre et contenu du rapport obligatoires." });
	}

	try {
		const stmt = db.prepare(
			"INSERT INTO reports (user_id, title, content) VALUES (?, ?, ?)"
		);
		const info = stmt.run(user.id, title.trim(), content.trim());

		return res.status(201).json({
			success: true,
			message: "Rapport de mission consigné avec succès.",
			reportId: info.lastInsertRowid,
		});
	} catch (err) {
		console.error("Erreur insertion rapport :", err);
		return res.status(500).json({ error: "Erreur serveur lors de la sauvegarde du rapport." });
	}
});

// GET /api/reports - Consultation de l'historique des rapports
router.get("/", (req, res) => {
	const user = req.session.user;

	try {
		let query;
		let reports;

		if (user.role === "ADMIN") {
			// L'administrateur dispose d'une vision globale sur l'ensemble des rapports
			query = `
				SELECT reports.id, reports.title, reports.content, reports.created_at, users.username as author
				FROM reports
				JOIN users ON users.id = reports.user_id
				ORDER BY reports.created_at DESC
			`;
			reports = db.prepare(query).all();
		} else {
			// Les justiciers et assistants consultent exclusivement leurs propres saisies
			query = `
				SELECT reports.id, reports.title, reports.content, reports.created_at, users.username as author
				FROM reports
				JOIN users ON users.id = reports.user_id
				WHERE reports.user_id = ?
				ORDER BY reports.created_at DESC
			`;
			reports = db.prepare(query).all(user.id);
		}

		return res.json({
			scope: user.role === "ADMIN" ? "Tous les rapports (Supervision Admin)" : "Mes rapports de mission",
			reports: reports || [],
		});
	} catch (err) {
		console.error("Erreur récupération rapports :", err);
		return res.status(500).json({ error: "Impossible de récupérer les rapports." });
	}
});

module.exports = router;
