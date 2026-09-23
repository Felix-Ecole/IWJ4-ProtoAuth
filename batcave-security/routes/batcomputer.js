// Routeur pour la console Batcomputer sécurisée
const express = require("express");
const path = require("path");
const fs = require("fs");
const { isAuthenticated } = require("../middlewares/authCheck");

const router = express.Router();

// GET /bat-computer - Console Batcomputer sécurisée
router.get("/bat-computer", isAuthenticated, (req, res) => {
	const user = req.session.user;
	const viewPath = path.join(__dirname, "..", "views", "bat-computer.html");

	fs.readFile(viewPath, "utf-8", (err, html) => {
		if (err) {
			console.error("Erreur lecture vue bat-computer :", err);
			return res.status(500).send("Erreur lors du chargement de la console Batcave.");
		}

		// Remplacement des balises par les informations de l'agent authentifié
		const customized = html
			.replace(/__USERNAME__/g, user.username)
			.replace(/__ROLE__/g, user.role);

		res.send(customized);
	});
});

module.exports = router;
