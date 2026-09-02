const express = require("express");
const path = require("path");
const db = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;

// Traitement des requetes JSON et formulaires
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Verification de l'etat du serveur
app.get("/", (req, res) => {
	res.json({ status: "ok", message: "Système de sécurité de la Batcave actif." });
});

// Demarrage du serveur uniquement en execution directe
if (require.main === module) {
	app.listen(PORT, () => {
		console.log(`Batcave Security Server en ligne sur http://localhost:${PORT}`);
	});
}

module.exports = app;
