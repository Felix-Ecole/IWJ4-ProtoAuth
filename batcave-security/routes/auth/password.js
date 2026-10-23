// Gestion de la modification sécurisée de mot de passe (critères ANSSI)
const express = require("express");
const bcrypt = require("bcrypt");
const db = require("../../config/database");
const { checkJWT } = require("../../middlewares/authCheck");
const { ANSSI_PASSWORD_REGEX, auditLog } = require("./helpers");

const router = express.Router();

// POST /change-password - Modification de la clé de sécurité agent
router.post("/change-password", checkJWT, async (req, res) => {
	const { oldPassword, newPassword, confirmPassword } = req.body || {};
	const userId = req.user?.id;

	if (!userId) {
		return res.status(401).json({ error: "Session non authentifiée." });
	}

	if (!oldPassword || !newPassword || !confirmPassword) {
		return res.status(400).json({ error: "Tous les champs de sécurité sont obligatoires." });
	}

	if (newPassword !== confirmPassword) {
		return res.status(400).json({
			error: "Le nouveau mot de passe et sa confirmation ne correspondent pas.",
		});
	}

	if (oldPassword === newPassword) {
		return res.status(400).json({
			error: "Le nouveau mot de passe doit être différent de l'ancienne clé.",
		});
	}

	// Validation stricte des critères de robustesse ANSSI
	if (!ANSSI_PASSWORD_REGEX.test(newPassword)) {
		return res.status(400).json({
			error:
				"Le mot de passe ne respecte pas les critères ANSSI : minimum 12 caractères, avec au moins une majuscule, une minuscule, un chiffre et un caractère spécial.",
		});
	}

	// Recherche de l'utilisateur dans la base SQLite
	const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
	if (!user) {
		return res.status(404).json({ error: "Agent introuvable en base de données." });
	}

	// Contrôle de l'ancien mot de passe via Bcrypt
	const isOldValid = await bcrypt.compare(oldPassword, user.password);
	if (!isOldValid) {
		return res.status(401).json({ error: "L'ancienne clé de sécurité saisie est incorrecte." });
	}

	// Hachage du nouveau mot de passe avec Bcrypt (coût 10)
	const saltRounds = 10;
	const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

	// Enregistrement de la nouvelle clé en base
	try {
		db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashedPassword, userId);
		auditLog(user.username, "PASSWORD_CHANGED", req);

		return res.json({
			success: true,
			message: "Clé de sécurité mise à jour avec succès selon les critères ANSSI.",
		});
	} catch (err) {
		console.error("Erreur lors de la mise à jour du mot de passe :", err);
		return res.status(500).json({
			error: "Erreur serveur lors de l'enregistrement de la nouvelle clé.",
		});
	}
});

module.exports = router;
