// Point d'entrée principal du serveur de sécurité de la Batcave (TP3)
require("dotenv").config();

const express = require("express");
const path = require("path");
const db = require("./config/database");

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

// Configuration des middlewares pour traiter les données entrantes (JSON et formulaires)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Analyse des cookies HTTP
const cookieParser = require("cookie-parser");
app.use(cookieParser());

// Middleware anti-usurpation d'identité et détection de vol de session (TP2 - Bonus 2)
const { antiHijack } = require("./middlewares/antiHijack");
app.use(antiHijack);

// Mise à disposition des ressources statiques publiques (scripts, CSS)
app.use(express.static(path.join(__dirname, "public")));

// Import des routeurs modulaires
const jwt = require("jsonwebtoken");
const authRouter = require("./routes/auth");
const batcomputerRouter = require("./routes/batcomputer");
const registerRouter = require("./routes/register");
const secretsRouter = require("./routes/secrets");
const reportsRouter = require("./routes/reports");
const adminRouter = require("./routes/admin");

const JWT_SECRET = process.env.JWT_SECRET || "batcave_jwt_secret_token_key_2026_super_secure";

// Montage des routeurs applicatifs
app.use("/auth", authRouter);
app.use("/api/auth", authRouter);
app.use("/", batcomputerRouter);
app.use("/", registerRouter);
app.use("/api", secretsRouter);
app.use("/api/reports", reportsRouter);
app.use("/admin", adminRouter);

// Racine : redirection intelligente selon l'état du jeton d'accès
app.get("/", (req, res) => {
	const token = req.cookies?.token;
	if (token) {
		try {
			jwt.verify(token, JWT_SECRET);
			return res.redirect("/bat-computer");
		} catch {
			// Jeton absent ou expiré
		}
	}
	return res.redirect("/auth/login");
});

// Gestion des routes introuvables (404)
app.use((req, res) => {
	if (req.accepts("html")) {
		return res
			.status(404)
			.send("<h1 style='font-family:sans-serif;'>404 : Signal Batcave Perdu</h1>");
	}
	res.status(404).json({ error: "Ressource introuvable sur le terminal Batcave." });
});

// Démarrage du serveur
if (process.env.NODE_ENV !== "test") {
	app.listen(PORT, () => {
		console.log(`[BATCAVE] Serveur de sécurité actif sur http://localhost:${PORT}`);
	});
}

module.exports = app;
