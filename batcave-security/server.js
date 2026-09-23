// Point d'entrée principal du serveur de sécurité de la Batcave (TP2)
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SqliteStore = require("better-sqlite3-session-store")(session);
const path = require("path");
const db = require("./config/database");

// Initialisation de l'application Express
const app = express();
const PORT = process.env.PORT || 3000;

// Configuration des middlewares pour traiter les données entrantes (JSON et formulaires)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuration du Session Store persistant SQLite (TP2 - Bonus 1)
const sessionStore = new SqliteStore({
	client: db,
	expired: {
		clear: true,
		intervalMs: 900000, // Nettoyage automatique des sessions expirées toutes les 15 minutes
	},
});

// Middleware de session avec politique de cookies sécurisés
app.use(
	session({
		name: "bat_identity",
		secret: process.env.SESSION_SECRET || "batcave_super_secret_session_key_2026_top_secret_bruce_wayne",
		store: sessionStore,
		resave: false,
		saveUninitialized: false,
		cookie: {
			httpOnly: true, // Protection contre les failles XSS
			sameSite: "strict", // Protection contre les attaques CSRF
			maxAge: 1800000, // Expiration automatique au bout de 30 minutes d'inactivité
			secure: false, // Environnement de développement local HTTP
		},
	})
);

// Middleware anti-usurpation d'identité et détection de vol de session (TP2 - Bonus 2)
const { antiHijack } = require("./middlewares/antiHijack");
app.use(antiHijack);

// Mise à disposition des ressources statiques publiques (scripts, CSS)
app.use(express.static(path.join(__dirname, "public")));

// Import des routeurs modulaires
const authRouter = require("./routes/auth");
const batcomputerRouter = require("./routes/batcomputer");
const registerRouter = require("./routes/register");
const secretsRouter = require("./routes/secrets");
const reportsRouter = require("./routes/reports");
const adminRouter = require("./routes/admin");

// Montage des routeurs applicatifs
app.use("/auth", authRouter);
app.use("/", batcomputerRouter);
app.use("/", registerRouter);
app.use("/api", secretsRouter);
app.use("/api/reports", reportsRouter);
app.use("/admin", adminRouter);

// Racine : redirection intelligente selon l'état de la session
app.get("/", (req, res) => {
	if (req.session && req.session.user) {
		return res.redirect("/bat-computer");
	}
	return res.redirect("/auth/login");
});

// Gestion des routes introuvables (404)
app.use((req, res) => {
	if (req.accepts("html")) {
		return res.status(404).send("<h1 style='font-family:sans-serif;'>404 : Signal Batcave Perdu</h1>");
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
