/**
 * BANC D'ESSAIS AUTOMATISÉ - TP3 : SYSTÈME DE JETONS DE LA BATCAVE
 *
 * Scénarios validés :
 * 1. Accès anonyme à /bat-computer : rejet 401 Unauthorized + redirection /auth/login
 * 2. Connexion Bruce Wayne (POST /auth/login) : émission conjointe de 2 cookies sécurisés (token 15s + refreshToken 7j)
 * 3. Persistance du refreshToken en base SQLite (table refresh_tokens)
 * 4. Accès autorisé à /api/me avec accessToken JWT actif (200 OK)
 * 5. Accès autorisé à l'arsenal /api/secrets avec accessToken JWT actif (200 OK)
 * 6. Expiration du jeton d'accès (15 secondes) : rejet 401 sur requête avec token expiré
 * 7. Rafraîchissement transparent via POST /api/auth/refresh avec le refreshToken (200 OK + nouveau token émis)
 * 8. Accès rétabli à /api/me après renouvellement transparent (200 OK)
 * 9. Modification mot de passe (règle ANSSI) : rejet d'un mot de passe trop court (< 12 car.) -> 400
 * 10. Modification mot de passe (règle ANSSI) : rejet d'une ancienne clé erronée -> 401
 * 11. Modification mot de passe (règle ANSSI) : succès avec clé complexe (12+ car, maj, min, chiffre, symbole) -> 200
 * 12. Rétablissement de la clé initiale de Bruce pour garantir l'idempotence
 * 13. Déconnexion avec révocation (POST /auth/logout) : suppression des cookies et purge SQLite
 * 14. Contrôle post-révocation : tentative de refresh avec l'ancien refreshToken purgé -> 401 Rejeté
 */

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const cookieJar = path.join(__dirname, "cookies_tp3.txt");

// Nettoyage préalable du fichier temporaire de cookies
if (fs.existsSync(cookieJar)) fs.unlinkSync(cookieJar);

// Initialisation et nettoyage de la base SQLite pour un banc 100% reproductible
let db;
try {
	db = require(path.join(__dirname, "..", "batcave-security", "config", "database.js"));
	db.prepare("DELETE FROM refresh_tokens").run();
	console.log(">> Base de données SQLite connectée. Table refresh_tokens initialisée pour le banc TP3.\n");
} catch (e) {
	console.log(">> Attention : Accès direct SQLite impossible via le banc de test :", e.message);
}

function run(cmd) {
	try {
		return execSync(cmd, { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
	} catch (e) {
		const out = e.stdout ? e.stdout.trim() : "";
		const err = e.stderr ? e.stderr.trim() : "";
		return (out + " " + err).trim();
	}
}

function sleep(ms) {
	const start = Date.now();
	while (Date.now() - start < ms) {
		// Attente synchrone sans bloquer l'interpréteur
	}
}

const DEFAULT_UA = "Bat-Computer-Terminal/3.0 (GothamCity; x64)";

let capturedRefreshToken = "";

const tests = [
	{
		title: "1. Accès anonyme à /bat-computer : Rejet 401 Unauthorized et en-tête Location /auth/login",
		cmd: "curl.exe -s -i http://localhost:3000/bat-computer",
		validate: (res) => res.includes("401") && res.toLowerCase().includes("location: /auth/login"),
		expected: "401 + Location /auth/login",
	},
	{
		title: "2. Connexion Bruce Wayne : POST /auth/login -> Réception des 2 cookies sécurisés (token & refreshToken)",
		cmd: `curl.exe -s -i -c "${cookieJar}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d "{\\"username\\":\\"bruce\\",\\"password\\":\\"WaynePassword123!\\"}"`,
		validate: (res) => {
			const hasToken = res.includes("token=");
			const hasRefresh = res.includes("refreshToken=");
			const isHttpOnly = res.toLowerCase().includes("httponly");
			const isStrict = res.toLowerCase().includes("samesite=strict");
			return hasToken && hasRefresh && isHttpOnly && isStrict;
		},
		expected: "Cookies 'token' et 'refreshToken' reçus avec flags HttpOnly et SameSite=Strict",
	},
	{
		title: "3. Persistance du refreshToken en base SQLite (table refresh_tokens vérifiée)",
		custom: () => {
			try {
				const row = db.prepare("SELECT COUNT(*) as count, token FROM refresh_tokens").get();
				if (row && row.count > 0) {
					capturedRefreshToken = row.token;
					return `Tokens en BDD: ${row.count}`;
				}
				return "Aucun token stocké en BDD";
			} catch (e) {
				return "Erreur lecture refresh_tokens: " + e.message;
			}
		},
		expected: "Tokens en BDD: 1",
	},
	{
		title: "4. Accès à /api/me avec accessToken valide : 200 OK et restitution du profil de Bruce (ADMIN)",
		cmd: `curl.exe -s -b "${cookieJar}" -A "${DEFAULT_UA}" http://localhost:3000/api/me`,
		validate: (res) => res.includes('"username":"bruce"') && res.includes('"role":"ADMIN"'),
		expected: '{"id":...,"username":"bruce","role":"ADMIN"}',
	},
	{
		title: "5. Accès à /api/secrets avec accessToken valide : 200 OK et restitution de l'arsenal",
		cmd: `curl.exe -s -b "${cookieJar}" -A "${DEFAULT_UA}" http://localhost:3000/api/secrets`,
		validate: (res) => res.includes("Batmobile") && res.includes("Batarang"),
		expected: "Arsenal complet retourné",
	},
	{
		title: "6. Cycle d'expiration du jeton d'accès (simulation 16 secondes d'attente pour dépasser les 15s)...",
		custom: () => {
			console.log("   [INFO] Pause chronométrée de 16 secondes pour franchir l'espérance de vie de 15s du JWT...");
			sleep(16000);
			// Requête directe sans rafraîchissement avec le cookie token expiré uniquement
			const res = run(`curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJar}" -A "${DEFAULT_UA}" http://localhost:3000/api/me`);
			return res;
		},
		validate: (res) => res.includes("Code: 401") || res.includes("TOKEN_EXPIRED"),
		expected: "Code: 401 (Jeton d'accès expiré)",
	},
	{
		title: "7. Rafraîchissement transparent : POST /api/auth/refresh avec le refreshToken valide -> 200 OK",
		cmd: `curl.exe -s -i -b "${cookieJar}" -c "${cookieJar}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/api/auth/refresh`,
		validate: (res) => res.includes("200 OK") && res.includes("token="),
		expected: "200 OK + nouveau cookie token émis",
	},
	{
		title: "8. Accès rétabli à /api/me avec le nouveau jeton d'accès : 200 OK",
		cmd: `curl.exe -s -b "${cookieJar}" -A "${DEFAULT_UA}" http://localhost:3000/api/me`,
		validate: (res) => res.includes('"username":"bruce"'),
		expected: "Profil bruce accessible",
	},
	{
		title: "9. Modification de mot de passe (ANSSI) : Rejet mot de passe trop court (< 12 caractères) -> 400",
		cmd: `curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJar}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/api/auth/change-password -H "Content-Type: application/json" -d "{\\"oldPassword\\":\\"WaynePassword123!\\",\\"newPassword\\":\\"Court1!\\",\\"confirmPassword\\":\\"Court1!\\"}"`,
		validate: (res) => res.includes("400"),
		expected: "Code: 400",
	},
	{
		title: "10. Modification de mot de passe (ANSSI) : Rejet ancienne clé erronée -> 401",
		cmd: `curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJar}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/api/auth/change-password -H "Content-Type: application/json" -d "{\\"oldPassword\\":\\"FauxPassword123!\\",\\"newPassword\\":\\"WayneSecure2026!\\",\\"confirmPassword\\":\\"WayneSecure2026!\\"}"`,
		validate: (res) => res.includes("401"),
		expected: "Code: 401",
	},
	{
		title: "11. Modification de mot de passe (ANSSI) : Succès avec clé conforme (12+ car, maj, min, chiffre, symbole)",
		cmd: `curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJar}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/api/auth/change-password -H "Content-Type: application/json" -d "{\\"oldPassword\\":\\"WaynePassword123!\\",\\"newPassword\\":\\"WayneSecure2026!\\",\\"confirmPassword\\":\\"WayneSecure2026!\\"}"`,
		validate: (res) => res.includes("200"),
		expected: "Code: 200",
	},
	{
		title: "12. Rétablissement de la clé initiale de Bruce pour garantir l'intégrité du banc",
		cmd: `curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJar}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/api/auth/change-password -H "Content-Type: application/json" -d "{\\"oldPassword\\":\\"WayneSecure2026!\\",\\"newPassword\\":\\"WaynePassword123!\\",\\"confirmPassword\\":\\"WaynePassword123!\\"}"`,
		validate: (res) => res.includes("200"),
		expected: "Code: 200",
	},
	{
		title: "13. Déconnexion avec révocation (POST /auth/logout) : suppression des cookies et purge SQLite",
		custom: () => {
			const res = run(
				`curl.exe -s -i -b "${cookieJar}" -c "${cookieJar}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/auth/logout -H "Accept: application/json"`
			);
			const tokenInDb = db.prepare("SELECT * FROM refresh_tokens WHERE token = ?").get(capturedRefreshToken);
			const isPurged = !tokenInDb;
			return isPurged ? "REVOCATION_SUCCESS" : "REVOCATION_FAILED";
		},
		expected: "REVOCATION_SUCCESS",
	},
	{
		title: "14. Tentative de refresh avec le refreshToken révoqué -> Rejet 401 Unauthorized",
		cmd: `curl.exe -s -w " [Code: %{http_code}]" -A "${DEFAULT_UA}" -X POST http://localhost:3000/api/auth/refresh -H "Content-Type: application/json" -d "{\\"refreshToken\\":\\"${capturedRefreshToken}\\"}"`,
		validate: (res) => res.includes("401"),
		expected: "Code: 401",
	},
];

console.log("================================================================================");
console.log("    RAPPORT OFFICIEL DE VALIDATION DU BANC TP3 - SYSTÈME DE JETONS BATCAVE     ");
console.log("================================================================================\n");

let passed = 0;
for (const t of tests) {
	const res = t.custom ? t.custom() : run(t.cmd);
	const ok = t.validate ? t.validate(res) : res.includes(t.expected);
	if (ok) passed++;

	console.log(`[${ok ? "OK" : "KO"}] ${t.title}`);
	if (!ok) {
		console.log(`   Attendu: "${t.expected}"`);
		console.log(`   Reçu:    "${res.length > 250 ? res.slice(0, 250) + "..." : res}"\n`);
	}
}

// Nettoyage final du fichier temporaire de cookies
if (fs.existsSync(cookieJar)) fs.unlinkSync(cookieJar);

console.log("\n--------------------------------------------------------------------------------");
console.log(`RÉSULTAT FINAL DU BANC TP3 : ${passed}/${tests.length} tests validés.`);
console.log("--------------------------------------------------------------------------------");

if (passed === tests.length) {
	console.log(">> TOUTES LES ÉTAPES DU TP3 (CYCLE JWT, 15S, REFRESH, ANSSI, RÉVOCATION) SONT VALIDÉES !");
	process.exit(0);
} else {
	console.log(">> CERTAINS TESTS N'ONT PAS ABOUTI. VÉRIFICATION DU SERVEUR REQUISE.");
	process.exit(1);
}
