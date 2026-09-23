/**
 * BANC D'ESSAIS AUTOMATISÉ - TP2 : SYSTÈME DE BADGES DE LA BATCAVE
 *
 * Scénarios validés :
 * 1. Accès anonyme à /bat-computer (401 + redirection /auth/login)
 * 2. Inscription et connexion valide via POST /auth/login (réception cookie bat_identity)
 * 3. Accès à /bat-computer avec cookie de session valide (200 OK)
 * 4. Persistance des sessions SQLite après coupure (Bonus 1)
 * 5. Détection d'usurpation de session avec User-Agent pirate (Bonus 2 - Anti-Hijacking -> 403 + destruction)
 * 6. Déconnexion propre via /auth/logout (invalidation cookie et session)
 * 7. Registre connexions_audit et accès réservé ADMIN (Bonus 3)
 */

const { execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const cookieJarBruce = path.join(__dirname, "cookies_bruce.txt");
const cookieJarRobin = path.join(__dirname, "cookies_robin.txt");

// Nettoyage préalable des fichiers temporaires de cookies
if (fs.existsSync(cookieJarBruce)) fs.unlinkSync(cookieJarBruce);
if (fs.existsSync(cookieJarRobin)) fs.unlinkSync(cookieJarRobin);

// Nettoyage et initialisation de la base SQLite pour un banc 100% reproductible
let db;
try {
	db = require(path.join(__dirname, "..", "batcave-security", "config", "database.js"));
	db.prepare("DELETE FROM connexions_audit").run();
	db.prepare("DELETE FROM reports").run();
	db.prepare("DELETE FROM users").run();
	try {
		db.prepare("DELETE FROM sessions").run();
	} catch (e) {
		// Table sessions initialisée à la première requête HTTP
	}
	console.log(">> Base de données SQLite initialisée et prête pour le banc TP2.\n");
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

const DEFAULT_UA = "Bat-Computer-Terminal/2.0 (GothamCity; x64)";
const PIRATE_UA = "Joker-Exploit-Browser/1.0 (ArkhamAsylum; Rogue)";

const tests = [
	{
		title: "1. Accès anonyme à /bat-computer : Rejet 401 Unauthorized et en-tête Location /auth/login",
		cmd: `curl.exe -s -i http://localhost:3000/bat-computer`,
		expected: "401",
		validate: (res) => res.includes("401") && res.toLowerCase().includes("location: /auth/login"),
	},
	{
		title: "2. Création préalable du compte Bruce Wayne (premier compte -> ADMIN)",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\\"username\\":\\"bruce\\",\\"password\\":\\"WaynePassword123!\\"}"',
		expected: "Code: 201",
	},
	{
		title: "3. Connexion Bruce Wayne : POST /auth/login -> Réception cookie signé bat_identity (HttpOnly, SameSite)",
		cmd: `curl.exe -s -i -c "${cookieJarBruce}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d "{\\"username\\":\\"bruce\\",\\"password\\":\\"WaynePassword123!\\"}"`,
		expected: "bat_identity",
		validate: (res) => {
			const hasCookie = res.includes("bat_identity=");
			const isHttpOnly = res.toLowerCase().includes("httponly");
			const isStrict = res.toLowerCase().includes("samesite=strict");
			return hasCookie && isHttpOnly && isStrict;
		},
	},
	{
		title: "4. Accès à /bat-computer avec le badge de session actif de Bruce : 200 OK + vue personnalisée",
		cmd: `curl.exe -s -b "${cookieJarBruce}" -A "${DEFAULT_UA}" http://localhost:3000/bat-computer`,
		expected: "Bienvenue dans la Batcave, agent bruce",
	},
	{
		title: "5. Bonus 1 : Persistance de session dans SQLite (table sessions vérifiée)",
		custom: () => {
			try {
				const row = db.prepare("SELECT COUNT(*) as count FROM sessions").get();
				return `Sessions persistées: ${row.count}`;
			} catch (e) {
				return "Erreur lecture sessions: " + e.message;
			}
		},
		expected: "Sessions persistées: 1",
	},
	{
		title: "6. Création du compte Robin (rôle JUSTICIER)",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\\"username\\":\\"robin\\",\\"password\\":\\"BoyWonder123!\\",\\"role\\":\\"JUSTICIER\\"}"',
		expected: "Code: 201",
	},
	{
		title: "7. Connexion de Robin et obtention de son badge de session propre",
		cmd: `curl.exe -s -i -c "${cookieJarRobin}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d "{\\"username\\":\\"robin\\",\\"password\\":\\"BoyWonder123!\\"}"`,
		expected: "bat_identity",
	},
	{
		title: "8. Bonus 2 (Anti-Hijacking) : Tentative de rejeu du cookie de Robin avec un User-Agent divergent -> 403 Forbidden",
		cmd: `curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJarRobin}" -A "${PIRATE_UA}" http://localhost:3000/api/me`,
		expected: "Code: 403",
	},
	{
		title: "9. Bonus 2 : Invalidation immédiate de la session suite au vol suspect (requête suivante -> 401)",
		cmd: `curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJarRobin}" -A "${DEFAULT_UA}" http://localhost:3000/api/me`,
		expected: "Code: 401",
	},
	{
		title: "10. Déconnexion propre : GET /auth/logout supprime le cookie et révoque la session",
		custom: () => {
			const res = run(`curl.exe -s -i -b "${cookieJarBruce}" -c "${cookieJarBruce}" -A "${DEFAULT_UA}" http://localhost:3000/auth/logout`);
			const isRedirect = res.includes("302") || res.toLowerCase().includes("location: /auth/login");
			const clearsCookie = res.includes("bat_identity=;");
			return isRedirect && clearsCookie ? "LOGOUT_SUCCESS" : "LOGOUT_FAILED: " + res;
		},
		expected: "LOGOUT_SUCCESS",
	},
	{
		title: "11. Vérification post-logout : L'ancien cookie de Bruce est désormais refusé sur /bat-computer -> 401",
		cmd: `curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJarBruce}" -A "${DEFAULT_UA}" http://localhost:3000/bat-computer`,
		expected: "Code: 401",
	},
	{
		title: "12. Bonus 3 : Vérification du registre connexions_audit en base SQLite (LOGIN, LOGOUT, FRAUD consignés)",
		custom: () => {
			try {
				const events = db.prepare("SELECT action FROM connexions_audit ORDER BY id ASC").all();
				const actions = events.map((e) => e.action);
				const hasLogin = actions.includes("LOGIN");
				const hasLogout = actions.includes("LOGOUT");
				const hasFraud = actions.includes("FRAUD");
				return hasLogin && hasLogout && hasFraud
					? `AUDIT_OK: ${actions.join(",")}`
					: `AUDIT_INCOMPLETE: ${actions.join(",")}`;
			} catch (e) {
				return "Erreur audit: " + e.message;
			}
		},
		expected: "AUDIT_OK",
	},
	{
		title: "13. Bonus 3 : Reconnexion de Bruce et consultation exclusive de la console d'audit (/admin/api/audit-logs -> 200)",
		custom: () => {
			run(`curl.exe -s -c "${cookieJarBruce}" -A "${DEFAULT_UA}" -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -d "{\\"username\\":\\"bruce\\",\\"password\\":\\"WaynePassword123!\\"}"`);
			const res = run(`curl.exe -s -w " [Code: %{http_code}]" -b "${cookieJarBruce}" -A "${DEFAULT_UA}" http://localhost:3000/admin/api/audit-logs`);
			return res;
		},
		expected: "Code: 200",
	},
];

console.log("================================================================================");
console.log("    RAPPORT OFFICIEL DE VALIDATION DU BANC TP2 - BADGES DE LA BATCAVE           ");
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

// Nettoyage final des jars
if (fs.existsSync(cookieJarBruce)) fs.unlinkSync(cookieJarBruce);
if (fs.existsSync(cookieJarRobin)) fs.unlinkSync(cookieJarRobin);

console.log("\n--------------------------------------------------------------------------------");
console.log(`RÉSULTAT FINAL DU BANC TP2 : ${passed}/${tests.length} tests validés.`);
console.log("--------------------------------------------------------------------------------");

if (passed === tests.length) {
	console.log(">> TOUTES LES EXIGENCES ET LES 3 BONUS DU TP2 SONT PARFAITEMENT VALIDÉS !");
	process.exit(0);
} else {
	console.log(">> CERTAINS TESTS N'ONT PAS ABOUTI. VÉRIFICATION DU SERVEUR REQUISE.");
	process.exit(1);
}
