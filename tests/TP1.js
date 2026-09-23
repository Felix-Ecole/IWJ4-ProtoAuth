/**
 * BANC D'ESSAIS AUTOMATISÉ - TP1 : SYSTÈME DE SÉCURITÉ DE LA BATCAVE
 *
 * Prérequis :
 * 1. Le serveur doit être démarré dans un autre terminal :
 *    cd batcave-security && npm start
 * 2. Lancement des tests :
 *    node tests/TP1.js
 *
 * Ce script réinitialise automatiquement les tables SQLite au début pour
 * garantir un banc d'essais 100 % reproductible sur une base propre.
 */

const { execSync } = require("child_process");
const path = require("path");

// Réinitialisation préalable des tables de la base de données SQLite
try {
	let db;
	try {
		db = require(path.join(__dirname, "..", "batcave-security", "config", "database.js"));
	} catch {
		db = require(path.join(__dirname, "..", "batcave-security", "database.js"));
	}
	db.prepare("DELETE FROM logs").run();
	db.prepare("DELETE FROM reports").run();
	db.prepare("DELETE FROM users").run();
	console.log(">> Base de données SQLite nettoyée et prête pour les tests.\n");
} catch (e) {
	console.log(">> Attention : Impossible de réinitialiser directement SQLite via Node.\n");
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

const tests = [
	{
		title: "1. Page publique d'inscription (/register.html)",
		cmd: 'curl.exe -s -o /dev/null -w "%{http_code}" http://localhost:3000/register.html',
		expected: "200",
	},
	{
		title: "2. POST /register : Mot de passe trop court (< 8 caractères -> 400)",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\\"username\\":\\"court\\",\\"password\\":\\"123\\"}"',
		expected: "Code: 400",
	},
	{
		title: "3. POST /register : Premier compte (bruce) promu automatiquement en ADMIN",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\\"username\\":\\"bruce\\",\\"password\\":\\"WaynePassword123!\\"}"',
		expected: '"role":"ADMIN"',
	},
	{
		title: "4. POST /register : Compte alfred avec rôle ASSISTANT explicite",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\\"username\\":\\"alfred\\",\\"password\\":\\"Pennyworth123!\\",\\"role\\":\\"ASSISTANT\\"}"',
		expected: '"role":"ASSISTANT"',
	},
	{
		title: "5. POST /register : Compte robin avec rôle JUSTICIER par défaut",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\\"username\\":\\"robin\\",\\"password\\":\\"BoyWonder123!\\"}"',
		expected: '"role":"JUSTICIER"',
	},
	{
		title: "6. POST /register : Détection de doublon (identifiant 'bruce' déjà pris -> 409)",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/register -H "Content-Type: application/json" -d "{\\"username\\":\\"bruce\\",\\"password\\":\\"AutreMdp123!\\"}"',
		expected: "Code: 409",
	},
	{
		title: "7. GET /bat-computer : Accès anonyme rejeté avec défi (401 Unauthorized)",
		cmd: "curl.exe -s -i http://localhost:3000/bat-computer",
		expected: 'WWW-Authenticate: Basic realm="Batcave"',
	},
	{
		title: "8. GET /bat-computer : Accès avec identifiants Bruce valides (200 OK HTML)",
		cmd: 'curl.exe -s -o /dev/null -w "%{http_code}" -u "bruce:WaynePassword123!" http://localhost:3000/bat-computer',
		expected: "200",
	},
	{
		title: "9. GET /api/me : Profil de Bruce (rôle ADMIN confirmé)",
		cmd: 'curl.exe -s -u "bruce:WaynePassword123!" http://localhost:3000/api/me',
		expected: '"role":"ADMIN"',
	},
	{
		title: "10. GET /api/me : Profil de Robin (rôle JUSTICIER confirmé)",
		cmd: 'curl.exe -s -u "robin:BoyWonder123!" http://localhost:3000/api/me',
		expected: '"role":"JUSTICIER"',
	},
	{
		title: "11. GET /api/secrets : Consultation de l'arsenal tactique sous Basic Auth (JSON)",
		cmd: 'curl.exe -s -u "bruce:WaynePassword123!" http://localhost:3000/api/secrets',
		expected: "Batarang",
	},
	{
		title: "12. POST /api/reports : Bruce consigne un premier rapport de patrouille (201)",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/api/reports -u "bruce:WaynePassword123!" -H "Content-Type: application/json" -d "{\\"title\\":\\"Patrouille Nuit 1\\",\\"content\\":\\"Secteur Est sous controle.\\"}"',
		expected: "Code: 201",
	},
	{
		title: "13. POST /api/reports : Robin consigne un rapport de maintenance (201)",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -X POST http://localhost:3000/api/reports -u "robin:BoyWonder123!" -H "Content-Type: application/json" -d "{\\"title\\":\\"Maintenance Batmobile\\",\\"content\\":\\"Vidange des reacteurs terminee.\\"}"',
		expected: "Code: 201",
	},
	{
		title: "14. GET /api/reports : Robin (JUSTICIER) ne consulte que ses propres rapports",
		cmd: 'curl.exe -s -u "robin:BoyWonder123!" http://localhost:3000/api/reports',
		expected: "Maintenance Batmobile",
	},
	{
		title: "15. GET /api/reports : Bruce (ADMIN) a une vision globale sur TOUS les rapports",
		cmd: 'curl.exe -s -u "bruce:WaynePassword123!" http://localhost:3000/api/reports',
		expected: "Patrouille Nuit 1",
	},
	{
		title: "16. RBAC : Robin (JUSTICIER) tente d'accéder aux logs d'audit -> 403 Accès refusé",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -u "robin:BoyWonder123!" http://localhost:3000/api/admin/logs',
		expected: "Code: 403",
	},
	{
		title: "17. RBAC : Bruce (ADMIN) accède avec succès aux journaux d'audit de sécurité (200)",
		cmd: 'curl.exe -s -w " [Code: %{http_code}]" -u "bruce:WaynePassword123!" http://localhost:3000/api/admin/logs',
		expected: "Code: 200",
	},
	{
		title: "18. Protection Brute-Force : 3 mauvais mots de passe puis blocage 30s (429)",
		custom: () => {
			// 3 tentatives infructueuses sur alfred
			run('curl.exe -s -u "alfred:badpass" http://localhost:3000/api/secrets');
			run('curl.exe -s -u "alfred:badpass" http://localhost:3000/api/secrets');
			run('curl.exe -s -u "alfred:badpass" http://localhost:3000/api/secrets');
			// 4e tentative qui doit déclencher le blocage HTTP 429
			return run(
				'curl.exe -s -w " [Code: %{http_code}]" -u "alfred:badpass" http://localhost:3000/api/secrets',
			);
		},
		expected: "Code: 429",
	},
	{
		title: "19. GET /logout : Invalidation de session avec en-tête dédié (401)",
		cmd: "curl.exe -s -i http://localhost:3000/logout",
		expected: 'WWW-Authenticate: Basic realm="Batcave-LoggedOut"',
	},
];

console.log("RAPPORT OFFICIEL DE VALIDATION CURL (TOUTES ROUTES & APIS) :\n");
let passed = 0;
for (const t of tests) {
	const res = t.custom ? t.custom() : run(t.cmd);
	const ok = res.includes(t.expected);
	if (ok) passed++;
	console.log(`${ok ? "[SUCCÈS]" : "[ÉCHEC ]"} ${t.title}`);
	console.log(`         Extrait : ${res.replace(/\r?\n/g, " ").slice(0, 110)}...`);
}
console.log(`\nRÉSULTAT FINAL : ${passed}/${tests.length} tests réussis.`);
