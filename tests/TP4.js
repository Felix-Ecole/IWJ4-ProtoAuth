// Banc d'essais automatisé officiel : TP4 - Opération Arkham Citadel
// Validation exhaustive des étapes 0 à 7 et des challenges 1 et 2

process.env.NODE_ENV = "test";
process.env.PORT = "3456";

const http = require("http");
const { authenticator } = require("../batcave-security/node_modules/@otplib/preset-v11");
const app = require("../batcave-security/server");
const db = require("../batcave-security/config/database");

let server;
const BASE_URL = "http://127.0.0.1:3456";

function request(method, path, body = null, headers = {}) {
	return new Promise((resolve, reject) => {
		const url = new URL(path, BASE_URL);
		const options = {
			method,
			hostname: url.hostname,
			port: url.port,
			path: url.pathname + url.search,
			headers: {
				Accept: "application/json",
				...headers,
			},
		};

		let payload = null;
		if (body) {
			payload = typeof body === "string" ? body : JSON.stringify(body);
			options.headers["Content-Type"] = "application/json";
			options.headers["Content-Length"] = Buffer.byteLength(payload);
		}

		const req = http.request(options, (res) => {
			let data = "";
			res.on("data", (chunk) => {
				data += chunk;
			});
			res.on("end", () => {
				let parsed = null;
				try {
					parsed = JSON.parse(data);
				} catch {
					parsed = data;
				}
				resolve({
					status: res.statusCode,
					headers: res.headers,
					body: parsed,
					raw: data,
				});
			});
		});

		req.on("error", reject);
		if (payload) {
			req.write(payload);
		}
		req.end();
	});
}

function parseCookies(header) {
	if (!header) return {};
	const list = Array.isArray(header) ? header : [header];
	const cookies = {};
	for (const item of list) {
		const parts = item.split(";")[0].split("=");
		cookies[parts[0].trim()] = parts[1]?.trim();
	}
	return cookies;
}

async function runTests() {
	console.log("===============================================================================");
	console.log("     BANC D'ESSAIS AUTOMATISÉ : TP4 - OPÉRATION ARKHAM CITADEL");
	console.log("===============================================================================\n");

	let passed = 0;
	let failed = 0;

	function assert(desc, condition, details = "") {
		if (condition) {
			console.log(`  [OK] ${desc}`);
			passed++;
		} else {
			console.error(`  [FAIL] ${desc} ${details ? `(${details})` : ""}`);
			failed++;
		}
	}

	server = http.createServer(app);
	await new Promise((res) => server.listen(3456, res));

	try {
		// Nettoyage et préparation de la base de test
		const testUser1 = "agent_arkham_test_" + Date.now();
		const testPass = "Batcave#2026Secret!";

		// Test 1 : Headers de sécurité Helmet
		console.log("--- TEST 1 : Injection Helmet et En-têtes HTTP de Sécurité ---");
		const resHeaders = await request("GET", "/auth/login");
		assert(
			"En-tête X-Content-Type-Options: nosniff présent",
			resHeaders.headers["x-content-type-options"] === "nosniff",
		);
		assert(
			"En-tête X-Frame-Options: SAMEORIGIN présent",
			resHeaders.headers["x-frame-options"] === "SAMEORIGIN",
		);
		assert(
			"En-tête Content-Security-Policy présent",
			!!resHeaders.headers["content-security-policy"],
		);

		// Test 2 : Enregistrement d'un nouvel agent (two_factor_enabled = 0 par défaut)
		console.log("\n--- TEST 2 : Création de compte et Vérification BDD ---");
		const regRes = await request("POST", "/register", {
			username: testUser1,
			password: testPass,
		});
		assert("Création agent réussie (201)", regRes.status === 201);

		const dbUser = db.prepare("SELECT * FROM users WHERE username = ?").get(testUser1);
		assert("Colonne two_factor_enabled présente et à 0", dbUser.two_factor_enabled === 0);
		assert("Colonne two_factor_secret initialement NULL", dbUser.two_factor_secret === null);

		// Test 3 : Zéro-Confiance sur /login (Utilisateur sans 2FA rejeté 403)
		console.log("\n--- TEST 3 : Zéro-Confiance sur /login (403 sans 2FA) ---");
		const loginNo2FARes = await request("POST", "/auth/login", {
			username: testUser1,
			password: testPass,
		});
		assert("Accès bloqué en 403 Forbidden sans 2FA", loginNo2FARes.status === 403);
		assert("requiresEnrollment: true renvoyé", loginNo2FARes.body?.requiresEnrollment === true);
		assert(
			"Aucun cookie token distribué",
			!parseCookies(loginNo2FARes.headers["set-cookie"]).token,
		);

		// Test 4 : Enrôlement 2FA (/api/auth/2fa/setup)
		console.log("\n--- TEST 4 : Enrôlement 2FA (/api/auth/2fa/setup) ---");
		const setupRes = await request("POST", "/api/auth/2fa/setup", {
			username: testUser1,
		});
		assert("Enrôlement 2FA initialisé (200 OK)", setupRes.status === 200);
		assert("Secret TOTP généré et renvoyé", typeof setupRes.body?.secret === "string");
		assert(
			"QR Code Base64 généré (data:image/png;base64,...)",
			setupRes.body?.qrCode?.startsWith("data:image/png;base64,"),
		);
		assert(
			"URI otpauth:// conforme Batcave",
			setupRes.body?.otpauth_url?.includes("otpauth://totp/Batcave"),
		);

		const dbUserWithSecret = db.prepare("SELECT * FROM users WHERE username = ?").get(testUser1);
		assert(
			"Secret temporaire persisté en base de données",
			dbUserWithSecret.two_factor_secret === setupRes.body.secret,
		);
		assert(
			"two_factor_enabled est toujours à 0 avant confirmation",
			dbUserWithSecret.two_factor_enabled === 0,
		);

		// Test 5 : Confirmation 2FA avec code invalide puis valide
		console.log("\n--- TEST 5 : Confirmation 2FA (/api/auth/2fa/confirm) ---");
		const badConfirmRes = await request("POST", "/api/auth/2fa/confirm", {
			username: testUser1,
			code: "000000",
		});
		assert("Échec avec code TOTP erroné (401)", badConfirmRes.status === 401);

		// Génération d'un code TOTP valide via otplib
		const validCode = authenticator.generate(dbUserWithSecret.two_factor_secret);
		const goodConfirmRes = await request("POST", "/api/auth/2fa/confirm", {
			username: testUser1,
			code: validCode,
		});
		assert("Succès confirmation avec code TOTP valide (200)", goodConfirmRes.status === 200);

		const dbUserActive2FA = db.prepare("SELECT * FROM users WHERE username = ?").get(testUser1);
		assert("two_factor_enabled activé à 1 en BDD", dbUserActive2FA.two_factor_enabled === 1);

		// Test 6 : Connexion Zéro-Confiance après activation (Étape 1 renvoie requires2FA: true)
		console.log("\n--- TEST 6 : Connexion Étape 1 avec 2FA active ---");
		const loginStep1Res = await request("POST", "/auth/login", {
			username: testUser1,
			password: testPass,
		});
		assert("Connexion étape 1 réussie (200)", loginStep1Res.status === 200);
		assert("requires2FA: true présent", loginStep1Res.body?.requires2FA === true);
		assert(
			"Aucun cookie token distribué lors de l'étape 1",
			!parseCookies(loginStep1Res.headers["set-cookie"]).token,
		);

		// Test 7 : Validation Finale TOTP (/api/verify-2fa)
		console.log("\n--- TEST 7 : Validation Finale (/api/verify-2fa) ---");
		const badVerifyRes = await request("POST", "/api/verify-2fa", {
			username: testUser1,
			code: "999999",
		});
		assert("Rejet en cas de mauvais code TOTP (401)", badVerifyRes.status === 401);

		const validVerifyCode = authenticator.generate(dbUserActive2FA.two_factor_secret);
		const goodVerifyRes = await request("POST", "/api/verify-2fa", {
			username: testUser1,
			code: validVerifyCode,
		});
		assert("Validation 2FA réussie (200)", goodVerifyRes.status === 200);

		const cookies = parseCookies(goodVerifyRes.headers["set-cookie"]);
		assert("Cookie accessToken (token) distribué", !!cookies.token);
		assert("Cookie refreshToken distribué", !!cookies.refreshToken);
		assert("accessToken expire à 15 minutes (900s)", goodVerifyRes.body?.expiresIn === 900);

		// Test 8 : Détection de vol et Reuse Detection (Challenge 1)
		console.log("\n--- TEST 8 : Rotation et Détection de Vol de Jetons (Challenge 1) ---");
		// 1er rafraîchissement légitime
		const refresh1Res = await request("POST", "/auth/refresh", null, {
			Cookie: `refreshToken=${cookies.refreshToken}`,
		});
		assert("1er rafraîchissement réussi avec rotation", refresh1Res.status === 200);
		const cookies2 = parseCookies(refresh1Res.headers["set-cookie"]);
		assert("Nouveau refreshToken distribué", !!cookies2.refreshToken);

		// Tentative de rejeu de l'ancien refreshToken consommé
		const reuseRes = await request("POST", "/auth/refresh", null, {
			Cookie: `refreshToken=${cookies.refreshToken}`,
		});
		assert("Tentative de rejeu détectée (403 Forbidden)", reuseRes.status === 403);
		assert(
			"Code TOKEN_REUSE_DETECTED renvoyé",
			reuseRes.body?.code === "TOKEN_REUSE_DETECTED",
		);

		// Vérification que TOUS les jetons de l'utilisateur ont été révoqués
		const activeTokens = db
			.prepare("SELECT COUNT(*) as count FROM refresh_tokens WHERE user_id = ?")
			.get(dbUserActive2FA.id).count;
		assert(
			"Révocation en cascade immédiate (0 jeton restant en BDD)",
			activeTokens === 0,
		);

		// Test 9 : Contrôle fin des privilèges par scopes OAuth2 (Challenge 2)
		console.log("\n--- TEST 9 : Gestion fine des Privilèges et Scopes (Challenge 2) ---");
		// Création d'un compte restreint (Nightwing avec scope limité)
		const nightwingUser = "nightwing_test_" + Date.now();
		db.prepare("INSERT INTO users (username, password, role, two_factor_enabled) VALUES (?, ?, ?, 1)").run(
			nightwingUser,
			"hashed_pass",
			"JUSTICIER",
		);
		const nightwingSecret = authenticator.generateSecret();
		db.prepare("UPDATE users SET two_factor_secret = ? WHERE username = ?").run(nightwingSecret, nightwingUser);

		// Connexion de Nightwing
		const nwCode = authenticator.generate(nightwingSecret);
		const nwVerifyRes = await request("POST", "/api/verify-2fa", {
			username: nightwingUser,
			code: nwCode,
		});
		const nwCookies = parseCookies(nwVerifyRes.headers["set-cookie"]);
		const nwScopes = nwVerifyRes.body?.user?.scopes || [];
		assert("Nightwing connecté avec scopes restreints", nwScopes.includes("batmobile:status"));
		assert("Nightwing ne possède pas le scope 'batmobile:control'", !nwScopes.includes("batmobile:control"));

		// Tentative d'accès de Nightwing à la Batmobile (requiert batmobile:control)
		const nwBatmobileRes = await request("GET", "/api/batmobile/systems", null, {
			Cookie: `token=${nwCookies.token}`,
		});
		assert("Accès Batmobile refusé à Nightwing (403 Forbidden)", nwBatmobileRes.status === 403);
		assert("Erreur INSUFFICIENT_SCOPE renvoyée", nwBatmobileRes.body?.code === "INSUFFICIENT_SCOPE");

		// Connexion de Batman (avec scope batmobile:control et computers:admin)
		const batmanUser = "batman";
		let batmanRecord = db.prepare("SELECT * FROM users WHERE username = 'batman'").get();
		let batmanSecret;
		if (!batmanRecord) {
			batmanSecret = authenticator.generateSecret();
			db.prepare("INSERT INTO users (username, password, role, two_factor_secret, two_factor_enabled) VALUES (?, ?, 'ADMIN', ?, 1)").run(
				batmanUser,
				"hashed_pass",
				batmanSecret,
			);
		} else {
			batmanSecret = batmanRecord.two_factor_secret || authenticator.generateSecret();
			db.prepare("UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE username = 'batman'").run(batmanSecret);
		}
		const bmCode = authenticator.generate(batmanSecret);
		const bmVerifyRes = await request("POST", "/api/verify-2fa", {
			username: batmanUser,
			code: bmCode,
		});
		const bmCookies = parseCookies(bmVerifyRes.headers["set-cookie"]);

		// Accès Batmobile autorisé pour Batman
		const bmBatmobileRes = await request("GET", "/api/batmobile/systems", null, {
			Cookie: `token=${bmCookies.token}`,
		});
		assert("Accès Batmobile autorisé pour Batman (200 OK)", bmBatmobileRes.status === 200);
		assert("Systèmes tactiques actifs", bmBatmobileRes.body?.status === "ACTIF");
	} catch (err) {
		console.error("\nErreur critique lors de l'exécution du banc d'essais :", err);
		failed++;
	} finally {
		if (server) {
			server.close();
		}
	}

	console.log("\n===============================================================================");
	console.log(`RÉSULTATS : ${passed} validé(s), ${failed} échoué(s) sur ${passed + failed} tests.`);
	console.log("===============================================================================");

	process.exit(failed > 0 ? 1 : 0);
}

runTests();
