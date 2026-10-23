# Changelog

Toutes les modifications notables apportées à ce projet sont consignées dans ce document.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et ce projet adhère à [Semantic Versioning](https://semver.org/lang/fr/).

---

## [4.0.0] - 2026-10-23

### Ajouté
- Injection globale du middleware de sécurité **Helmet** avec politique CSP stricte (`Content-Security-Policy`, `nosniff`, `SAMEORIGIN`) (Étape 1).
- Verrouillage des cookies de session (`httpOnly: true`, `sameSite: 'strict'`) et ajustement de l'espérance de vie du jeton d'accès à **15 minutes** (Étape 2).
- Migration incrémentale du schéma SQLite `users` avec ajout des colonnes `two_factor_secret` et `two_factor_enabled` (Étape 3).
- Route d'initialisation de l'enrôlement 2FA `POST /api/auth/2fa/setup` avec génération du secret TOTP, création de l'URI standardisée `otpauth://` et rendu QR Code en Base64 via `qrcode` (Étape 4).
- Route de confirmation 2FA `POST /api/auth/2fa/confirm` validant mathématiquement le premier code à 6 chiffres via `@otplib/preset-v11` et activant `two_factor_enabled = 1` en BDD (Étape 5).
- Contrôleur d'authentification en mode Zéro-Confiance sur `POST /auth/login` bloquant à 403 Forbidden les comptes sans 2FA et interrompant le flux avec `requires2FA: true` sans émission préalable de jeton (Étape 6).
- Route de validation finale du double verrou `POST /api/verify-2fa` contrôlant le code TOTP avant délivrance des cookies sécurisés `token` et `refreshToken` (Étape 7).
- Interface interactive de connexion et d'enrôlement 2FA intégrée dans `login.html` avec scan de QR Code et saisie directe TOTP.
- Détection de vol et réutilisation frauduleuse de refresh tokens (*Reuse Detection*) avec révocation globale de toutes les sessions actives en base SQLite (Challenge 1).
- Middleware de contrôle d'accès fin par scopes OAuth2 `checkScope(requiredScope)` protégeant les systèmes critiques de la Batcave (Batmobile, armurerie, rapports) (Challenge 2).
- Banc d'essais automatisé validant 37 assertions couvrant 100% des exigences du TP4 (`robots/test_tp4.js`).
- Refactorisation modulaire du routeur d'authentification `routes/auth.js` découpé en modules dédiés (`routes/auth/login.js`, `twoFactor.js`, `tokens.js`, `password.js`, `helpers.js`).

---

## [3.0.0] - 2026-09-26

### Ajouté
- Migration vers une architecture stateless pure fondée sur le couple de jetons JWT / Refresh Token.
- Émission d'un `accessToken` JWT d'espérance de vie courte (15 secondes) signé cryptographiquement.
- Génération d'un `refreshToken` opaque aléatoire de 64 octets (espérance de vie de 7 jours).
- Table relationnelle SQLite `refresh_tokens` assurant la persistance et la traçabilité des jetons.
- Endpoint de renouvellement transparent `POST /api/auth/refresh` (et `/auth/refresh`).
- Procédure de déconnexion avec révocation immédiate en base (`DELETE FROM refresh_tokens WHERE token = ?`).
- Pattern Retry frontend (`authFetch`) interceptant les codes 401, rafraîchissant les jetons en tâche de fond et rejouant les requêtes de façon transparente sans coupure opérationnelle.
- Route sécurisée `POST /api/auth/change-password` soumise aux directives de robustesse de l'ANSSI (12 caractères min, majuscule, minuscule, chiffre, symbole spécial).
- Interface de renouvellement de clé avec indicateurs interactifs de conformité ANSSI dans la console Bat-Ordinateur.
- Rotation systématique des refresh tokens et détection de réutilisation frauduleuse (*Reuse Detection*) avec révocation globale de toutes les sessions actives de l'agent compromis (Challenge 1).
- Protocole de double authentification 2FA pour les commandes tactiques de la Batmobile (`POST /api/auth/verify-2fa`, claim `is2FAVerified`, middleware `require2FA`, route `/api/batmobile/systems`) (Challenge 2).
- Prise en charge native de l'en-tête standard `Authorization: Bearer <JWT>` pour les équipements IoT et la Bat-Armure Mk-VII (`GET /api/suit/status`) (Challenge 3).
- Banc d'essais automatisé officiel couvrant l'ensemble du cycle de vie des jetons et des scénarios de test (`tests/TP3.js`).

### Modifié
- Remplacement du middleware de session serveur (`express-session`) par `cookie-parser` et `jsonwebtoken`.
- Adaptation des routeurs applicatifs (`batcomputer`, `reports`, `secrets`, `admin`) pour consommer le payload `req.user`.

---

## [2.0.0] - 2026-09-23

### Ajouté
- Architecture modulaire complète (`config/`, `middlewares/`, `routes/`, `views/`).
- Externalisation des secrets et de la configuration via `dotenv` et `.env.example`.
- Système d'authentification par badge de session avec cookie signé `bat_identity`.
- Paramétrage renforcé de sécurité sur les cookies (`httpOnly: true`, `sameSite: "strict"`, durée 30 minutes).
- Session Store persistant sur SQLite via `better-sqlite3-session-store` (Bonus 1).
- Régénération systématique du session ID (`req.session.regenerate()`) contre la fixation de session.
- Middleware `isAuthenticated` protégeant la console Bat-Ordinateur et les routes privées.
- Déconnexion propre (`GET /auth/logout`) avec destruction de session serveur et purge du cookie.
- Vigile anti-usurpation d'identité et détection de vol de session par empreinte client IP + User-Agent (Bonus 2).
- Registre relationnel `connexions_audit` traçant les événements `LOGIN`, `LOGOUT` et `FRAUD` (Bonus 3).
- Console d'audit interactive réservée au rôle `ADMIN` avec tableau de bord temps réel, filtrage et indicateurs (Bonus 3).
- Banc d'essais automatisé complet validant 13 scénarios techniques (`tests/TP2.js`).

### Modifié
- Refactorisation de `server.js` en point d'entrée allégé et modulaire.
- Migration de `bat-computer.html` vers le dossier sécurisé `views/`.
- Isolation de la base de données et des schémas relationnels dans `config/database.js`.

---

## [1.0.0] - 2026-09-02

### Ajouté
- Initialisation du module `batcave-security` (Express + SQLite via `better-sqlite3`).
- Système d'inscription avec validation (longueur $\ge 8$, `trim`, unicité 409) et hachage `bcrypt`.
- Formulaire public d'enregistrement sous Tailwind CSS avec sélecteur d'accréditation.
- Attribution automatique du rôle `ADMIN` au tout premier compte inscrit.
- Middleware HTTP Basic Auth (`WWW-Authenticate`) et sécurisation de `/bat-computer` et `/api/secrets`.
- Personnalisation de session (`GET /api/me`) et table relationnelle des rapports (`/api/reports`).
- Contrôle d'accès RBAC (`ADMIN`, `ASSISTANT`, `JUSTICIER`) avec gestion du code 403.
- Journalisation des accès dans la table `logs` et route d'audit réservée aux administrateurs.
- Protection anti force brute (blocage temporaire de 30s après 3 échecs).
- Route `/logout` de purge de session.
- Guide complet de développement et de recette (`DEVELOPMENT.md`).
- Banc d'essais automatisé complet (`tests/TP1.js`).
