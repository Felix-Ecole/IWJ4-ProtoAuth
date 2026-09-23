# Changelog

Toutes les modifications notables apportées à ce projet sont consignées dans ce document.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et ce projet adhère à [Semantic Versioning](https://semver.org/lang/fr/).

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
