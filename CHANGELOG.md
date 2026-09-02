# Changelog

Toutes les modifications notables apportées à ce projet sont consignées dans ce document.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et ce projet adhère à [Semantic Versioning](https://semver.org/lang/fr/).

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
