# TP1 - Système de Sécurité de la Batcave

Serveur centralisé d'authentification et de contrôle d'accès au Bat-Ordinateur, missionné par Bruce Wayne et Alfred Pennyworth.

Le système s'appuie sur une authentification HTTP **Basic Auth**, un hachage salé via **Bcrypt** et une persistance sous **SQLite** (`better-sqlite3`).

---

## 1. Contexte et Architecture Fonctionnelle

Le module assure le cloisonnement entre les espaces d'accès public et les ressources confidentielles de la Batcave :

- **Registre des justiciers** : Formulaire d'enregistrement (`/register.html`) avec validation stricte côté serveur (mot de passe $\ge 8$ caractères, suppression des espaces résiduels, gestion des conflits d'unicité avec code `409 Conflict` et hachage `bcrypt`). Les comptes créés sont persistés localement dans le fichier SQLite `database.db` (table `users`), consultable avec l'extension VS Code *SQLite Viewer*.
- **Protection Basic Auth** : Interception systématique des routes sensibles par le middleware `basicAuth`. En cas d'identifiants absents ou invalides, retour d'un statut `401 Unauthorized` avec l'en-tête standard `WWW-Authenticate: Basic realm="Batcave"`.
- **Espace opérationnel & Rapports** : Console du Bat-Ordinateur servie depuis un répertoire privé (`/bat-computer`), restitution nominative du profil (`GET /api/me`), exposition de l'arsenal tactique (`GET /api/secrets`) et persistance des notes de mission (`/api/reports`).
- **Mesures de sécurité avancées** : Contrôle d'accès basé sur les rôles (RBAC) interdisant les endpoints sensibles aux agents non autorisés (`403 : Accès refusé`), journalisation systématique dans la table `logs`, protection anti force brute (blocage temporaire de 30 secondes après 3 échecs) et point de déconnexion `/logout`.

---

## 2. Modèle de Données SQLite (`database.db`)

```sql
-- Table des utilisateurs et rôles
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'JUSTICIER'
);

-- Table des rapports de mission
CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table des journaux d'audit de sécurité
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip TEXT NOT NULL,
    username TEXT,
    success INTEGER NOT NULL
);
```

---

## 3. Spécification des Endpoints de l'API

| Méthode | Route | Accès | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/register` | Public | Enregistrement d'un nouvel agent (`username`, `password`, optionnel `role`) |
| `GET` | `/register.html` | Public | Formulaire web d'enregistrement |
| `GET` | `/bat-computer` | Basic Auth | Console du Bat-Ordinateur (servie depuis `private/`) |
| `GET` | `/api/me` | Basic Auth | Informations de l'agent authentifié (`id`, `username`, `role`) |
| `GET` | `/api/secrets` | Basic Auth | Liste des équipements et gadgets tactiques |
| `POST` | `/api/reports` | Basic Auth | Enregistrement d'un rapport de mission |
| `GET` | `/api/reports` | Basic Auth | Historique des rapports (propres à l'agent ou globaux pour ADMIN) |
| `GET` | `/api/admin/logs` | ADMIN | Consultation des 50 dernières entrées d'audit |
| `GET` | `/logout` | Public | Fermeture de session et purge des identifiants |

---

> [!NOTE]
> Pour les instructions d'installation, de lancement et les procédures de validation (cURL, Postman, navigateur), consultez le document racine [`DEVELOPMENT.md`](../DEVELOPMENT.md).
