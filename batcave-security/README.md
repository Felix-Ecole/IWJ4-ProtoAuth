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

## 4. TP2 - Le Système de Badges de la Batcave (Modernisation)

Le système Basic Auth transmettait les identifiants à chaque requête HTTP et ne permettait pas de révoquer un appareil spécifique sans changer le mot de passe. Alfred a exigé une modernisation : authentification par badge éphémère (Session ID signé via cookie HTTP-only `bat_identity`).

### 4.1 Architecture Modulaire
Le code monolithique `server.js` a été refactorisé selon une structure modulaire découplée :
- `config/database.js` : Initialisation SQLite, clés étrangères et tables relationnelles.
- `middlewares/authCheck.js` : Vigile `isAuthenticated` vérifiant `req.session.user` (renvoi 401 et redirection `/auth/login`).
- `middlewares/antiHijack.js` : Détection du vol de session par empreinte client IP + User-Agent (Bonus 2).
- `middlewares/checkRole.js` : Contrôle d'accès basé sur les rôles (RBAC).
- `routes/auth.js` : Routeur de session (`GET /auth/login`, `POST /auth/login`, `GET /auth/logout`).
- `routes/batcomputer.js` : Console Batcomputer servie depuis `views/bat-computer.html`.
- `routes/register.js` : Création de compte justicier avec validation stricte et promotion automatique du premier compte en `ADMIN`.
- `routes/reports.js` : Gestion des rapports de mission (personnels ou supervision globale pour l'ADMIN).
- `routes/secrets.js` : Arsenal tactique de Batman et profil de session.
- `routes/admin.js` : Console d'audit des flux de connexion (`GET /admin/audit` et `GET /admin/api/audit-logs`) (Bonus 3).
- `views/` : Interfaces HTML sécurisées servies hors du dossier public (`login.html`, `bat-computer.html`, `audit.html`).

### 4.2 Configuration et Sécurité des Cookies (`.env`)
Les secrets sont externalisés dans un fichier `.env` chargé via `dotenv` :
```env
PORT=3000
SESSION_SECRET=batcave_super_secret_session_key_2026_top_secret_bruce_wayne
```
Le cookie de session `bat_identity` est configuré avec des règles de sécurité strictes :
- **`name: "bat_identity"`** : Dissimule l'empreinte technologique Express/Connect.
- **`httpOnly: true`** : Interdit l'accès au cookie via les scripts JS clients (protection XSS).
- **`sameSite: "strict"`** : Bloque l'envoi du cookie lors de requêtes cross-site (protection CSRF).
- **`maxAge: 1800000`** : Expiration automatique après 30 minutes d'inactivité.

### 4.3 Fonctionnalités Bonus Implémentées
1. **Session Store Persistant SQLite (Bonus 1)** : Utilisation de `better-sqlite3-session-store` connecté sur l'instance SQLite. Les sessions survivent à un redémarrage du serveur Node sans forcer les agents à se reconnecter.
2. **Détection de Vol de Session (Anti-Hijacking - Bonus 2)** : L'IP et le User-Agent enregistrés au login sont vérifiés à chaque requête protégée. En cas de divergence, la session est détruite, le cookie effacé, l'incident consigné en `FRAUD` et la requête bloquée (403 Forbidden).
3. **Registre d'Audit et Console ADMIN (Bonus 3)** : La table `connexions_audit` journalise chaque `LOGIN`, `LOGOUT` et `FRAUD`. Une console dédiée `/admin/audit` offre un tableau de bord visuel filtrable en temps réel aux administrateurs.

### 4.4 Endpoints de l'API (TP2)

| Méthode | Route | Accès | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | Redirection intelligente vers `/bat-computer` ou `/auth/login` |
| `GET` | `/auth/login` | Public | Formulaire HTML d'identification (Tailwind Batcave) |
| `POST` | `/auth/login` | Public | Vérification identifiants, régénération anti-fixation, cookie `bat_identity` |
| `GET` | `/auth/logout` | Session | Destruction de session, purge du cookie et redirection |
| `POST` | `/register` | Public | Enregistrement d'un nouvel agent (Bcrypt, règle premier ADMIN) |
| `GET` | `/bat-computer` | Session | Interface sécurisée du Bat-Ordinateur |
| `GET` | `/api/me` | Session | Informations de l'agent connecté (`id`, `username`, `role`) |
| `GET` | `/api/secrets` | Session | Arsenal tactique de Batman |
| `GET` | `/api/reports` | Session | Consultation des rapports (tous si `ADMIN`, personnels sinon) |
| `POST` | `/api/reports` | Session | Enregistrement d'un rapport de mission |
| `GET` | `/admin/audit` | Session `ADMIN` | Interface web de la console de surveillance des badges |
| `GET` | `/admin/api/audit-logs` | Session `ADMIN` | Flux JSON des événements d'audit avec filtrage |

---

## 5. TP3 - Le Système de Jetons de la Batcave (Architecture Stateless)

Pour résoudre les crises de saturation mémoire et l'inconfort opérationnel de Batman lors des coupures de session en pleine mission, l'architecture évolue vers un modèle **stateless sécurisé** fondé sur le couple de jetons :
1. **`accessToken`** : Jetons JWT éphémères signés cryptographiquement (durée courte de 15 secondes pour les démonstrations de rotation).
2. **`refreshToken`** : Chaîne aléatoire cryptographique opaque valide 7 jours, persistée dans la table SQLite `refresh_tokens`.

### 5.1 Modélisation du Flux et Cycle de Vie (Étape 1)

Le schéma ci-dessous modélise le cycle complet de connexion, d'expiration, de rafraîchissement transparent en arrière-plan et de rejeu automatique ("Retry Pattern") :

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client (Frontend authFetch)
    participant API as API (Serveur Express)
    participant DB as DB (Base SQLite)

    alt 1. Connexion initiale
        Client->>API: POST /auth/login { username, password }
        API->>DB: Vérification Bcrypt & Stockage refreshToken
        DB-->>API: Enregistrement confirmé (7 jours)
        API-->>Client: 200 OK + Set-Cookie: token (JWT 15s) & refreshToken (7j HttpOnly)
    end

    alt 2. Requête normale avec JWT valide
        Client->>API: GET /api/me (Cookie: token valide)
        API->>API: Vérification cryptographique signature JWT
        API-->>Client: 200 OK (Données utilisateur)
    end

    alt 3. Expiration et Rafraîchissement transparent (Retry Pattern)
        Client->>API: GET /api/me (Cookie: token expiré)
        API-->>Client: 401 Unauthorized (TOKEN_EXPIRED)
        Note over Client: authFetch intercepte l'erreur 401 et suspend la requête
        Client->>API: POST /api/auth/refresh (Cookie: refreshToken)
        API->>DB: Contrôle validité refreshToken & Rotation (is_used = 1)
        DB-->>API: Jeton valide
        API-->>Client: 200 OK + Set-Cookie: token (Nouveau JWT 15s)
        Note over Client: Rejeu automatique de la requête initiale en arrière-plan
        Client->>API: GET /api/me (Nouveau Cookie: token)
        API-->>Client: 200 OK (Données délivrées sans coupure UX)
    end

    alt 4. Déconnexion et révocation d'urgence
        Client->>API: POST /auth/logout (Cookie: refreshToken)
        API->>DB: DELETE FROM refresh_tokens WHERE token = ?
        DB-->>API: Jeton révoqué en BDD
        API-->>Client: 200 OK + Clear-Cookie: token & refreshToken
    end
```

> [!NOTE]
> Le schéma technique haute résolution au format image est disponible à la racine du dépôt : [`tp3-architecture-flux.png`](../tp3-architecture-flux.png).

### 5.2 Architecture Stateless & Table des Jetons (Étape 2)
- Élimination de `express-session` au profit d'un modèle sans état basé sur `cookie-parser` et `jsonwebtoken`.
- Configuration de deux cookies sécurisés distincts (`HttpOnly`, `SameSite=Strict`, `secure: false` en environnement local) :
  - `token` : jeton d'accès JWT signé cryptographiquement (`expiresIn: "15s"`).
  - `refreshToken` : jeton opaque aléatoire généré par `crypto.randomBytes(64)` d'une durée de 7 jours.
- Schéma de persistance SQLite (`refresh_tokens`) :
  - `id` : identifiant unique auto-incrémenté.
  - `user_id` : clé étrangère liant le jeton à la table `users` (avec `ON DELETE CASCADE`).
  - `token` : valeur cryptographique unique du jeton.
  - `expires_at` : horodatage ISO de fin de validité.
  - `is_used` : drapeau binaire (0 ou 1) dédié à la détection de rejeu.

### 5.3 Rafraîchissement Transparent & Révocation d'Urgence (Étape 3)
- **Endpoint `POST /api/auth/refresh` (et `/auth/refresh`)** :
  - Récupère le `refreshToken` depuis les cookies HTTP-only.
  - Vérifie son existence et son statut en base de données.
  - En cas de validité : émet un nouvel `accessToken` JWT de 15 secondes.
  - En cas d'expiration : purge immédiate du token en base et retour `401 Unauthorized`.
- **Déconnexion sécurisée (`/auth/logout`)** :
  - Révocation physique immédiate du jeton en base (`DELETE FROM refresh_tokens WHERE token = ?`).
  - Suppression conjointe des deux cookies côté client.

### 5.4 Résilience Frontend : Le Pattern "Retry" (Étape 4)
Pour que Batman ne subisse aucune déconnexion intempestive en intervention lors de l'expiration du jeton de 15 secondes, la fonction wrapper `authFetch(url, options)` a été intégrée dans la console Bat-Ordinateur :
1. Exécution de la requête initiale.
2. Si le serveur renvoie un code `401 Unauthorized` (jeton d'accès expiré) :
   - Interception immédiate en tâche de fond.
   - Appel transparent de `POST /api/auth/refresh`.
   - Si le refresh réussit : la requête initiale est automatiquement rejouée et renvoie ses données comme si de rien n'était.
   - Si le refresh échoue (refreshToken expiré ou révoqué) : redirection vers `/auth/login`.

### 5.5 Modification Sécurisée du Mot de Passe selon les Directives ANSSI (Étape 5)
La route `POST /api/auth/change-password` impose une politique de sécurité stricte certifiée par l'ANSSI :
- Longueur minimale de **12 caractères**.
- Présence obligatoire d'au moins **une majuscule**, **une minuscule**, **un chiffre** et **un symbole spécial**.
- Différence obligatoire entre l'ancienne et la nouvelle clé.
- Vérification cryptographique de l'ancien mot de passe via `bcrypt.compare`.
- Interface visuelle interactive dans la console Bat-Ordinateur avec 4 jauges de conformité actualisées en temps réel à chaque frappe de clavier.

### 5.6 Challenges Bonus Implémentés

#### Challenge 1 : Rotation des Refresh Tokens & Détection de Réutilisation (*Reuse Detection*)
- **Rotation systématique** : à chaque sollicitation de `/refresh`, l'ancien jeton est marqué comme consommé (`is_used = 1`) et un nouveau couple de jetons est généré.
- **Détection d'attaque par rejeu** : si un pirate tente d'utiliser un jeton déjà consommé, le serveur détecte immédiatement une tentative de vol.
- **Sanction maximale** : révocation immédiate de **toutes les sessions actives** de l'agent en base (`DELETE FROM refresh_tokens WHERE user_id = ?`), consignation d'un log `FRAUD` et blocage 403.

#### Challenge 2 : Protocole 2FA pour les Commandes Critiques de la Batmobile
- Les commandes hautement sensibles de la Batmobile (`/api/batmobile/systems`) exigent une certification 2FA.
- Le jeton JWT émis au login possède le claim `is2FAVerified: false`.
- L'agent doit soumettre le code secret d'Alfred sur `POST /api/auth/verify-2fa`.
- En cas de succès, un nouveau JWT rehaussé avec `is2FAVerified: true` est délivré, déverrouillant le middleware `require2FA`.

#### Challenge 3 : Support Universel Bearer Token pour la Bat-Armure Mk-VII
- Les dispositifs IoT de terrain (comme la Bat-Armure) ne gèrent pas le stockage de cookies.
- Le middleware `checkJWT` extrait le jeton indifféremment depuis le cookie HTTP ou depuis l'en-tête standard `Authorization: Bearer <JWT>`.
- Route dédiée de télémétrie de l'armure : `GET /api/suit/status`.

### 5.7 Tableau Récapitulatif des Endpoints (TP3)

| Méthode | Route | Authentification requise | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth/login` | Public | Authentification, émission des cookies `token` (15s) et `refreshToken` (7j) |
| `POST` | `/api/auth/refresh` | Cookie `refreshToken` | Rotation des jetons et renouvellement de l'accessToken JWT |
| `POST` | `/auth/logout` | Cookie `refreshToken` | Révocation immédiate en BDD SQLite et purge des cookies |
| `POST` | `/api/auth/change-password` | JWT (`checkJWT`) | Mise à jour sécurisée de la clé selon les critères ANSSI |
| `POST` | `/api/auth/verify-2fa` | JWT (`checkJWT`) | Validation du second facteur 2FA (Code Alfred) pour la Batmobile |
| `GET` | `/api/me` | JWT (Cookie ou Bearer) | Restitution du profil de l'agent connecté |
| `GET` | `/api/secrets` | JWT (Cookie ou Bearer) | Consultation de l'arsenal tactique |
| `GET` | `/api/batmobile/systems` | JWT + 2FA (`require2FA`) | Commandes tactiques de la Batmobile (2FA certifié requis) |
| `GET` | `/api/suit/status` | JWT (Bearer ou Cookie) | Télémétrie en temps réel de la Bat-Armure Mk-VII |
| `GET` | `/bat-computer` | JWT (`checkJWT`) | Console centrale d'administration du Bat-Ordinateur |

---

> [!NOTE]
> Pour les instructions d'installation, de lancement et les procédures de validation (cURL, Postman, navigateur), consultez le document racine [`DEVELOPMENT.md`](../DEVELOPMENT.md).
