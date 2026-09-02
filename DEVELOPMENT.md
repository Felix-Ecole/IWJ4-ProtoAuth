# Guide de Développement et de Recette

Ce document rassemble les consignes techniques, les protocoles de validation et les normes de développement applicables au projet.

---

## 1. Démarrage et Environnement Local

### Dépendances et Lancement
```bash
# Accéder au module actif (TP1)
cd batcave-security

# Installation des dépendances
npm install

# Démarrage avec rechargement automatique
npm start
```
Le serveur est accessible sur `http://localhost:3000`.

### Formatage du Code
Le projet utilise Prettier avec les règles suivantes définies dans `.prettierrc` :
- Tabulations réelles (`useTabs: true`) équivalant visuellement à 4 espaces (`tabWidth: 4`).
- Doubles quotes (`singleQuote: false`).
- Fin de ligne au format LF (`endOfLine: "lf"`).

```bash
# Vérifier et reformater l'ensemble des fichiers
npm run format
```

---

## 2. Persistance, Rôles et Permissions

### Emplacement de la Base de Données
Les comptes créés sont persistés localement dans le fichier SQLite :
- **Fichier** : [`batcave-security/database.db`](./batcave-security/database.db)
- **Table** : `users` (`id`, `username`, `password`, `role`)

### Définition des Rôles et Attribution des Permissions
Le système gère trois niveaux d'accréditation :

| Rôle | Attribution | Permissions et Accès |
| :--- | :--- | :--- |
| **`ADMIN`** | **Automatique pour le 1ᵉʳ compte créé**, ou sélectionné à l'inscription | Accès complet sans restriction : console, arsenal, lecture de **tous les rapports de mission** et consultation exclusive des **journaux d'audit** (`/api/admin/logs`). |
| **`ASSISTANT`** | Sélectionnable sur `/register.html` ou via l'API | Accès aux pages opérationnelles configurées (console `/bat-computer`, arsenal `/api/secrets`). Rejet `403 : Accès refusé` sur les logs d'audit. |
| **`JUSTICIER`** | Rôle standard par défaut | Accès console, arsenal, rédaction et consultation de **ses propres rapports** uniquement. Rejet `403 : Accès refusé` sur les fonctions d'administration. |

### Modification manuelle des rôles (SQLite Viewer)
Pour modifier les droits d'un compte existant ou vérifier les mots de passe hachés :
1. Installer l'extension VS Code **[SQLite Viewer](https://marketplace.visualstudio.com/items?itemName=qwtel.sqlite-viewer)** (`qwtel.sqlite-viewer`).
2. Ouvrir le fichier `database.db` dans l'éditeur.
3. Modifier directement la valeur de la colonne `role` (`ADMIN`, `ASSISTANT` ou `JUSTICIER`) sur la ligne de l'utilisateur concerné.

---

## 3. Procédures de Validation et Recette (TP1)

La validation du TP1 peut être exécutée de manière entièrement automatisée ou manuellement selon trois méthodes distinctes :

### Validation Automatisée
Un banc d'essais complet testant l'intégralité des 19 critères est disponible à la racine :
```bash
node tests/TP1.js
```

### Méthode 1 : Navigateur Web (Dialogue natif)
1. Ouvrir `http://localhost:3000/register.html` pour créer un premier compte (qui devient automatiquement `ADMIN`, ex. : `bruce` / `WaynePass123!`).
2. Accéder à `http://localhost:3000/bat-computer`.
3. Le navigateur intercepte le code `401 Unauthorized` et l'en-tête `WWW-Authenticate` pour ouvrir sa boîte de dialogue native.
4. Renseigner l'identifiant et le mot de passe pour afficher le tableau de bord avec les journaux d'audit visibles pour l'ADMIN.

### Méthode 2 : Outil externe (Postman, Thunder Client ou OpenAPI)
1. Créer une requête `GET` ciblant `http://localhost:3000/api/secrets`.
2. Dans l'onglet **Authorization**, choisir **Basic Auth** et renseigner les identifiants.
3. Constater l'envoi de l'en-tête `Authorization: Basic <base64>` et la réponse `200 OK` contenant le tableau JSON de l'arsenal.

### Méthode 3 : Ligne de commande cURL
Tester l'accès direct via le terminal :
```bash
curl -i -u "bruce:WaynePass123!" http://localhost:3000/api/secrets
```
La réponse doit inclure le code `200 OK` et le JSON des équipements.

### Test de la Protection Anti Force Brute
Effectuer 3 tentatives erronées consécutives :
```bash
curl -i -u "bruce:mauvais_pass" http://localhost:3000/api/secrets
curl -i -u "bruce:mauvais_pass" http://localhost:3000/api/secrets
curl -i -u "bruce:mauvais_pass" http://localhost:3000/api/secrets
```
La 4ᵉ tentative doit retourner un code `429 Too Many Requests` avec l'indication du temps de blocage (30 secondes).

---

## 4. Conventions Git et Livrables

- **Branche principale** : `master`
- **Branches de travail** : `tp<numero>-<theme>`
- **Releases** : Tags annotés SemVer (`v1.0.0`)
- **Documentation** : Mise à jour conjointe du `README.md` racine, du `README.md` du TP et du `CHANGELOG.md`.
