# IWJ4 - ProtoAuth : Protocoles et Architectures d'Authentification

Projet pédagogique dédié à l'étude et à l'implémentation progressive de différents mécanismes d'authentification et d'autorisation dans des architectures applicatives modernes.

---

## Sommaire des Travaux Pratiques

| TP | Module | Thématique principale | Branche de référence | Statut |
| :--- | :--- | :--- | :--- | :--- |
| **TP1** | `batcave-security` | Basic Auth, Bcrypt, persistance SQLite, RBAC & audit | `tp1-securite-batcave` | Terminé (`v1.0.0`) |

---

## Démarrage Rapide

```bash
# Se positionner sur le module TP1
cd batcave-security

# Installer les dépendances
npm install

# Démarrer le serveur
npm start
```
Le serveur écoute par défaut sur [http://localhost:3000](http://localhost:3000).

Pour les détails d'exécution, de recettes et les protocoles de tests (cURL, Postman, navigateur), consultez le [Guide de Développement](DEVELOPMENT.md).

---

## Conventions du projet

### Gestion des branches
- **Branche principale** : `master` (code stable et versions taguées).
- **Branches thématiques** : `tp<numero>-<theme>` (ex. : `tp1-securite-batcave`). Chaque TP est développé de façon isolée puis synchronisé de manière linéaire avec `master`.

### Versionnement et releases
Le projet respecte les spécifications [Semantic Versioning 2.0.0](https://semver.org/).
- Chaque rendu ou version stable fait l'objet d'un tag Git annoté (`vX.0.0` pour un TP finalisé, `vX.Y.0` pour un jalon intermédiaire).
- L'historique des changements est tracé dans le fichier [`CHANGELOG.md`](./CHANGELOG.md).

### Documentation attendue
Chaque module / TP comprend :
1. Ce `README.md` global à la racine du dépôt.
2. Un `README.md` dédié dans le sous-dossier du TP détaillant le fonctionnement technique, les endpoints et l'architecture fonctionnelle.
3. Le suivi des modifications consigné dans [`CHANGELOG.md`](./CHANGELOG.md).
4. Le guide de test et de recette dans [`DEVELOPMENT.md`](./DEVELOPMENT.md).

---

## Prérequis et environnement d'exécution
- **Node.js** : v20+ (testé sur v24)
- **Gestionnaire de paquets** : npm
- **Base de données embarquée** : SQLite via `better-sqlite3`
