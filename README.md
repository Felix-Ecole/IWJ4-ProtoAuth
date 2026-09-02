# IWJ4 - ProtoAuth : Protocoles et Architectures d'Authentification

Projet pédagogique dédié à l'étude et à l'implémentation progressive de différents mécanismes d'authentification et d'autorisation dans des architectures applicatives modernes.

---

## Sommaire des Travaux Pratiques

| TP | Module | Thématique principale | Branche de référence | Statut |
| :--- | :--- | :--- | :--- | :--- |
| **TP1** | `batcave-security` | Basic Auth, Bcrypt, persistance SQLite, RBAC & audit | `tp1-securite-batcave` | En cours |

---

## Conventions du projet

### Gestion des branches
- **Branche principale** : `master` (code stable et versions taguées).
- **Branches thématiques** : `tp<numero>-<theme>` (ex. : `tp1-securite-batcave`). Chaque TP est isolé sur sa branche dédiée puis synchronisé de façon linéaire avec `master`.

### Versionnement et releases
Le projet respecte les spécifications [Semantic Versioning 2.0.0](https://semver.org/).
- Chaque rendu ou version stable fait l'objet d'un tag Git annoté (`vX.0.0` pour un TP finalisé, `vX.Y.0` pour un jalon intermédiaire).
- L'historique des changements est tracé dans le fichier [`CHANGELOG.md`](./CHANGELOG.md).

### Documentation attendue
Chaque module / TP comprend :
1. Ce `README.md` global à la racine du dépôt.
2. Un `README.md` dédié dans le sous-dossier du TP détaillant le fonctionnement technique, les endpoints et les consignes de lancement.
3. Le suivi des modifications consigné dans `CHANGELOG.md`.

---

## Prérequis et environnement d'exécution
- **Node.js** : v20+ (recommandé v24)
- **Gestionnaire de paquets** : npm
- **Base de données embarquée** : SQLite via `better-sqlite3`
