# 🛡️ Password Manager Daemon (C/Kore)

Un gestionnaire de mots de passe ultra-léger conçu pour macOS, utilisant **Kore** comme serveur backend et **SQLite** pour la persistance.

## 🚀 Architecture

- **Backend** : Langage C avec le framework [Kore.io](https://kore.io).
- **Base de données** : SQLite3.
- **Sécurité** : Génération via `/dev/urandom`.
- **Interface** : API REST (consommée par un futur client Vue.js).

## 🛠️ Installation & Build

### Prérequis

- macOS avec Homebrew
- Kore : `brew install kore`
- SQLite3 (inclus par défaut sur macOS)

### Compilation

Pour compiler le module :

```bash
kore build
```

## ▶️ Utilisation

### Lancer le serveur

Le serveur est expose en local sur `http://127.0.0.1:8888`.

### Exemples d'appels API

Lister les mots de passe :

```bash
curl -X GET http://127.0.0.1:8888/api/passwords
```

Generer et sauvegarder un mot de passe :

```bash
curl -X POST http://127.0.0.1:8888/api/passwords/generate
```

Supprimer un mot de passe :

```bash
curl -X DELETE http://127.0.0.1:8888/api/passwords/delete
```
