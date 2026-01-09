# 🔒 Détection de Failles Web Simples

Outil d'audit applicatif basique pour détecter les vulnérabilités XSS, SQL Injection et vérifier les headers de sécurité.

## ✨ Fonctionnalités

- ✅ **Détection de formulaires vulnérables** - Identifie automatiquement tous les formulaires et les teste
- 🎯 **Tests XSS** - Détection de vulnérabilités Cross-Site Scripting (XSS) dans les formulaires et paramètres URL
- 💉 **Tests SQL Injection** - Détection de vulnérabilités SQL Injection avec différents payloads
- 🛡️ **Vérification des headers de sécurité** - Vérifie la présence et la configuration des headers de sécurité :
  - Content-Security-Policy (CSP)
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - X-XSS-Protection
  - Referrer-Policy
  - Permissions-Policy
- 📝 **Rapports détaillés** - Génère des rapports en format TXT et JSON

## 📋 Prérequis

- Python 3.6 ou supérieur
- Bibliothèques Python (installer avec `pip install -r requirements.txt`)

## 🚀 Installation

1. Installez les dépendances :

```bash
pip install -r requirements.txt
```

2. Rendez le script exécutable (optionnel) :

```bash
chmod +x detection_failles.py
```

## 📖 Utilisation

### Utilisation de base

```bash
python3 detection_failles.py <URL>
```

Exemple :
```bash
python3 detection_failles.py https://example.com
python3 detection_failles.py http://testphp.vulnweb.com
```

### Options disponibles

```bash
python3 detection_failles.py <URL> [options]
```

**Options :**

- `--timeout SECONDS` : Timeout pour les requêtes HTTP (défaut: 10 secondes)
- `--verify-ssl` : Vérifier les certificats SSL (désactivé par défaut pour les tests)
- `--output-dir, -o DIR` : Répertoire de sortie pour les rapports (défaut: `reports`)
- `--json-only` : Générer uniquement le rapport JSON
- `--txt-only` : Générer uniquement le rapport TXT

### Exemples d'utilisation

**Scan de base :**
```bash
python3 detection_failles.py https://example.com
```

**Scan avec vérification SSL :**
```bash
python3 detection_failles.py https://example.com --verify-ssl
```

**Générer uniquement le rapport JSON :**
```bash
python3 detection_failles.py https://example.com --json-only
```

**Sauvegarder dans un répertoire personnalisé :**
```bash
python3 detection_failles.py https://example.com --output-dir mes_rapports
```

**Combinaison d'options :**
```bash
python3 detection_failles.py http://192.168.1.1 --timeout 15 --txt-only -o results
```

## 🎯 Types de vulnérabilités détectées

### Cross-Site Scripting (XSS)

L'outil teste plusieurs vecteurs d'attaque XSS :
- Injection de balises `<script>`
- Injection d'événements HTML (`onerror`, `onload`)
- Injection via protocole `javascript:`
- XSS réfléchi dans les formulaires
- XSS réfléchi dans les paramètres URL

### SQL Injection (SQLi)

L'outil teste plusieurs types d'injection SQL :
- Injection basique : `' OR '1'='1`
- Injection avec commentaires : `' OR '1'='1' --`
- Injection UNION SELECT
- Injection avec SLEEP/WAITFOR (Time-based)
- Détection d'erreurs SQL dans les réponses

### Headers de Sécurité

Vérifie la présence et la configuration de :

- **Content-Security-Policy** : Protection contre XSS et injection
- **Strict-Transport-Security (HSTS)** : Force HTTPS
- **X-Frame-Options** : Protection contre le clickjacking
- **X-Content-Type-Options** : Empêche le MIME-sniffing
- **X-XSS-Protection** : Protection XSS du navigateur
- **Referrer-Policy** : Contrôle les informations du referrer
- **Permissions-Policy** : Contrôle les fonctionnalités du navigateur

## 📝 Format des rapports

### Rapport TXT

Le rapport TXT contient :
- Liste des vulnérabilités XSS détectées avec payloads
- Liste des vulnérabilités SQL Injection détectées
- Analyse des headers de sécurité (présents, manquants, problèmes)
- Recommandations de correction pour chaque problème

### Rapport JSON

Le rapport JSON contient toutes les informations structurées :
- Métadonnées (URL, date de scan)
- Liste complète des vulnérabilités
- Détails des headers de sécurité
- Résumé statistique

**Exemple de structure JSON:**
```json
{
  "metadata": {
    "target": "https://example.com",
    "scan_date": "2024-01-15T10:30:00",
    "report_version": "1.0"
  },
  "vulnerabilities": {
    "xss": [...],
    "sqli": [...],
    "security_headers": {...}
  },
  "summary": {
    "xss_count": 2,
    "sqli_count": 1,
    "missing_headers_count": 3,
    "total_issues": 6
  }
}
```

## 🧪 Sites de test

Pour tester l'outil de manière légale :

- **testphp.vulnweb.com** - Site de test avec vulnérabilités intentionnelles
- **httpbin.org** - Service HTTP de test
- Votre propre application locale

⚠️ **IMPORTANT** : Ne testez que des sites que vous autorisez ou des sites de test publics.

## ⚠️ Limitations et avertissements

### Limitations

- Cet outil effectue des tests basiques et ne remplace pas un audit de sécurité professionnel
- Les tests sont basiques et peuvent produire des faux positifs/négatifs
- Ne teste pas toutes les variantes d'injection possibles
- Les tests sont visibles dans les logs du serveur cible

### Avertissements légaux

- ⚠️ **N'utilisez cet outil QUE sur des systèmes que vous autorisez**
- Le test de vulnérabilités sur des systèmes non autorisés est **ILLÉGAL**
- Assurez-vous d'avoir une autorisation écrite avant tout test
- Respectez les conditions d'utilisation des sites testés

## 🔧 Dépannage

**Erreur : "ModuleNotFoundError: No module named 'requests'"**
```bash
pip install -r requirements.txt
```

**Erreur : "SSL certificate verify failed"**
- Utilisez `--verify-ssl` seulement si vous avez confiance dans le certificat
- Ou testez sur un environnement local

**Erreur : "Connection timeout"**
- Augmentez le timeout avec `--timeout 30`
- Vérifiez que le site est accessible

**Aucune vulnérabilité détectée**
- Cela ne signifie pas nécessairement qu'il n'y en a pas
- Cet outil effectue des tests basiques
- Consultez un expert en sécurité pour un audit complet

## 📚 Ressources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Security Headers](https://securityheaders.com/)

## 📄 Licence

Ce projet est fourni tel quel, à des fins éducatives.

## 👤 Auteur

Détection de Failles Web Simples - Projet Python

---

**Note** : Utilisez cet outil de manière responsable et éthique. Les tests de sécurité non autorisés sont illégaux.

