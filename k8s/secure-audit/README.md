# Déploiement Kubernetes — Secure Audit (By Build Web)

Ce dossier contient les manifests Kubernetes pour déployer l'application
**Secure Audit** sur un cluster Kubernetes.

---

## Fichiers

| Fichier | Description |
|---|---|
| `secret.yaml` | Clé secrète Flask, utilisateurs initiaux et compte de secours |
| `pvc.yaml` | Volume persistant pour stocker `users.json` |
| `deployment.yaml` | Déploiement de l'application (1 réplica) |
| `service.yaml` | Service ClusterIP exposant le port 80 → 5000 |
| `ingress.yaml` | Ingress NGINX avec TLS Let's Encrypt |

---

## Prérequis

- Cluster Kubernetes (≥ 1.25)
- `kubectl` configuré sur le bon contexte
- Contrôleur Ingress NGINX installé
- cert-manager installé (pour le TLS automatique)
- L'image Docker `secure-audit:latest` accessible depuis le cluster

---

## Construction de l'image

Depuis la racine du projet `audit/` :

```bash
docker build -t secure-audit:latest docker/secure-audit/
```

Pour pousser vers un registry :

```bash
docker tag secure-audit:latest registry.example.com/secure-audit:1.0.0
docker push registry.example.com/secure-audit:1.0.0
```

Mettre à jour l'image dans `deployment.yaml` :
```yaml
image: registry.example.com/secure-audit:1.0.0
```

---

## Déploiement étape par étape

### 1. Créer le namespace

Le namespace `audit` est partagé avec les autres composants du projet.
S'il n'existe pas encore :

```bash
kubectl apply -f ../namespace.yaml
# ou
kubectl create namespace audit
```

### 2. Configurer les utilisateurs initiaux

Éditer `secret.yaml` avant d'appliquer. Les valeurs sont encodées en base64.

#### Clé secrète Flask

Générer une clé aléatoire solide (minimum 32 caractères) :

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# Encoder le résultat
echo -n "la-cle-generee" | base64
```

Remplacer la valeur de `SECRET_KEY` dans `secret.yaml`.

#### Utilisateurs — via `INITIAL_USERS`

C'est la méthode principale. Au **premier démarrage**, le container lit la
variable `INITIAL_USERS` (JSON) et crée automatiquement le fichier `users.json`
dans le volume persistant. Les démarrages suivants ignorent cette variable
puisque le fichier existe déjà.

**Format JSON :**

```json
[
  {
    "username": "admin",
    "password": "MonMotDePasseAdmin"
  },
  {
    "username": "chez-meilan",
    "password": "MonMotDePasseClient",
    "allowed_urls": ["https://chez-meilan.fr"],
    "description": "Client Chez Meilan"
  }
]
```

- Sans `allowed_urls` (ou `null`) → accès illimité (compte admin)
- Avec `allowed_urls` → l'utilisateur ne peut auditer que ces URLs
- Plusieurs URLs possibles : `["https://site1.fr", "https://site2.fr"]`

**Encoder pour le secret Kubernetes :**

```bash
echo -n '[{"username":"admin","password":"MonMotDePasseAdmin"},{"username":"chez-meilan","password":"MonMotDePasseClient","allowed_urls":["https://chez-meilan.fr"],"description":"Client Chez Meilan"}]' \
  | base64 -w 0
```

Remplacer la valeur de `INITIAL_USERS` dans `secret.yaml`.

> **En production**, utiliser [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
> ou [External Secrets Operator](https://external-secrets.io/) plutôt que de stocker
> des secrets en clair dans le dépôt Git.

### 3. Appliquer tous les manifests

```bash
kubectl apply -f k8s/secure-audit/
```

Ou dans l'ordre explicite :

```bash
kubectl apply -f k8s/secure-audit/secret.yaml
kubectl apply -f k8s/secure-audit/pvc.yaml
kubectl apply -f k8s/secure-audit/deployment.yaml
kubectl apply -f k8s/secure-audit/service.yaml
kubectl apply -f k8s/secure-audit/ingress.yaml
```

### 4. Configurer le domaine

Modifier `ingress.yaml` : remplacer `audit.example.com` par votre domaine réel,
puis pointer ce domaine vers l'IP de votre Ingress NGINX.

```bash
kubectl get ingress -n audit secure-audit
```

### 5. Vérifier le déploiement

```bash
# Statut des pods
kubectl get pods -n audit -l app=secure-audit

# Vérifier que les utilisateurs ont bien été initialisés (premier démarrage)
kubectl logs -n audit -l app=secure-audit | grep "\[init\]"
# Attendu : [init] 2 utilisateur(s) initialisé(s) → /app/data/users.json

# Logs en temps réel
kubectl logs -n audit -l app=secure-audit -f

# Statut du certificat TLS
kubectl get certificate -n audit secure-audit-tls
```

---

## Gestion des utilisateurs

Les utilisateurs sont stockés dans `/app/data/users.json` (volume persistant).
Le script `manage_users.py` permet de gérer ce fichier sans redéployer.

### Lister les utilisateurs

```bash
kubectl exec -n audit deploy/secure-audit -- \
  python /app/manage_users.py list
```

### Ajouter un utilisateur

```bash
# Compte admin (accès illimité)
kubectl exec -n audit deploy/secure-audit -- \
  python /app/manage_users.py add nouvel-admin \
  --password MonMotDePasse

# Compte restreint à un site
kubectl exec -n audit deploy/secure-audit -- \
  python /app/manage_users.py add nouveau-client \
  --password MonMotDePasse \
  --url https://nouveauclient.fr \
  --description "Client Nouveau"

# Compte restreint à plusieurs sites
kubectl exec -n audit deploy/secure-audit -- \
  python /app/manage_users.py add multi-sites \
  --password MonMotDePasse \
  --url https://site1.fr \
  --url https://site2.fr
```

### Changer un mot de passe

```bash
kubectl exec -n audit deploy/secure-audit -- \
  python /app/manage_users.py passwd chez-meilan \
  --password NouveauMotDePasse
```

### Supprimer un utilisateur

```bash
kubectl exec -n audit deploy/secure-audit -- \
  python /app/manage_users.py delete chez-meilan
```

### Réinitialiser tous les utilisateurs depuis `INITIAL_USERS`

Si vous modifiez le secret `INITIAL_USERS` et souhaitez repartir de zéro,
supprimer `users.json` puis redémarrer le pod :

```bash
# Supprimer users.json dans le volume
kubectl exec -n audit deploy/secure-audit -- rm /app/data/users.json

# Redémarrer le pod (relit INITIAL_USERS et recrée users.json)
kubectl rollout restart deployment/secure-audit -n audit

# Vérifier la recréation dans les logs
kubectl logs -n audit -l app=secure-audit | grep "\[init\]"
```

---

## Comportement de l'interface selon le type de compte

| Type de compte | Champ URL dans le formulaire |
|---|---|
| Admin (`allowed_urls: null`) | Champ texte libre — peut auditer n'importe quelle URL |
| Client 1 site | Champ pré-rempli en lecture seule — URL non modifiable |
| Client N sites | Liste déroulante avec ses sites autorisés uniquement |

Toute tentative de soumettre une URL non autorisée via l'API est bloquée
côté serveur (HTTP 403), indépendamment de l'interface.

---

## Mise à jour de l'application

```bash
# Rebuilder et repousser l'image
docker build -t registry.example.com/secure-audit:1.0.1 docker/secure-audit/
docker push registry.example.com/secure-audit:1.0.1

# Mettre à jour le tag dans deployment.yaml, puis appliquer
kubectl apply -f k8s/secure-audit/deployment.yaml

# Ou forcer un redémarrage sans changer de tag (ex: tag "latest")
kubectl rollout restart deployment/secure-audit -n audit
```

> Le volume persistant (`/app/data/users.json`) est conservé lors des mises à jour —
> les utilisateurs ne sont pas perdus.

---

## Notes importantes

### Réplicas

L'application utilise **1 seul réplica** (`replicas: 1`). Les jobs d'audit en cours
sont stockés en mémoire — plusieurs réplicas provoqueraient des incohérences.

Pour passer à plusieurs réplicas, il faudrait migrer le stockage des jobs vers
Redis ou une base de données (PostgreSQL).

### Sécurité

- Modifier **impérativement** les mots de passe par défaut dans `secret.yaml` avant tout déploiement.
- Utiliser une `SECRET_KEY` longue et aléatoire (minimum 32 caractères).
- Le TLS est géré automatiquement par cert-manager + Let's Encrypt via l'Ingress.
- Ne jamais committer `secret.yaml` avec de vraies valeurs dans Git.

### Ressources

Les `requests` et `limits` sont dimensionnés pour un usage léger.
Un audit peut consommer davantage de CPU/RAM pendant les scans — ajuster si nécessaire.

---

## Suppression

```bash
# Supprimer les manifests (le volume persistant est conservé)
kubectl delete -f k8s/secure-audit/

# Supprimer également le volume (supprime users.json définitivement)
kubectl delete pvc secure-audit-data -n audit
```

---

*Déployé par **Build Web** — contact@buildweb.fr — 07 81 55 02 56*
