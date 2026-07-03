# Redirections URL simples

Petite application Node.js sans dependance externe pour gerer des redirections `301` depuis une interface web protegee.

## Configuration

Modifiez le fichier `.env`:

```env
PORT=3000
HTTP_PORT=80
HTTPS_PORT=443
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-moi
SESSION_SECRET=change-moi-aussi
DATA_DIR=./data
LETSENCRYPT_EMAIL=
LETSENCRYPT_DOMAINS=
LETSENCRYPT_STAGING=false
CERTBOT_BIN=certbot
```

Variables TLS:

- `LETSENCRYPT_EMAIL`: email utilise pour Let's Encrypt
- `LETSENCRYPT_DOMAINS`: liste des domaines separes par des virgules ou espaces
- `HTTP_PORT`: port HTTP expose pour le challenge ACME et la redirection vers HTTPS
- `HTTPS_PORT`: port HTTPS de l'application
- `LETSENCRYPT_STAGING=true`: a utiliser pour valider la configuration sans consommer les quotas de production
- `CERTBOT_BIN`: binaire a lancer si `certbot` n'est pas dans le `PATH`

## Lancement

```bash
npm start
```

Sans configuration TLS, ouvrez `http://localhost:3000`.

Avec `LETSENCRYPT_EMAIL` et au moins un domaine:

- au demarrage, l'application verifie si un certificat existe deja dans `DATA_DIR/letsencrypt`
- si le certificat existe, l'application sert en HTTPS sur `HTTPS_PORT` et redirige le HTTP vers HTTPS sur `HTTP_PORT`
- sinon, l'application demarre en HTTP simple et affiche dans les logs la commande `certbot` exacte a lancer manuellement

Contraintes:

- les domaines doivent deja pointer en DNS vers ce serveur
- les ports `80` et `443` doivent etre exposes
- les domaines wildcard `*.exemple.com` ne sont pas geres par cette implementation, car ils exigent un challenge DNS

## Utilisation

- Connectez-vous avec les identifiants du `.env`
- Ajoutez un chemin source comme `/promo` ou un sous-domaine comme `promo.monsite.com/offre`
- Renseignez la cible comme `https://monsite.com/offre`
- L'application repondra ensuite avec une redirection `301`

## Persistance Dokploy

Les redirections sont stockees dans `redirects.json` dans le dossier `DATA_DIR`.
Les certificats Let's Encrypt sont aussi stockes dans `DATA_DIR/letsencrypt`.

En local, vous pouvez laisser `DATA_DIR=./data`.
Dans Dokploy, montez un volume persistant sur `/app/data` et laissez:

```env
DATA_DIR=/app/data
```

Configuration recommandee dans Dokploy:

- Variable d'environnement: `DATA_DIR=/app/data`
- Variables d'environnement TLS:
  - `LETSENCRYPT_EMAIL=vous@domaine.fr`
  - `LETSENCRYPT_DOMAINS=exemple.fr www.exemple.fr`
  - `LETSENCRYPT_STAGING=true` pour le premier test, puis `false`
- Volume persistant:
  - type recommande: `Volume Mount`
  - `Volume Name`: `redirect-data`
  - `Mount Path`: `/app/data`

Explication des champs Dokploy:

- `Volume Name`: c'est le nom du stockage persistant cree par Docker/Dokploy. Vous pouvez choisir un autre nom, mais `redirect-data` permet d'identifier clairement a quoi sert ce volume.
- `Mount Path`: c'est le chemin a l'interieur du conteneur ou ce stockage est branche. L'application lit et ecrit ses redirections dans ce dossier.
- avec `DATA_DIR=/app/data`, l'application stocke ses donnees dans `/app/data/redirects.json`
- les certificats sont aussi conserves dans `/app/data/letsencrypt`
- si le volume `redirect-data` est monte sur `/app/data`, alors ce fichier reste present meme apres un redemarrage ou un redeploiement du conteneur

Important:

- si aucun volume persistant n'est monte sur `/app/data`, les redirections seront perdues au redemarrage ou redeploiement du conteneur
- sans volume persistant, les certificats Let's Encrypt seront aussi redemandes, ce qui peut provoquer des erreurs de quota
- si le dossier est bien monte, les redirections restent conservees entre les redeploiements

## Sous-domaines avec Dokploy

Si vous voulez rediriger des sous-domaines comme `createur.rooky.fr` ou `tv.rooky.fr`, l'application sait les gerer, mais le routage doit aussi etre configure dans Dokploy et dans le DNS.

Exemples de source valides dans l'interface:

- `createur.rooky.fr`
- `createur.rooky.fr/mon-chemin`
- `/mon-chemin`

Points a verifier:

- le DNS doit pointer vers le serveur
- Dokploy doit router ces hosts vers cette application
- si besoin, ajouter un domaine wildcard comme `*.votredomaine.fr` sur l'application
- pour Let's Encrypt HTTP-01, les domaines non-wildcard doivent aussi etre routables publiquement sur le port 80

## Verification rapide apres deploiement

1. Deployer l'application
2. Verifier que `DATA_DIR=/app/data` est bien defini
3. Verifier qu'un volume persistant est monte sur `/app/data`
4. Renseigner `LETSENCRYPT_EMAIL` et `LETSENCRYPT_DOMAINS`
5. Lancer un premier deploiement avec `LETSENCRYPT_STAGING=true`
6. Verifier que le certificat est cree
7. Passer `LETSENCRYPT_STAGING=false`
8. Redemarrer l'application
9. Verifier que les redirections et le certificat existent toujours
