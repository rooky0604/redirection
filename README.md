# Redirections URL simples

Petite application Node.js sans dependance externe pour gerer des redirections `301` depuis une interface web protegee.

## Configuration

Modifiez le fichier `.env`:

```env
PORT=3000
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-moi
SESSION_SECRET=change-moi-aussi
DATA_DIR=./data
```

Le TLS (HTTPS) n'est pas gere par l'application: il est pris en charge par Dokploy/Traefik au niveau de la plateforme, pour chaque domaine declare dans l'onglet Domains.

## Lancement

```bash
npm start
```

Ouvrez `http://localhost:3000`.

## Utilisation

- Connectez-vous avec les identifiants du `.env`
- Ajoutez un chemin source comme `/promo` ou un sous-domaine comme `promo.monsite.com/offre`
- Vous pouvez aussi enregistrer un sous-domaine générique comme `*.monsite.com` : n'importe quel sous-domaine (`service.monsite.com`, `tv.monsite.com`, etc.) sera alors redirigé vers la même cible. Le domaine racine seul (`monsite.com`) n'est pas couvert par ce wildcard, il faut l'enregistrer separement si besoin.
- Renseignez la cible comme `https://monsite.com/offre` (toujours avec le prefixe `https://` ou `http://` pour une cible externe, sinon elle est interpretee comme une autre source deja enregistree dans l'application)
- L'application repondra ensuite avec une redirection `301`

Important pour le wildcard `*.monsite.com`: cote DNS et Dokploy, un domaine wildcard doit aussi etre declare (DNS `*.monsite.com` et domaine `*.monsite.com` cote Dokploy/Traefik) pour que le trafic des sous-domaines non prevus atteigne bien le conteneur. Sans ca, seuls les sous-domaines explicitement declares dans Dokploy fonctionneront, meme si la redirection est bien enregistree dans l'application.

## Persistance Dokploy

Les redirections sont stockees dans `redirects.json` dans le dossier `DATA_DIR`.

En local, vous pouvez laisser `DATA_DIR=./data`.
Dans Dokploy, montez un volume persistant sur `/app/data` et laissez:

```env
DATA_DIR=/app/data
```

Configuration recommandee dans Dokploy:

- Variable d'environnement: `DATA_DIR=/app/data`
- Volume persistant:
  - type recommande: `Volume Mount`
  - `Volume Name`: `redirect-data`
  - `Mount Path`: `/app/data`

Explication des champs Dokploy:

- `Volume Name`: c'est le nom du stockage persistant cree par Docker/Dokploy. Vous pouvez choisir un autre nom, mais `redirect-data` permet d'identifier clairement a quoi sert ce volume.
- `Mount Path`: c'est le chemin a l'interieur du conteneur ou ce stockage est branche. L'application lit et ecrit ses redirections dans ce dossier.
- avec `DATA_DIR=/app/data`, l'application stocke ses donnees dans `/app/data/redirects.json`
- si le volume `redirect-data` est monte sur `/app/data`, alors ce fichier reste present meme apres un redemarrage ou un redeploiement du conteneur

Important:

- si aucun volume persistant n'est monte sur `/app/data`, les redirections seront perdues au redemarrage ou redeploiement du conteneur
- si le dossier est bien monte, les redirections restent conservees entre les redeploiements

## Sous-domaines avec Dokploy

Si vous voulez rediriger des sous-domaines comme `createur.rooky.fr` ou `tv.rooky.fr`, l'application sait les gerer, mais le routage doit aussi etre configure dans Dokploy et dans le DNS.

Exemples de source valides dans l'interface:

- `createur.rooky.fr`
- `createur.rooky.fr/mon-chemin`
- `/mon-chemin`
- `*.rooky.fr` (wildcard, couvre tous les sous-domaines)

Points a verifier:

- le DNS doit pointer vers le serveur pour chaque domaine/sous-domaine utilise
- Dokploy doit router ces hosts vers cette application (onglet Domains, avec le bon port conteneur, `PORT` dans `.env`)
- le certificat TLS de chaque domaine est gere automatiquement par Dokploy/Traefik, rien a faire cote application

## Verification rapide apres deploiement

1. Deployer l'application
2. Verifier que `DATA_DIR=/app/data` est bien defini
3. Verifier qu'un volume persistant est monte sur `/app/data`
4. Verifier que le domaine utilise est bien ajoute dans Dokploy (onglet Domains) avec un certificat valide
5. Verifier que les redirections existent toujours apres un redeploiement
