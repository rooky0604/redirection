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

## Lancement

```bash
npm start
```

Puis ouvrez `http://localhost:3000`.

## Utilisation

- Connectez-vous avec les identifiants du `.env`
- Ajoutez un chemin source comme `/promo` ou un sous-domaine comme `promo.monsite.com/offre`
- Renseignez la cible comme `https://monsite.com/offre`
- L'application repondra ensuite avec une redirection `301`

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

Points a verifier:

- le DNS doit pointer vers le serveur
- Dokploy doit router ces hosts vers cette application
- si besoin, ajouter un domaine wildcard comme `*.votredomaine.fr` sur l'application

## Verification rapide apres deploiement

1. Deployer l'application
2. Verifier que `DATA_DIR=/app/data` est bien defini
3. Verifier qu'un volume persistant est monte sur `/app/data`
4. Creer une redirection test
5. Redemarrer l'application
6. Verifier que la redirection existe toujours
