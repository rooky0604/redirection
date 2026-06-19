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
