# Redirections URL simples

Petite application Node.js sans dependance externe pour gerer des redirections `301` depuis une interface web protegee.

## Configuration

Modifiez le fichier `.env`:

```env
PORT=3000
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-moi
SESSION_SECRET=change-moi-aussi
```

## Lancement

```bash
npm start
```

Puis ouvrez `http://localhost:3000`.

## Utilisation

- Connectez-vous avec les identifiants du `.env`
- Ajoutez un chemin source comme `/promo`
- Renseignez la cible comme `https://monsite.com/offre`
- L'application repondra ensuite avec une redirection `301`

Les redirections sont stockees dans `data/redirects.json`.
