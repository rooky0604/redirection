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

## Planning (page publique)

La page publique `/planning` affiche la grille de la semaine (lundi a dimanche) : streams termines les jours passes (lus par rooky-tv dans l'agenda Google de la chaine, sans lien Google ici), puis le planning a venir avec le programme de chaque stream. Un bouton "Programme de la semaine" y mene depuis la page d'accueil des que la chaine du site est renseignee. Rien ne se saisit sur ce site et rien n'est publie sur Discord.

1. Dans `/admin/planning`, indiquez la chaine Twitch du site et enregistrez : un code de liaison s'affiche.
2. Sur rooky-tv (Programme > Programme sur Discord > Sites redirection), collez ce code puis "Relier".
3. rooky-tv envoie ensuite le programme a chaque changement (`POST /api/planning/sync`, protege par le code).

Image sur Discord : dans `/admin/planning`, collez le webhook d'un salon. Le programme de la semaine y est publie en image (meme grille que la page) et le message est mis a jour tout seul, sans notification, a chaque changement du planning et a chaque nouveau jour. "Republier" poste un nouveau message (mention optionnelle). L'image est generee avec `sharp` ; l'image Docker installe la police DejaVu (`font-dejavu`) et les dependances (`npm ci`).

"Nouveau code" invalide l'ancien (a recoller dans rooky-tv). Le programme recu est stocke dans `planning/<chaine>.json` du dossier `DATA_DIR`, la chaine du site dans `site-config.json`. Aucune variable d'environnement n'est necessaire.

## Mon setup (page publique)

- `/admin/setup` : bouton pour telecharger le script PowerShell `setup/Mon-Setup-Twitch.ps1` (servi tel quel sur `/setup/Mon-Setup-Twitch.ps1`), et juste dessous la ligne a coller dans PowerShell pour l'executer.
- Le script detecte le materiel du PC et ouvre une page locale ; "Copier et ouvrir mon site" copie le texte Markdown (le meme que pour Twitch) a coller dans `/admin/setup`.
- Le texte est garde tel quel dans `setup.json` (par espace) et affiche en cartes sur `/setup` ; un bouton "Mon setup" apparait sur la page d'accueil.

- `/config` : adresse courte de la page `/setup`, a mettre telle quelle dans une commande `!config` (n'importe quel bot, texte fixe).
- `/setup/config` : la config sur une ligne de chat (texte brut, 450 caracteres par defaut, `?max=100..500`), toujours a jour avec le setup enregistre ; les derniers elements sont retires (…) si c'est trop long, le lien `/setup` reste. Pour une commande Twitch `!config` : Nightbot `!commands add !config $(urlfetch <site>/setup/config)`, StreamElements `!command add !config ${customapi.<site>/setup/config}` (donnees sur `/admin/setup`).

### Securite du script (depot public et empreinte)

- **Reference : le depot public [rooky0604/mon-setup-twitch](https://github.com/rooky0604/mon-setup-twitch)** (script, `Mon-Setup-Twitch.ps1.sha256`, une release + un tag `vX.Y.Z` par version, tableau de tracabilite dans son README, GitHub Action `verify.yml`).
- `setup/Mon-Setup-Twitch.ps1` est une copie exacte (octet pour octet, LF impose par `.gitattributes`) : le meme fichier sur tous les sites, l'adresse du site n'est pas ecrite dedans (la ligne PowerShell la passe en `$SiteUrl`, sinon le script la lit dans la marque de telechargement de Windows).
- La GitHub Action `verify-setup-script.yml` de ce depot verifie que `setup/Mon-Setup-Twitch.ps1.sha256` correspond a la copie **et** que la copie a la meme empreinte que le depot public (et que le script reste ASCII, LF, sans erreur de syntaxe).
- La ligne PowerShell lit l'empreinte dans le depot public (raw.githubusercontent.com) et ne lance le script que si elle est identique ; lance depuis un fichier, le script compare lui-meme son empreinte au depot. Dans les deux cas il affiche sa version, le lien du depot et `/setup/verification`, ce qu'il va faire, et demande de valider l'operation (O).
- Page publique **`/setup/verification`** : ce que fait le script, empreinte du fichier servi comparee au depot public, liens (depot, code, .sha256, versions, historique, verifications), ligne PowerShell et commande `Get-FileHash`. Lien sur `/admin/setup` seulement (ligne "Liste generee par un script public..." sous l'apercu et bouton "Page de verification"), pas sur `/setup`.
- **Publier une nouvelle version** : dans `mon-setup-twitch`, modifier le script et `$SetupVersion`, `sha256sum Mon-Setup-Twitch.ps1 > Mon-Setup-Twitch.ps1.sha256`, ajouter la ligne au tableau du README, commit + tag `vX.Y.Z` + release ; puis copier les deux fichiers dans `setup/` ici et pousser.

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

## Espaces : d'autres streamers sur leur propre domaine

Le meme site peut heberger l'espace d'autres streamers, chacun sur son propre domaine (ex. `streamerb.fr`), a cote de l'espace principal (`lien.rooky.fr`). Chaque espace est completement separe :

| Separe par espace | Commun a tout le site |
|---|---|
| Liens et page publique, apparence, statistiques | Demandes de sites (`/admin/requests`) |
| Planning public et code de liaison avec rooky-tv | Liste des espaces (`data/spaces.json`) |
| Espace modo, tickets, groupes locaux de l'equipe | |
| Monitoring (webhooks, bots) | |
| Administration (`/admin`) | |

L'espace est choisi d'apres le domaine de chaque visite. Fichiers d'un espace : `data/spaces/<id>/` ; l'espace principal garde ceux de `data/`.

### Creer un espace

1. Le streamer fait sa demande sur `https://lien.rooky.fr/register` (connexion Discord via bot.rooky.fr, proprietaire du serveur Discord), avec l'adresse de son domaine (`https://streamerb.fr`).
2. Dans **Admin > Demandes de sites**, sur sa demande : **Heberger ici**. La chaine Twitch est facultative ; si elle est donnee, le planning est relie tout de suite et son code de liaison lui est affiche sur `/register`.
3. Dans **Dokploy > Domains** de cette application : ajouter son domaine (et `www.` si besoin), meme port que `lien.rooky.fr`, HTTPS active.
4. Le streamer fait pointer son DNS vers le serveur (enregistrement A, ou CNAME vers `lien.rooky.fr`).

### Administration d'un espace

- Le proprietaire va sur `https://son-domaine/admin` -> **Se connecter avec Discord**. Seul le proprietaire du serveur Discord de l'espace est accepte (verifie par bot.rooky.fr). Le code de connexion est lie a son domaine : il ne sert pas sur un autre espace.
- Une fois le planning relie, le streamer de la chaine peut aussi passer par **Acces modo**.
- Il ne voit que son espace : pas les demandes de sites, ni les autres espaces.
- Toi (mot de passe `ADMIN_*`, ou owner de rooky-tv par Acces modo) : administrateur de tous les espaces.

### Retirer un espace

**Admin > Demandes de sites** -> **Retirer l'espace** : son domaine affiche de nouveau l'espace principal. Ses fichiers restent dans `data/spaces/<id>/` (supprimables a la main). Penser a retirer aussi le domaine dans Dokploy.

`lien.rooky.fr` reste toujours l'espace principal, avec ses pages publiques : il ne peut jamais devenir un autre espace, ni aucun domaine deja utilise par ses redirections (`createur.rooky.fr`, `*.rooky.fr`...). "Heberger ici" refuse ces demandes.

Variables facultatives : `MAIN_SITE_HOSTS` (defaut `lien.rooky.fr`, plusieurs separes par des virgules), domaines de l'espace principal ; `BOT_SITE_URL` (defaut `https://bot.rooky.fr`), adresse de rooky-tv pour la connexion Discord.

## Verification rapide apres deploiement

1. Deployer l'application
2. Verifier que `DATA_DIR=/app/data` est bien defini
3. Verifier qu'un volume persistant est monte sur `/app/data`
4. Verifier que le domaine utilise est bien ajoute dans Dokploy (onglet Domains) avec un certificat valide
5. Verifier que les redirections existent toujours apres un redeploiement
