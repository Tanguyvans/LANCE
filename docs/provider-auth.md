# Authentification des mutations de providers

Les écritures du registre SQLite via `POST /api/providers` et
`PATCH /api/providers/{name}` exigent un en-tête :

```text
Authorization: Bearer <LANCE_ADMIN_TOKEN>
```

Le serveur lit `LANCE_ADMIN_TOKEN` depuis l’environnement. Une variable
absente ou vide est un défaut de configuration et renvoie `503` avec
`detail.code = "admin_auth_not_configured"`, sans appeler la route d’écriture.
Une panne DB renvoie aussi `503`, mais sans ce code d’authentification. Un
en-tête absent, mal formé ou invalide renvoie `401` avec
`WWW-Authenticate: Bearer`. La comparaison du jeton est constante et le jeton
n’est jamais inclus dans une réponse.

Le `GET /api/providers` et les autres routes restent inchangés dans ce lot.
Cette protection ne constitue donc pas une authentification complète de
l’application : elle couvre uniquement les deux mutations du registre des
providers.

Dans le gestionnaire « Modèles & Providers », la clé est saisie dans un champ
mot de passe visible et peut être collée. Elle reste uniquement en mémoire
JavaScript de la page, n’est pas persistée. L’action « Effacer la clé et
fermer », la croix, Échap et la fermeture par le fond la suppriment de la
mémoire et du DOM.

## Déploiement

Configurez une clé aléatoire, dédiée à ce tableau de bord, directement sur le
mini-PC qui héberge le service (par exemple avec `openssl rand -hex 32`), dans
le gestionnaire de secrets ou l’environnement du service. Ne l’ajoutez jamais
à Git, à `.env.example`, à une capture d’écran ou à une URL. Exposez le
gestionnaire uniquement derrière HTTPS ou un tunnel de confiance avec contrôle
d’accès ; ce jeton ne remplace pas cette protection réseau.
