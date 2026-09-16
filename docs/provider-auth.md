# Authentification des actions administratives

Toutes les routes API de mutation (`POST`, `PUT`, `PATCH`, `DELETE`) exigent un en-tête :

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

Cela couvre les runs et batches, leur arrêt, le déploiement et le nettoyage,
la génération de scénarios, l'évaluation LLM et les modifications de modèles
et fournisseurs. La dépendance est posée sur l'application FastAPI : les
nouvelles mutations sont également protégées par défaut. Les lectures restent
accessibles sans clé : les rapports et journaux ne sont pas rendus confidentiels.

## Tableau de bord

Saisissez la clé dans « Accès administrateur », en haut de la page, avant une
action. Ce champ mot de passe possède un libellé et un retour d'erreur ; il
s'ouvre après un refus `401`. La clé reste dans la page, sans stockage
persistant. « Effacer » la retire du champ, et un rechargement la supprime.
Elle n'est envoyée que pour les mutations API de même origine ; les redirections
de ces requêtes sont refusées. Le navigateur et l'API doivent être servis sur
la même origine ; les mutations depuis une autre origine sont refusées par CORS.

Dans le gestionnaire « Modèles & Providers », la clé est saisie dans un champ
mot de passe visible et peut être collée. Elle reste uniquement en mémoire
JavaScript de la page, n’est pas persistée. L’action « Effacer la clé et
fermer », la croix, Échap et la fermeture par le fond la suppriment de la
mémoire et du DOM.

Ce champ historique prime sur le champ global pour les mutations de fournisseurs
uniquement. Sa fermeture n'efface pas le champ global. Utilisez le champ global
pour les autres actions, notamment les modifications des modèles.

## Déploiement

Configurez une clé aléatoire, dédiée à ce tableau de bord, directement sur le
mini-PC qui héberge le service (par exemple avec `openssl rand -hex 32`), dans
le gestionnaire de secrets ou l’environnement du service. Ne l’ajoutez jamais
à Git, à `.env.example`, à une capture d’écran ou à une URL. Exposez le
gestionnaire uniquement derrière HTTPS ou un tunnel de confiance avec contrôle
d’accès ; ce jeton ne remplace pas cette protection réseau.

Sans configuration de `LANCE_ADMIN_TOKEN`, les actions du dashboard sont
volontairement bloquées. La CLI locale n'utilise pas cette authentification HTTP.

## Fournisseurs d’exécution

OpenRouter, Codex et Anthropic ne sont plus des fournisseurs exécutables dans
LANCE : CLI, worker, API de lancement et évaluation LLM les refusent explicitement.
Le pont d’exécution Codex est supprimé. Leurs anciennes lignes dans le registre
et leurs résultats restent consultables ; aucune migration ne les efface.

Pour lancer un run, choisir explicitement `provider` et `model` dans l’API.
La CLI et le worker exigent `--provider` ou `AGENT_PROVIDER` ; ils n’ont plus
de fournisseur implicite. Les fournisseurs personnalisés enregistrés en base,
notamment Ollama et les endpoints locaux, restent disponibles. Un modèle choisi
pour une phase particulière doit être enregistré avec son fournisseur : son
nom ne permet plus de deviner un abonnement ou un fournisseur cloud.

La source de tarifs OpenRouter reste utilisée pour **estimer les coûts**, pas
pour exécuter des modèles. Elle peut effectuer des requêtes de catalogue public ;
aucun prompt ne lui est envoyé par ce mécanisme. Les tarifs historiques et les
compteurs de tokens ne sont pas supprimés.

Le backfill des anciens runs reprend le fournisseur et le statut des métadonnées.
Sans fournisseur enregistré, il indique `unknown` ; sans statut, `partial`.
La présence d’un rapport n’est pas une preuve de réussite.
