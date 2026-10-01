# Authentification des actions administratives

Les lancements (`POST /api/pipeline/start`, y compris le déploiement seul,
et `POST /api/pipeline/batch`) sont accessibles sans clé ni session, même
sans `LANCE_ADMIN_TOKEN`. Les validations et contrôles de concurrence restent actifs.
Le navigateur envoie ces lancements sans clé ni cookie de session administrateur.

Les autres routes API de mutation (`POST`, `PUT`, `PATCH`, `DELETE`) exigent
une authentification : session navigateur valide ou en-tête :

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

Cela couvre l’arrêt des runs et batches, le nettoyage,
la génération de scénarios, l'évaluation LLM et les modifications de modèles
et fournisseurs. La dépendance est posée sur l'application FastAPI : les
nouvelles mutations sont également protégées par défaut, sauf les deux routes
de lancement explicitement exemptées. Les lectures restent
accessibles sans clé : les rapports et journaux ne sont pas rendus confidentiels.

## Tableau de bord

Le tableau de bord ne présente plus de bandeau de connexion administrateur.
Les runs et batches se lancent directement, sans clé ni session.

Le gestionnaire « Modèles & Providers » conserve son champ de clé pour les
mutations de fournisseurs. Cette clé reste uniquement en mémoire et est effacée
à la fermeture du gestionnaire. Les autres mutations protégées peuvent être
appelées avec une authentification API ; voir la [session administrateur](admin-session.md).
Les lectures restent accessibles sans connexion.

## Déploiement

Configurez une clé aléatoire, dédiée à ce tableau de bord, directement sur le
mini-PC qui héberge le service (par exemple avec `openssl rand -hex 32`), dans
le gestionnaire de secrets ou l’environnement du service. Ne l’ajoutez jamais
à Git, à `.env.example`, à une capture d’écran ou à une URL. Exposez le
gestionnaire uniquement derrière HTTPS ou un tunnel de confiance avec contrôle
d’accès ; ce jeton ne remplace pas cette protection réseau.

Sans configuration de `LANCE_ADMIN_TOKEN`, les actions administratives restent
bloquées ; les lancements de scénarios et batches restent accessibles. La CLI locale n'utilise pas cette authentification HTTP.

## Fournisseurs d’exécution

Pour le point d’accès `ollama-umons`, le choix des modèles et les commandes de
diagnostic, consulter le [guide LLM UMONS](umons-llm.md).

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

### Dialogue avec les outils

L’endpoint `ollama-umons` a rejeté des historiques terminés par des résultats
d’outils (`no user query found in messages`). Pour ce fournisseur, LANCE ajoute
une courte continuation utilisateur après le groupe complet de résultats, avant
la requête suivante. La demande initiale, les appels, leurs identifiants et leurs
résultats restent inchangés ; les outils ne sont pas réexécutés par l’adaptation.
La continuation demande au modèle d’utiliser les observations existantes sans
répéter les actions terminées. Elle ne garantit pas que le modèle ne proposera
jamais de recherche redondante.

Cette compatibilité est limitée à cet endpoint, pas à tous les modèles Ollama.
Les autres fournisseurs conservent le dialogue standard et la reprise bornée
après un rejet reconnu. Si l’endpoint rejette aussi la continuation, l’erreur
remonte sans boucle de reprise supplémentaire. Les limites de tours, de temps
et de coût ne sont pas augmentées.
