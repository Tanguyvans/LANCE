# Session administrateur

Le bandeau de connexion administrateur a été supprimé du tableau de bord.
Les lancements de runs et de batches sont accessibles sans clé ni session.

L’API de session reste disponible pour les clients : `POST /api/admin/session`
avec `Authorization: Bearer <LANCE_ADMIN_TOKEN>` et `X-Lance-Admin-Session: 1`
crée une session ; `DELETE /api/admin/session` la révoque. Les autres actions
administratives restent protégées.

Un identifiant aléatoire de session est placé dans un cookie HttpOnly,
SameSite=Strict, limité au chemin `/api`. La durée est fixe (8 heures), sans
renouvellement silencieux. Les mutations par cookie exigent l’en-tête
`X-Lance-Admin-Session: 1` et rejettent les origines différentes.

En HTTPS, le cookie est Secure. En HTTP, ce flag ne peut pas être activé :
le transport HTTP ne chiffre ni la clé ni la session. Réserver cet accès à un
réseau de confiance / tunnel chiffré (comme Tailscale) et préférer HTTPS.
Un proxy HTTPS doit transmettre le schéma correctement via une configuration
de proxy de confiance ; ne pas faire confiance aux en-têtes forwarded de tous.

Les sessions sont en mémoire, limitées à 256, partagées dans un processus.
Un redémarrage ou une rotation de la clé serveur invalide les sessions.
Ce mécanisme nécessite une seule instance de serveur ; plusieurs workers
nécessiteraient un stockage de sessions partagé. Une clé serveur absente
continue de bloquer les mutations administratives, mais pas les lancements. Ne pas exposer cette API sur Internet sans
protection réseau et limitation des tentatives d'authentification.
