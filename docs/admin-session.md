# Session administrateur

Dans « Accès administrateur », saisir la clé puis cliquer sur **Se connecter
pour 8 h**. La session permet de lancer les runs et de gérer la configuration
après actualisation, sans ressaisir la clé. **Déconnexion** révoque la session.
Les clients API peuvent toujours utiliser `Authorization: Bearer`.

La clé saisie est effacée du formulaire après connexion. Seul un identifiant
aléatoire de session est placé dans un cookie HttpOnly, SameSite=Strict,
limité au chemin `/api`. Aucune clé n'est enregistrée dans localStorage ou
sessionStorage. La durée est fixe (8 heures), sans renouvellement silencieux.
Les mutations par cookie exigent un en-tête non simple et rejettent les origines
différentes ; CORS ne doit pas autoriser des sites externes avec credentials.

En HTTPS, le cookie est Secure. En HTTP, ce flag ne peut pas être activé :
le transport HTTP ne chiffre ni la clé ni la session. Réserver cet accès à un
réseau de confiance / tunnel chiffré (comme Tailscale) et préférer HTTPS.
Un proxy HTTPS doit transmettre le schéma correctement via une configuration
de proxy de confiance ; ne pas faire confiance aux en-têtes forwarded de tous.

Les sessions sont en mémoire, limitées à 256, partagées dans un processus.
Un redémarrage ou une rotation de la clé serveur invalide les sessions.
Ce mécanisme nécessite une seule instance de serveur ; plusieurs workers
nécessiteraient un stockage de sessions partagé. Une clé serveur absente
continue de bloquer les mutations. Ne pas exposer cette API sur Internet sans
protection réseau et limitation des tentatives d'authentification.
