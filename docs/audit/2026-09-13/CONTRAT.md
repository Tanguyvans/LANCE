# Contrat strict-v3.11 / evidence-v11

Corrections vérifiables hors ligne ; aucun résultat historique n'est modifié.
Les profils full et compact partagent ces règles.

1. SSH : les lignes d'algorithmes observés sont comparées à la politique finie
   `ssh-crypto-policy-v1`. Les annotations génériques, les courbes NIST et
   HMAC-SHA1 seul ne suffisent pas. La preuve indique les algorithmes concernés
   et ne prétend démontrer ni déchiffrement, ni exécution, ni compromission.
   Hôte, service, port et sortie effective de l'outil restent obligatoires.
2. Déduplication : seule une identité structurelle exacte peut compléter des
   métadonnées produit/version manquantes, avec une unique correspondance
   compatible. Une métadonnée absente ne relie jamais deux versions en conflit.
   IDs sources et références sont conservés. Les preuves des déclarations sont
   validées avant la déduplication statistique, sans assemblage opportuniste.
   La couverture utilise la population réellement soumise à vérification.
3. Diagnostic : chaque déclaration finale non créditée est expliquée comme
   preuve insuffisante, constat étayé hors référentiel, autre déclaration du même
   attendu ou conflit d'appariement. Les doublons regroupés sont présentés à
   part. Aucun bonus VP n'est ajouté. Un échec ne constitue pas une contradiction ;
   cette catégorie reste à zéro en l'absence d'un validateur de contre-preuve.
4. Préparation : l'injection nginx doit explicitement exposer sa version et le
   contrôle doit vérifier la réponse HTTP, pas seulement la configuration.
   Les contrôles de rôle doivent exiger des résultats positifs pour toute leur
   population attendue. Le contrôleur enregistre les étapes deploy/inject/verify.
   Un état invalide, en attente, d'un autre scénario ou d'un contrat inconnu rend
   l'entonnoir et son score officiel indisponibles, sans inventer des FN.

## Limites de validation

Le préflight ne certifie **pas toutes les propriétés de vérité terrain** de tous
les scénarios. Son champ `all_ground_truth_properties_verified` reste faux.
L'absence de métadonnées de préparation n'est pas réinterprétée comme un succès :
elle est affichée comme non documentée. Les contrôles historiques compatibles
restent évaluables avec cette réserve ; aucune vérité terrain n'est réécrite
pour améliorer un score. Les anciens contrats sont distingués des nouveaux.

Les nouveaux contrôles doivent encore être essayés sur le mini-PC, après revue
et publication explicitement autorisées. Les tests locaux n'attestent pas de
l'état actuel du laboratoire.
