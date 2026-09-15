# Livrable d'intrusion — validation structurelle, étape 2

Cette étape remplace l'acceptation de n'importe quel JSON pour les soumissions
du modèle par le validateur `json_intrusion`. Elle ne change ni le modèle,
ni les budgets, ni les reprises fournisseur, ni le verrou de finalisation.

## Ce qui est accepté

Une soumission contient les quatre sections du prompt : `summary`,
`credential_pool`, `compromised_devices` et `chains`. Leurs champs sont typés,
les compteurs sont des entiers non négatifs et les identifiants ne sont pas
dupliqués. Les nombres d'accès déclarés et de transitions doivent être cohérents
avec les listes. Les identifiants ou contenus sensibles ne sont pas recopiés
dans les messages d'erreur du validateur.

Zéro accès reste un résultat possible : des tableaux vides et des compteurs
cohérents sont valides. Un accès direct peut être décrit par une chaîne d'un
seul nœud, avec zéro transition. `total_hops` conserve la convention de la
synthèse existante : somme de `max(0, nombre_de_nœuds - 1)` sur les chaînes.
Ce compteur reste déclaratif ; il ne prouve pas un pivot réseau.

## Ce qui est refusé

Un objet vide, un tableau à la racine, `null`, un scalaire, des sections
manquantes, des types incorrects ou une déclaration explicitement incomplète
ne peuvent pas être promus comme un nouveau livrable final valide.

La transaction conserve la tentative rejetée et son erreur, puis permet au
modèle de réparer son JSON dans les limites déjà existantes. Un ancien fichier
valide ne remplace pas une nouvelle soumission acceptée dans l'exécution.
Les reçus de tentative indiquent désormais le nom du validateur utilisé.

## Ce que cette validation ne démontre pas

Une structure valide n'est pas une preuve de faille, d'accès ou de pivot.
L'attribution des observations aux machines et services ainsi que les scores
d'audit et d'intrusion restent du ressort des contrôles de preuve existants.
Cette étape n'ajoute pas de nouvelles actions réseau, ne force pas une réussite
et ne vérifie pas la vérité terrain à partir des déclarations du modèle.

La branche compact locale conserve son outil de complétion fondé sur le journal
d'actions : elle ne soumet pas ce JSON par `save_deliverable`. Son contrat de
complétion et les exigences de preuve ne sont pas remplacés par ce contrôle
structurel. Aucun profil supplémentaire ni second pipeline n'est ajouté.

Les anciens runs ne sont ni réécrits ni réévalués automatiquement. Un reçu ancien
sans champ `validator` ne doit pas être présenté comme validé par ce nouveau
contrat. Les versions des métriques restent inchangées, car leurs formules et
leurs règles de preuve ne changent pas.

La correction du passage prématuré en finalisation et celle des reprises de
contexte restent des étapes ultérieures.

## Validation avant publication — 15 septembre 2026

- Tests ciblés de structure, transaction, registre et profils d'intrusion :
  108 réussis.
- Suite complète sous Python 3.12 : 2 339 réussis, 4 ignorés et un échec
  d'environnement (le bac à sable interdit le serveur RPC local d'Ansible).
  Ce test Ansible, constitué uniquement de faits et d'assertions sur localhost,
  a été relancé avec les permissions nécessaires : 1 réussi. Aucun échec
  fonctionnel non résolu dans les tests exécutés.
- Validation des 31 vérités terrain et `git diff --check` réussis.
- Aucun essai d'intrusion sur le laboratoire n'a été lancé pour cette validation.
