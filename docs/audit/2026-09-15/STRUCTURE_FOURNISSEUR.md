# Clarification du fournisseur — première extraction

## Changement limité

Les reprises réseau et les délais sortent de `src/agent/provider.py` pour
rejoindre `src/agent/core/provider_transport.py`. Une seule implémentation est
utilisée ; les fonctions déplacées restent importables sous leurs anciens noms
privés depuis `provider.py`, via des alias, pas des copies ni un second chemin
d'exécution.

Cette extraction conserve les décisions existantes : mêmes codes HTTP,
mêmes classes d'erreurs, mêmes nombres de tentatives, mêmes délais et mêmes
exceptions finales. Le nom du logger de transport indique désormais le module
qui produit ces messages. Les événements structurés du journal ne changent pas.

## Où intervenir

| Responsabilité | Emplacement |
| --- | --- |
| Refaire la même requête après une erreur réseau/HTTP, respecter le délai | `core/provider_transport.py` |
| Autoriser une continuation du modèle ou verrouiller la clôture | `core/completion_policy.py` |
| Préparer la conversation, appeler le fournisseur et distribuer les appels d'outils | `provider.py` |
| Filtrer et conserver le diagnostic confidentiel | `core/provider_diagnostics.py`, appelé par `core/runner.py` |
| Vérifier une preuve ou attribuer un accès | `evidence/` et les contrôles des phases, jamais le transport |

Les deux types de reprise ne doivent pas être confondus :

- **Reprise réseau** : pas de réponse exploitable reçue ; renvoi de la même
  requête sans ajout de message ni exécution d'outil.
- **Continuation du modèle** : décision de poursuivre la conversation, bornée
  par les règles de phase et les budgets. Elle n'est pas déclenchée par le
  module de transport.

## Cas de la connexion UMONS refusée

Le test hors ligne simule le client SDK réel au-dessus d'un transport mémoire.
Avec cinq reprises configurées, il doit y avoir exactement six appels et cinq
attentes de 5, 10, 20, 40 et 80 secondes, simulées sans attente réelle. Le dernier
échec reste explicite. Aucun outil n'est exécuté et aucune consommation de
tokens n'est enregistrée. Avec ou sans diagnostic, la séquence reste identique.

Les tests couvrent aussi une reprise suivie d'un succès, une erreur HTTP non
réessayable, le rejet de conversation `no user query`, un délai déjà dépassé,
un délai insuffisant pour la prochaine attente et un observateur défaillant.

## Ce qui reste séparé

Cette étape ne répare pas le relais UMONS et ne vérifie pas sa disponibilité
avant le déploiement S1. Elle ne change ni le mode `full`, ni le modèle, ni les
budgets, ni les scores, ni les contrats de preuve. Aucun ancien run n'est réécrit.

Le découpage du collecteur d'événements encore présent dans `provider.py`, celui
des validateurs et la réduction des états globaux restent des étapes distinctes.
Un éventuel contrôle de disponibilité avant S1 devra lui aussi avoir son propre
contrat : joignabilité d'une API ne signifie pas réussite de la génération.

## Validation locale

- Comparaison des arbres syntaxiques des quatre fonctions déplacées : logique
  identique à celle du commit `1ea2c34`, après normalisation des noms et docstrings.
- 22 nouveaux tests de transport réussis, dont la panne simulée via le SDK réel.
- Suite complète sous Python 3.12 : **2 442 réussis, 1 ignoré, 3 avertissements
  de dépréciation**, aucun échec (157 secondes).
- `git diff --check` réussi. Aucun appel UMONS, scénario de laboratoire,
  changement de configuration serveur ou déploiement pour cette étape.

Les tests existants de délais et de reprise de conversation conservent leurs
assertions ; seul l'emplacement de l'horloge simulée suit le module extrait.
