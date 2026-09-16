# Rapport rédigé par sections

La phase 6 est commune aux profils full et compact. Elle ne demande plus au
modèle de résumer tous les résultats dans une seule réponse.

## Composition

1. Une fiche par hypothèse de phase 3, y compris les hypothèses indéterminées
   ou sans test. Le code y associe les tests et références de phase 4.
2. Des fiches d’intrusion séparées : accès corroborés par la projection des
   observations, puis couverture et limites. Un accès ne devient pas un pivot.
3. Une synthèse courte, produite en dernier à partir des compteurs, des statuts
   d’exécution et des limites structurées, sans renvoyer toutes les fiches.
4. Un assemblage déterministe avec les tableaux factuels existants. Aucun appel
   au modèle ne réécrit le rapport complet.

Les faits, identifiants, états enregistrés et références sont rendus par le code.
Le modèle fournit seulement un commentaire explicatif et des recommandations,
explicitement marqués comme non validés. Une référence attribuée à la bonne
hypothèse et à la bonne cible n’est pas encore une preuve de la propriété
annoncée : les exigences de preuve et l’évaluation du benchmark restent inchangées.
La phase 6 n’utilise pas la vérité terrain pour améliorer le score.

Les doublons d’identifiants, les tests orphelins et les sources absentes restent
visibles comme diagnostics ; ils ne sont pas silencieusement fusionnés ou ignorés.

## Échecs et reprise

Chaque fiche est enregistrée immédiatement. Une réponse tronquée, vide, en
erreur ou hors délai n’est pas publiée comme commentaire utilisable. Les faits
de cette fiche restent présents, avec la cause de rédaction incomplète, et les
autres fiches peuvent être rédigées. Le statut de la phase est alors `partial`.
Un arrêt ou un dépassement de budget conserve son statut propre ; une erreur
d’assemblage ou de validation finale reste un échec.

Lors d’une nouvelle invocation de la phase 6 dans le même dossier de run, seules
les fiches utilisables dont les sources, le prompt et le modèle sont identiques
sont réutilisées. Les fiches en échec ou modifiées sont régénérées ; la synthèse
est régénérée si ses compteurs ou limites changent. Cela ne relance aucun test
réseau et ne réécrit pas les livrables des phases précédentes. Ce mécanisme ne
constitue pas un bouton de reprise supplémentaire dans l’interface.

Les anciens runs ne sont pas migrés automatiquement. Une rédaction réussie ne
transforme pas un échec d’intrusion en succès et ne résout pas ses causes.

## Limites et consommation

- Appels séquentiels sans outils, un appel par fiche non réutilisable.
- Contexte limité à 24 000 octets par appel. Une fiche trop volumineuse conserve
  tous ses faits dans le rapport mais sa rédaction est signalée indisponible.
- Les extraits de résultats d’outils sont bornés et signalés comme extraits ; les
  références renvoient toujours au journal complet.
- Limite de sortie du profil conservée ; budget et tokens toujours comptabilisés.
- `LANCE_REPORT_SECTION_TIMEOUT` : 45 secondes par appel par défaut.
- `LANCE_LOCAL_MOE_REPORT_PHASE_TIMEOUT` : 600 secondes pour l’ensemble de la
  rédaction par défaut. Ce nom de configuration existant vaut pour les deux profils.

Le découpage augmente le nombre d’appels. Il ne garantit ni une baisse de coût
ni l’absence de troncature. Il localise les échecs et permet de réutiliser les
fiches déjà exploitables. Les délais peuvent être ajustés au fournisseur.

## Fichiers du run

| Fichier | Rôle |
| --- | --- |
| `06_report_sections.json` | Manifeste des fiches actives, états, causes, réutilisations. |
| `06_report_sections/<empreinte>.json` | Faits, commentaire ou brouillon rejeté et état de chaque fiche. |
| `06_report_cards.md` | Fiches d’audit et diagnostics assemblés. |
| `06_report_intrusion_cards.md` | Fiches d’intrusion assemblées. |
| `06_report_analysis.md` | Synthèse courte, seulement si sa génération est exploitable. |
| `06_report.md` | Rapport final déterministe. |

Les instantanés sont un cache local au run, pas un historique immuable de chaque
tentative. Les livrables et le journal d’outils originaux restent les sources.

## Vérification locale

```bash
python -m pytest -q tests/test_report_sections.py tests/test_report_review_regressions.py tests/test_report_completion_boundary.py tests/test_report_semantics_boundary.py
python -m pytest -q tests model_training/tests
```

Les tests de rédaction utilisent des fournisseurs simulés : ils vérifient les
frontières et les reprises, pas la qualité rédactionnelle réelle du modèle.
