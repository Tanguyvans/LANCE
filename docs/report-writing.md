# Rapport rédigé par sections

La phase 6 est commune aux profils full et compact. Elle ne demande plus au
modèle de résumer tous les résultats dans une seule réponse.
L’ancien constructeur de contexte global et la classe compacte vide ont été
retirés. Le rendu reconstruit toujours le rapport à partir des faits ; il ne
fusionne plus un ancien rapport rédigé par le modèle avec des tableaux.
La lecture des rapports historiques par le tableau de bord reste disponible.

## Composition

1. Une fiche par hypothèse de phase 3, y compris les hypothèses indéterminées
   ou sans test. Le code y associe les tests et références de phase 4.
2. Des fiches d’intrusion séparées : accès corroborés par la projection des
   observations, puis couverture et limites. Un accès ne devient pas un pivot.
3. Une synthèse courte, calculée par le code en dernier à partir des compteurs,
   statuts d’exécution et limites structurées, sans appel au modèle. Elle ne peut
   inventer une disparition de références ni transformer une donnée inconnue
   en échec ou en absence de faille. Les confirmations enregistrées ne sont
   pas présentées comme des VP du benchmark.
4. Un assemblage déterministe avec les tableaux factuels existants. Aucun appel
   au modèle ne réécrit le rapport complet.

Les faits, identifiants, états enregistrés et références sont rendus par le code.
Pour les fiches, le modèle fournit seulement un commentaire explicatif et des recommandations,
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
Si un arrêt explicite et un dépassement de budget surviennent ensemble, la
phase termine avec `stopped` dans ses métadonnées et son événement de fin.
`phase6_budget_exceeded` conserve séparément le dépassement observé ; aucune
nouvelle génération n'est lancée.

Une section tronquée (`finish_reason=length`) bénéficie d'une seule nouvelle
tentative, depuis les mêmes faits et sans réinjecter le brouillon incomplet.
Le plafond de sortie est doublé (au plus 8 192 tokens pour cette reprise, sans
réduire un plafond initial supérieur). Les deux tentatives sont conservées dans
l'instantané de la fiche. Les autres causes ne déclenchent pas cette reprise.
Les arrêts, le budget financier et le délai global restent prioritaires.

Pour les fournisseurs enregistrés sous `ollama` ou `ollama-*`, seule la rédaction
de phase 6 demande `reasoning_effort=none`, selon le
[contrat Ollama](https://docs.ollama.com/api/openai-compatibility).
Le raisonnement des phases d'analyse, de vérification et d'intrusion reste
inchangé, tout comme le profil full/compact. Aucun paramètre supplémentaire
n'est imposé aux autres fournisseurs. Un serveur incompatible reste en erreur :
la réponse n'est pas promue artificiellement et le réglage n'est pas ignoré en silence.

Lors d’une nouvelle invocation de la phase 6 dans le même dossier de run, seules
les fiches utilisables dont les sources, le prompt et le modèle sont identiques
sont réutilisées. Les fiches en échec ou modifiées sont régénérées ; la synthèse
est régénérée si ses compteurs ou limites changent. Cela ne relance aucun test
réseau et ne réécrit pas les livrables des phases précédentes. Ce mécanisme ne
constitue pas un bouton de reprise supplémentaire dans l’interface.

Les anciens runs ne sont pas migrés automatiquement. Une rédaction réussie ne
transforme pas un échec d’intrusion en succès et ne résout pas ses causes.

## Limites et consommation

- Appels séquentiels sans outils, jusqu'à deux générations par fiche non
  réutilisable, la seconde uniquement après troncature. Les reprises de transport
  du fournisseur restent distinctes et bornées par le délai de l'appel.
- Contexte limité à 24 000 octets par appel. Une fiche trop volumineuse conserve
  tous ses faits dans le rapport mais sa rédaction est signalée indisponible.
- Les extraits de résultats d’outils sont bornés et signalés comme extraits ; les
  références renvoient toujours au journal complet.
- Limite de sortie du profil conservée pour la première tentative ; reprise
  bornée à un plafond supérieur. Toutes les consommations retournées par le
  fournisseur sont comptabilisées, y compris celles des brouillons rejetés.
- Chaque tentative conserve sa cause, son plafond de tokens, sa durée et les
  compteurs de tokens disponibles. Le nombre de caractères de raisonnement et
  de réponse visible aide au diagnostic ; le texte du raisonnement n'est pas
  archivé. Un compteur absent reste inconnu, pas zéro.
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
| `06_report_analysis.md` | Synthèse factuelle calculée par le pipeline ; inconnues et rédaction partielle explicites. |
| `06_report.md` | Rapport final déterministe. |

Les instantanés conservent les tentatives de la dernière génération de leur
fiche ; une nouvelle invocation peut remplacer un instantané en échec. Ce n'est
pas un historique immuable. Le cache tient compte des réglages de génération.
Les livrables et le journal d’outils originaux restent les sources.

## Vérification locale

```bash
python -m pytest -q tests/test_report_sections.py tests/test_report_review_regressions.py tests/test_report_completion_boundary.py tests/test_report_semantics_boundary.py
python -m pytest -q tests model_training/tests
```

Les tests de rédaction utilisent des fournisseurs simulés : ils vérifient les
frontières et les reprises, pas la qualité rédactionnelle réelle du modèle.

Essai réel ciblé du 16 septembre 2026 : les neuf sections tronquées du run
`2026-09-16_154821` ont été régénérées en mémoire avec `qwen3.8:27b` sur
`ollama-umons`, `reasoning_effort=none` et 2 048 tokens. Les neuf appels se sont
terminés avec `finish_reason=stop` et ont passé les contrôles de rédaction dès
la première tentative. Aucun outil ni scénario n'a été relancé, aucun fichier
du run historique n'a été remplacé. Cet essai n'est pas une validation d'un
nouveau run S1 complet ni une garantie de qualité rédactionnelle.
