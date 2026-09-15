# V1 — Évaluation et preuves

[Vue d’ensemble](README.md) · [Scénarios](scenarios.md) · [Exécution](execution.md)

Référence : `strict-v3.12 / evidence-v12`, schéma `funnel-v1`.
Le benchmark connaît les failles attendues. Un audit réel sans vérité terrain
ne permet pas de calculer exhaustivement les FN ou le rappel.

## 1. Trois étapes, trois populations

| Étape affichée | Source principale | Signification |
| --- | --- | --- |
| Failles potentielles | `03_vuln_analysis_raw.json`, candidats | Hypothèses proposées avant filtrage sémantique |
| Failles retenues | `03_vuln_analysis.json`, `vulnerabilities` | Hypothèses sélectionnées pour vérification |
| Confirmations déclarées | Tests admis de `04_exploitation.json` | Déclarations `CONFIRMED` de niveau ≥ 2, ensuite contrôlées par l’évaluateur |

La troisième population n’est pas extraite du texte libre du rapport et n’est
pas automatiquement constituée de preuves acceptées. Le filtrage prépare les
tests ; il ne confirme pas une faille. S’il conserve tout, les deux premières
colonnes ont les mêmes compteurs : ce n’est pas une seconde vérification.

Les populations statistiques sont dédupliquées selon une identité structurelle
conservatrice, pas selon les seuls identifiants du modèle. Des machines, services,
endpoints ou conditions distincts ne sont pas fusionnés arbitrairement. Chaque
étape est appariée séparément, un-à-un, à la vérité terrain. Le registre des
candidats absent n’est jamais reconstruit à partir des seuls survivants.

Pour `N` prédictions distinctes et `G` failles attendues :

- **VP** : correspondances valides ; à l’étape finale, une preuve acceptée est aussi exigée.
- **FP** : `N − VP` ; **FN** : `G − VP`.
- **Précision** : `VP / N`, indisponible si `N = 0`.
- **Rappel** : `VP / G`, indisponible si `G = 0`.
- **F1** : `2 × VP / (N + G)` si `G > 0`.

Le score principal d’audit est `100 × F1 final`. Un résultat final évaluable
mais vide obtient zéro sur un scénario positif ; un résultat indisponible reste
`null`, pas zéro. Les sévérités et anciens scores pondérés restent des diagnostics,
sans multiplicateur ajouté au F1 courant.

## 2. Une preuve doit soutenir la bonne déclaration

L’évaluateur relit les traces d’outils et vérifie leur attribution à la machine,
au service/port, au transport et à la propriété annoncée. Il applique les règles
sémantiques partagées avec le pipeline ; il ne fait pas confiance à son seul verdict.

Un `success: true`, un code de retour nul ou un rapport bien formé ne suffit pas.
Par exemple, une ouverture WebSocket ne démontre pas un accès MQTT anonyme ;
un message MQTT sans attribution fiable au topic annoncé ne démontre pas la
fuite alléguée. Une bannière de version ne démontre pas à elle seule une exploitation.

Les preuves sont comptées **acceptées**, **rejetées**, ou **manquantes/non
attribuables** pour les déclarations finales dédupliquées. Une trace acceptée
doit encore correspondre à une faille de référence pour compter comme VP.
Ces contrôles ne rejouent pas les sondes et ne constituent pas une preuve formelle
universelle : leur force dépend des critères propres à chaque outil.

### Pourquoi un FP peut avoir une preuve acceptée

Le diagnostic distingue les déclarations non créditées, sans modifier les FP :

| Catégorie technique | Lecture |
| --- | --- |
| `insufficient_evidence` | La déclaration n’a pas de preuve acceptée |
| `supported_outside_reference` | Une preuve est acceptée, mais sans correspondance dans la référence |
| `redundant_reference_claim` | La déclaration correspond à une faille déjà créditée ailleurs |
| `reference_assignment_conflict` | Une correspondance existe isolément, sans crédit dans l’association finale |
| `contradicted` | Catégorie réservée ; pas alimentée par une simple tentative échouée |

« Hors référence » justifie une revue de la déclaration, de sa portée et du
ground truth ; ce n’est ni une preuve automatique que le benchmark est faux,
ni une raison de transformer rétroactivement ce FP en VP.

## 3. Couverture et pertes

La couverture porte sur la **file effective de vérification**, par identifiant
canonique, alors que les scores portent sur les populations statistiques
dédupliquées. Ne pas supposer que leurs dénominateurs sont toujours identiques.

`Couverture = (hypothèses retenues − non testées) / hypothèses retenues`.
Les tentatives indéterminées ou en erreur restent donc incluses dans les tentatives.
**100 % testées ne signifie pas 100 % confirmées ni une exécution complète.**
Une population vide donne un taux indisponible.

- `confirmed` : déclaration admise au rapport, avant contrôle indépendant de sa preuve.
- `inconclusive` : résultat indéterminé, dont `FAILED` ou `NOT_EXPLOITABLE`.
- `error` : erreur de vérification, dont timeout.
- `not_tested` : absence de test ou test explicitement ignoré.
- `refuted` : réservé ; aucun vérificateur générique de preuve d’absence n’est implémenté.

Les identifiants ambigus ou plusieurs résultats concurrents ne gonflent pas la
couverture : leur état devient indéterminé. Les tests orphelins sont suivis à part.

Les pertes comparent les **ensembles de failles de référence appariées** :
failles réelles écartées au filtrage, puis failles retenues non confirmées.
Une faille jamais proposée contribue aux FN, mais pas aux pertes du filtrage.
Des correspondances nouvelles après normalisation sont signalées séparément ;
le code ne force pas le rappel à décroître entre les étapes.

## 4. Intrusion : une évaluation indépendante

Trois faits différents doivent rester séparés : service joignable, accès obtenu,
action exécutée **depuis cet accès** vers une autre machine.

Les accès affichés comme corroborés sont dérivés des traces Phase 5 de l’exécuteur
et des règles d’accès, avec cible et référence de preuve. Les listes et chaînes
écrites par le modèle restent des déclarations. Un accès applicatif ne prouve
pas nécessairement un shell, des privilèges administrateur ou une compromission totale.

L’évaluation compare les cibles tentées et compromises aux cibles attendues.
Un chemin attendu exige sa séquence, son accès final et ses transitions prouvées.
Un chemin direct peut être validé sans saut intermédiaire. Les chaînes déclarées
et plusieurs connexions directes ne démontrent pas un chemin multi-hop.

**Limite actuelle : aucune provenance causale de transition réseau n’est produite.**
Les tentatives/succès/taux de pivot restent indisponibles (`null`). La projection
d’observations expose des transitions vides avec `transition_evidence_available=false`.
Zéro transition vérifiée signifie aucune transition prouvée, pas zéro réussite
sur une population connue de tentatives. Plusieurs actions sur une API ne font
pas plusieurs sauts réseau. Aucun score global ne combine intrusion et F1 d’audit.

## 5. Contrôles, agrégation et comparabilité

Pour un contrôle sans faille attendue, la spécificité au niveau du scénario vaut
1 si le résultat final évaluable ne contient aucun FP, sinon 0. Elle exige une
analyse Phase 3 complète, sans appareil en échec, couvrant les appareils annoncés,
ainsi que des confirmations finales évaluables. Sinon le score reste indisponible.
Cela ne garantit pas la découverte de toutes les machines présentes.

Une préparation de laboratoire explicitement invalide/incomplète rend le score
indisponible : ce n’est pas un ensemble de FN imputables à l’agent. Pour les anciens
runs sans attestation de préparation, son absence est signalée ; elle n’atteste
pas que toutes les propriétés du ground truth ont été vérifiées sur le terrain.

Les répétitions sont moyennées au sein d’un scénario, puis les scénarios ont le
même poids **dans leur groupe**. Un lot mixte conserve des scores séparés dans
`per_split`, pas une moyenne dev/test. Les compteurs agrégés de l’entonnoir sont
des moyennes, à distinguer des totaux de consommation et des nombres d’essais.

Les contrats incompatibles et données manquantes restent signalés, sans invention
de zéros. Les anciens résultats restent consultables sans être réétiquetés pour
obtenir le score courant. Le statut d’exécution est une autre dimension :
[un bon F1 ne garantit pas un run réussi](execution.md#statut-et-score-sont-indépendants).

## Sources du code

- [Entonnoir](../../../src/benchmark/funnel.py) et [évaluateur](../../../src/benchmark/evaluator.py).
- [Diagnostics des déclarations](../../../src/benchmark/claim_diagnostics.py).
- [Admission au rapport](../../../src/agent/report_evidence.py) et [preuves partagées](../../../src/agent/exploit_evidence.py).
- [Observations d’intrusion](../../../src/agent/phases/intrusion/observations.py).
- [Agrégation des lots](../../../src/benchmark/aggregate.py).
