# Couverture et validité du benchmark

**Question :** quelles propriétés IoTChainBench définit-il, lesquelles sont
effectivement observées, et lesquelles ses mesures permettent-elles de valider ?
Périmètre : catalogue public, contrats, évaluateur et préparation expérimentale.

**Statut : exploration avec contre-exemples logiciels reproduits ; corrections
et expériences proposées.** Début et dernière mise à jour : 29 septembre 2026.
Aucune mesure de couverture réelle en laboratoire n'a été réalisée ici.

## Synthèse

Le catalogue contient 29 scénarios et 288 vulnérabilités attendues, mais aucun
scénario officiel entièrement sain. La diversité du test est concentrée sur
HTTP/SSH et des chaînes ; le nombre de scénarios ne mesure pas l'indépendance
des mécanismes ni leur fidélité au matériel IoT.

La revue reproduit un taux de tentative erroné dans un cas ambigu et deux
contre-exemples des validateurs HTTP. Elle identifie aussi une collision
d'attribution d'un contrôle négatif. Ces défauts ne démontrent pas leur fréquence
ni leur effet sur les scores de campagnes antérieures. Le F1 final, les preuves,
les tentatives et les contrôles doivent rester des dimensions distinctes.

## Documents et preuves

- **[Rapport de lecture — PDF](report.pdf)** : couverture, dénominateurs, contre-exemples et améliorations proposées ; version du 29 septembre 2026.
- **[Source LaTeX éditable](report.tex)** : figures TikZ, tableaux et bibliographie intégrés.
- [Analyse et sources primaires](analysis.md) : inventaire, défauts, limites et priorités.
- [Scripts locaux de reproduction](../../benchmarks/experiments/research-review/README.md).
- [Validation effectuée](../2026-09-27-agent-vs-automation/validation.md).
- [Synthèse des trois recherches](../2026-09-27-agent-vs-automation/research-review.md).

Le rapport suit la [structure scientifique classique](../README.md#structure-scientifique-classique) :
résumé, sommaire cliquable, méthode, constats, limites, conclusion et références.

## Suite et références

Priorité proposée : corriger les mesures et calibrer les validateurs sur des
contre-exemples, préparer des contrôles sains réels, puis élargir des familles
dont le déploiement et l'oracle sont vérifiables. La preuve causale de pivot
reste un chantier distinct. Les expériences terrain nécessitent une demande
explicite et ciblent nato/pve-nato.

Références actuelles : [scénarios](../../docs/benchmark/v1/scenarios.md),
[évaluation](../../docs/benchmark/v1/evaluation.md),
[catalogue des attaques](../../docs/benchmark/catalogue-attaques.md).
Les propositions de cette étude ne changent pas ces contrats.
