# Gestion et scalabilité du contexte du pipeline

**Statut : exploration rouverte sur le pipeline actuel.** Nouvelle étude et
revue des constats : 29 septembre 2026. Le plan initial du rapport reste
archivé ; sa date d'origine n'est pas renseignée. Son classement à cette date
n'a pas validé ses anciennes estimations.

**Dernière révision du rapport : 2026-09-30 21:55
(Europe/Brussels, UTC+02:00).** Ajout de l'heure de révision ; les constats et
reproductions restent ceux de la revue du 29 septembre.

## Question et synthèse

Comment conserver les preuves, contradictions et décisions utiles tout en
bornant les requêtes des six phases ? La revue actuelle distingue sortie
tronquée avant archivage, croissance d'historique, projection sans récupération
et attribution des résultats au scanner ou au modèle. Cinq probes synthétiques
reproduisent des pertes ; leur effet sur les scores réels reste à mesurer.

Le rapport dispose déjà d'une rédaction par fiches et d'un assemblage
déterministe. Ce fonctionnement constitue le point de départ de l'étude.

## Documents et preuves

- **[Rapport de lecture — PDF](report.pdf)** : diagnostic C1–C8, résultats synthétiques et architecture/protocole proposés ; révision horodatée ci-dessus.
- **[Source LaTeX éditable](report.tex)** : schémas TikZ de l'état actuel et de la proposition, avec bibliographie intégrée.
- [Analyse actuelle et sources](analysis.md) : faits du code, hypothèses, architecture proposée et ablations.
- [Reproductions locales](../../benchmarks/experiments/research-review/README.md).
- [Synthèse transversale](../2026-09-27-agent-vs-automation/research-review.md) et [validation](../2026-09-27-agent-vs-automation/validation.md).

Le rapport suit la [structure scientifique classique](../README.md#structure-scientifique-classique) :
résumé, sommaire cliquable, méthode, constats, limites, conclusion et références.

Le [plan historique](plan.md) conserve les constats, estimations et propositions
de l'époque. Il indique que les corrections ont été livrées sous une autre forme.
Ses numéros de phase, noms de fonctions et commandes ne constituent pas une
description de l'architecture actuelle ni une liste de tâches à exécuter.

## Références actuelles et suite

- [Rédaction du rapport par sections](../../docs/architecture/report-writing.md).
- [Structure du pipeline](../../src/agent/phases/README.md).
- [Isolation des livrables](../../docs/architecture/run-artifacts.md).

Suite proposée : préserver le brut avant projection, instrumenter les entrées,
comparer une meilleure projection déterministe à des lectures ciblées, puis
tester l'effet sur les décisions et les preuves. Ni une fenêtre plus grande
ni le succès d'un test logiciel ne démontrent un meilleur audit.
