# Couverture, contexte et apport des LLM : lire la recherche

**Statut : diagnostic logiciel et protocole proposés, 29 septembre 2026.**
Trois analyses GPT ont été réalisées en parallèle, puis leurs principaux
mécanismes vérifiés localement. Aucun résultat de campagne ne démontre encore
un gain LLM. La base inspectée est `45c8dab892ecb4e5f513813387090e0cded1b85d`,
avec une réorganisation documentaire locale préexistante.

La synthèse est désormais le [rapport principal en PDF](report.pdf), dont
[report.tex](report.tex) est la source éditable. Il contient les constats des
trois axes, l'ordre de travail, les comparateurs, le protocole statistique,
les coûts et les décisions possibles, y compris si les règles suffisent.
Cette page sert à la navigation et ne maintient pas une seconde copie du rapport.

## Rapports et notes complémentaires

| Question | Rapport de lecture | Preuves et détails |
| --- | --- | --- |
| Que couvrent le corpus et les mesures ? | [PDF benchmark](../2026-09-29-benchmark-coverage/report.pdf) · [LaTeX](../2026-09-29-benchmark-coverage/report.tex) | [Analyse](../2026-09-29-benchmark-coverage/analysis.md) |
| Où les informations peuvent-elles disparaître ? | [PDF contexte](../2026-09-29-context-scalability/report.pdf) · [LaTeX](../2026-09-29-context-scalability/report.tex) | [Analyse](../2026-09-29-context-scalability/analysis.md) |
| Comment attribuer un bénéfice aux décisions LLM ? | [PDF principal](report.pdf) · [LaTeX](report.tex) | [Analyse](analysis.md), [protocole détaillé](protocol.md), [état de l'art](state-of-the-art.md) |

Le [journal de validation](validation.md) conserve commandes, environnement,
observations et limites. Les [scripts locaux](../../benchmarks/experiments/research-review/README.md)
reproduisent l'inventaire et les contre-exemples sans modèle ni cible réseau.
Le [suivi logiciel](implementation-plan.md) distingue ce qui existe de ce qui
reste à implémenter.

## Contre-revue

Une contrelecture GPT croisée a corrigé l'attribution des métriques, la portée
compact/full et les unités de comparaison. La contre-revue Muse demandée a été
préparée, mais **n'a pas été exécutée** : l'approbation automatique a rejeté
la transmission du résumé au service externe, et une autorisation explicite
a été demandée. Aucun avis n'est attribué à Muse.

Les questions, corrections et limites sont conservées dans les
[arbitrages de revue](adversarial-review.md). La convergence entre modèles
ne constitue pas une preuve expérimentale. Les bibliographies des rapports
précisent les dates/versions et les portions effectivement lues.
