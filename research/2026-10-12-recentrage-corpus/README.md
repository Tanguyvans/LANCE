# Recentrage conditionnel et structuration du corpus

**Cycle de vie : Actif** (créé le 2026-10-12).

## Question et périmètre

Sous quelles conditions mesurables un agent LLM dépasse-t-il une
automatisation à règles, et comment structurer le corpus de scénarios
pour le prouver ? Ce dossier reprend la question de l'étude
[agent contre automatisation](../2026-09-27-agent-vs-automation/README.md)
en la recentrant : écart conditionnel plutôt que duel global, grille de
couverture dérivée, edge cases déployables, sets pilote et campagne.

Cible de soumission associée (hors `research/`) :
[objectifs AsiaCCS 2027](../../objectifs/asiaccs-2027/README.md).

## Statut et dates

- Début de l'étude : **2026-10-12**.
- Statut : **protocole et propositions — aucun résultat expérimental nouveau.**
- Décision intermédiaire liée : **2026-11-16** (critères dans le dossier d'objectifs).

## Synthèse

- La question globale « le modèle bat-il les règles ? » est remplacée par
  une question conditionnelle falsifiable (hypothèses H0-H3, critère de
  décision unique), avec issues négatives publiables.
- Le corpus est bon en développement, faible en évaluation (75 % de
  failles à signature) : on le lit à travers une grille dérivée des
  vérités terrain, sans modifier catalogue ni vérités terrain.
- Quatre edge cases déployables sont retenus dans l'ordre (EC1 surface,
  EC2 leurres, EC3 chaînage cassable, EC4 autorisation presque valide) ;
  EC5 et EC6 sont différés après la soumission du 2026-12-11.

## Documents (dernières révisions : 2026-10-12, Europe/Brussels, UTC+02:00)

- **[Proposition de recentrage — PDF](proposition-conditions.pdf)** ·
  [LaTeX](proposition-conditions.tex) : question conditionnelle, six
  conditions, H0-H3, protocole apparié. Révision 2026-10-12 21:25.
- **[État des lieux plateforme — PDF](etat-des-lieux-plateforme.pdf)** ·
  [LaTeX](etat-des-lieux-plateforme.tex) : architecture à changer,
  objectifs mesurables, métriques comportementales. Révision 2026-10-12 22:11.
- **[Structuration du corpus — PDF](structuration-corpus.pdf)** ·
  [LaTeX](structuration-corpus.tex) : grille dérivée, edge cases,
  sets et séquençage en trois horizons. Révision 2026-10-12 23:05.

Chaque rapport a été relu par un relecteur indépendant (source + PDF) ;
les verdicts sont consignés dans les journaux de session du 2026-10-12.
Ces relectures ne constituent ni validation logicielle ni expérimentale.

## Suite et points ouverts

1. Script d'index dérivé et gel du manifeste pilote (S1, S14, S15, S1h).
2. Validation EC3/EC4 en exécution réelle.
3. Décision du 2026-11-16 selon les critères du dossier d'objectifs.
