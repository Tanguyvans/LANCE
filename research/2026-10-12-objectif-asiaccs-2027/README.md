# Objectif AsiaCCS 2027 : soumission LANCE

## Question et périmètre

Ce dossier fixe l'objectif de soumission du programme
[agent contre automatisation](../2026-09-27-agent-vs-automation/README.md) :
**soumettre un papier à ACM AsiaCCS 2027 (round 2) au plus tard le
11 décembre 2026**, sur la question « sous quelles conditions un agent LLM
dépasse-t-il une automatisation à règles, à outils, preuves et budgets
identiques ? ».

C'est un dossier de **pilotage scientifique** : cible, exigences de la
conférence, contributions à prouver, critères de décision. Il ne contient
ni résultats ni copie de la proposition de recherche. L'avancement
opérationnel (runs prévus, exécutés, échoués, coûts) se suit dans le
[manifeste de campagne](../../benchmarks/experiments/policy-comparison/README.md),
qui reste la source de vérité de l'exécution.

## Statut

**Objectif retenu le 2026-10-12 ; expérimentation à lancer.**
Aucun run de campagne n'a été exécuté pour cet objectif. La proposition
scientifique associée est un protocole proposé, sans résultat expérimental
nouveau.

## Dates

- Début de l'objectif : **2026-10-12**.
- Point de décision soumission / repli : **2026-11-16** (critères dans le plan).
- Soumission visée : **2026-12-11 (AoE)**, AsiaCCS 2027 round 2.
- Conférence : 12-16 juillet 2027, Macao.
- Dernière mise à jour de ce dossier : **2026-10-12**.

## Synthèse

- **Cible unique** : AsiaCCS 2027. EuroS&P 2027 (2 décembre 2026) est écarté
  comme cible simultanée : les deux conférences interdisent la soumission
  concurrente, et le papier serait encore en revue à EuroS&P au deadline
  AsiaCCS. EuroS&P reste une cible ultérieure pour une version élargie.
- **Contribution visée** : une carte mesurée des conditions d'écart entre
  politiques, pas une supériorité générale du modèle. Un écart nul partout,
  documenté proprement, reste un résultat utilisable mais change la forme
  du papier (voir critères de repli dans le plan).
- **Instrument déjà disponible** : pipeline six phases, quatre modes
  d'exécution (`lance`, `rules`, `vanilla`, `scripted`), comparateur apparié
  D1/A1, contrat de preuve strict-v3, 29 scénarios et 22 définitions de packs.
  Le travail restant est expérimental et rédactionnel, pas la construction
  d'un nouveau système.

## Documents

- [Plan de soumission](plan-soumission.md) : exigences AsiaCCS vérifiées,
  contributions candidates, expériences E1-E3, pistes bonus, rétroplanning,
  critères de décision et risques.
- Proposition scientifique :
  [PDF](../2026-09-27-agent-vs-automation/proposition-conditions.pdf) ·
  [LaTeX](../2026-09-27-agent-vs-automation/proposition-conditions.tex)
  (révision 2026-10-12 21:25, Europe/Brussels, UTC+02:00).
- Protocole et comparateurs :
  [protocol.md](../2026-09-27-agent-vs-automation/protocol.md),
  [guide CLI D1/A1](../../docs/benchmark/agent-vs-automation-cli.md).
- Suivi d'exécution :
  [manifeste de campagne](../../benchmarks/experiments/policy-comparison/README.md).

## Suite et points ouverts

1. Lancer le pilote D1/A1 (24 exécutions modélisées) et consigner chaque
   essai dans le manifeste de campagne.
2. Calibrer le seuil delta sur le pilote, jamais après observation du test.
3. Décider le 2026-11-16 selon les critères du plan : soumission AsiaCCS,
   ou repli workshop / version journal ultérieure.
4. Préparer tôt l'artefact anonymisé exigé par l'appendice Open Science.
