# Objectif AsiaCCS 2027 : soumission LANCE

## Question et périmètre

Ce dossier fixe l'objectif de soumission du programme
[agent contre automatisation](../../research/2026-09-27-agent-vs-automation/README.md) :
**soumettre un papier à ACM AsiaCCS 2027 (round 2) au plus tard le
11 décembre 2026**, sur la question « sous quelles conditions un agent LLM
dépasse-t-il une automatisation à règles, à outils, preuves et budgets
identiques ? ».

C'est un dossier d'**objectifs de projet** (hors `research/`) : cible,
exigences de la conférence, contributions à prouver, critères de décision.
Il ne contient ni résultats ni copie de la proposition de recherche, qui
reste dans l'étude `research/` liée ci-dessous. L'avancement
opérationnel (runs prévus, exécutés, échoués, coûts) se suit dans le
[manifeste de campagne](../../benchmarks/experiments/policy-comparison/README.md),
qui reste la source de vérité de l'exécution.

## Statut

**Objectif retenu le 2026-10-12 ; suivi réconcilié le 2026-10-16, campagne incomplète.**
Le [registre des tentatives](../../benchmarks/experiments/policy-comparison/reconciliation-2026-10-16.json)
recense 15 tentatives de campagne, 8 de calibration et 13 inspections, dont six
ont créé un diagnostic isolé. Sous le gel actuel, huit tentatives appariées
couvrent sept des douze paires prévues : trois sont comparables et cinq
incomparables. La seconde tentative S1 r1, arrêtée à la limite de durée,
avait écrasé son premier résumé ; les deux résultats sont maintenant conservés.

Les six exports des trois paires S1 comparables sont retrouvés via les API
nato : 214 fichiers, 725 entrées de journal d'outils et concordance des 18
fichiers de métadonnées publiés initialement. Le recalcul confirme leur
comparabilité ; la revue humaine des preuves et des remises à zéro reste
ouverte. Le [journal détaillé](../../benchmarks/experiments/policy-comparison/pilot-2026-10-preflight.md#réconciliation-complète-du-16-octobre)
précise les références et les limites de l'export API. Aucun avantage général
du LLM n'est démontré.

## Dates

- Début de l'objectif : **2026-10-12**.
- Décision soumission / repli : à la condition écrite dans le plan (manuscrit
  relisible et artefact prêt), sans date interne.
- Soumission visée : **2026-12-11 (AoE)**, AsiaCCS 2027 round 2. C'est la seule
  contrainte externe ; elle n'ordonne pas les étapes.
- Conférence : 12-16 juillet 2027, Macao.
- Dernière mise à jour de ce dossier : **2026-10-21 10:30 (Europe/Brussels,
  UTC+02:00)**.

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

- [Audit de couverture des scénarios](audit-couverture.md) : matrice réelle du corpus (75 % de failles à signature, strate logique réduite à S15, edge cases absents) et verdict sur le set pilote (remplacer le contrôle sain fictif par S1h).
- [Plan de soumission](plan-soumission.md) : exigences AsiaCCS vérifiées,
  contributions candidates, expériences E1-E3, pistes bonus, rétroplanning,
  critères de décision et risques.
- Proposition scientifique :
  [PDF](../../research/2026-10-12-recentrage-corpus/proposition-conditions.pdf) ·
  [LaTeX](../../research/2026-10-12-recentrage-corpus/proposition-conditions.tex)
  (révision 2026-10-12 21:25, Europe/Brussels, UTC+02:00).
- Protocole et comparateurs :
  [protocol.md](../../research/2026-09-27-agent-vs-automation/protocol.md),
  [guide CLI D1/A1](../../docs/benchmark/agent-vs-automation-cli.md).
- Suivi d'exécution :
  [manifeste de campagne](../../benchmarks/experiments/policy-comparison/README.md).

## Avancement V2 au 2026-10-19

Le [plan V2 consolidé](../../research/2026-10-12-recentrage-corpus/README.md)
conserve 44 scénarios, 25 ensembles et 216 configurations candidates. Deux
[pilotes réels](../../docs/benchmark/agent-vs-automation-cli.md) sont qualifiés
sur leurs quatre bras script/Qwen, dans un périmètre local et borné :
`ssh_reference_live` le 15 octobre, puis
[`mqtt_reference_live`](../../docs/benchmark/agent-vs-automation-cli.md#qualification-mqtt-réelle-vérifiée-le-19-octobre-2026)
le 19 octobre (run `39239366068`, cas F0/F1, 120 fichiers et deux archives
vérifiés). Ces calibrations restent hors admission confirmatoire M-T.
**La prochaine réalisation V2 est `s_api_organisations`**, puis `s_mqtt_reprise`
et `s_cache_identites`. Le gel et l’alignement des métriques restent à établir
avant le nouveau test ; la poursuite du pilote historique ci-dessous constitue
un suivi distinct, conservé sans remplacer ses échecs.
Consolidation documentaire : **2026-10-19 (Europe/Brussels, UTC+02:00)**.

## Suite et points ouverts

1. Faire relire les preuves et précontrôles retrouvés, puis préparer un plan
   distinct pour la poursuite : cinq paires restent sans exécution sous ce
   gel (S15 r2–r3 et S1h r1–r3). `next-trial.txt` porte
   `blocked-new-freeze-required`. Les dépassements précédents restent dans
   le registre ; aucune reprise ne les remplace.
2. Calibrer le seuil delta sur le pilote, jamais après observation du test.
3. Décider selon les critères du plan, quand la condition de décision est
   remplie (manuscrit relisible, artefact prêt) : soumission AsiaCCS, ou repli
   workshop / version journal ultérieure.
4. Préparer tôt l'artefact anonymisé exigé par l'appendice Open Science.

## Point de reprise du 15 octobre 2026

Les sections suivantes conservent les étapes successives de la récupération.
Le statut courant est celui de la réconciliation en tête de ce document ;
les blocages réseau et pointeurs décrits ci-dessous sont des constats datés.

- Manifeste actif : [pilot-2026-10.json](../../benchmarks/experiments/policy-comparison/pilot-2026-10.json),
  et non `pilot.example.json`. Set : S1, S14, S15, S1h ; trois répétitions.
- Configuration gelée : `ollama-umons` / `qwen3.8:27b`, profil `full`,
  200 appels outil, 1 800 s par bras, 600 s par appareil en phase 3,
  plafond de 2 USD ; modèle et empreinte documentés dans le manifeste.
- Prochaine vérification : historique de `pilot-campaign.yml`, identité du
  checkout d'exécution, verrou du laboratoire et artefacts déjà conservés.
  Ne pas modifier `src/` pendant cette campagne gelée.
- Accès depuis cet environnement cloud : la requête HTTP vers nato renvoie
  `403 Domain forbidden` et la lecture de l'API GitHub Actions renvoie
  `Forbidden`. Aucun lancement ni déploiement effectué à cette reprise.
  Ces refus ne prouvent ni une panne de nato ni l'absence d'identifiants.

Le bilan local se recalcule avec la commande du guide de campagne en utilisant
le manifeste actif. Les coûts manquants restent inconnus, et non nuls.

## Reprise distante du 16 octobre 2026

La lecture de l'API GitHub fonctionne désormais. L'historique de
`pilot-campaign.yml` contient des jobs terminés avec succès pour les sept
paires suivantes (date d'exécution : 14 octobre) :

| Paire identifiée par l'artefact | Run GitHub Actions | Conclusion du workflow |
| --- | --- | --- |
| S1 r1 | [38570488357](https://github.com/Tanguyvans/LANCE/actions/runs/38570488357) | success |
| S1 r2 | [38575803864](https://github.com/Tanguyvans/LANCE/actions/runs/38575803864) | success |
| S1 r3 | [38581153999](https://github.com/Tanguyvans/LANCE/actions/runs/38581153999) | success |
| S14 r1 | [38611677976](https://github.com/Tanguyvans/LANCE/actions/runs/38611677976) | success |
| S14 r2 | [38616086219](https://github.com/Tanguyvans/LANCE/actions/runs/38616086219) | success |
| S14 r3 | [38621265302](https://github.com/Tanguyvans/LANCE/actions/runs/38621265302) | success |
| S15 r1 | [38626380879](https://github.com/Tanguyvans/LANCE/actions/runs/38626380879) | success |

Il s'agit d'un inventaire opérationnel : les noms des artefacts identifient
les essais, mais ni la complétude des bras ni leur comparabilité scientifique
n'ont été vérifiées ici. Des tentatives en échec ou annulées existent aussi
et restent à réconcilier sans les effacer. Aucun nouveau run n'est lancé.

**Action prioritaire :** télécharger les artefacts, vérifier les comparaisons,
les précontrôles, les identités de ressources et la disponibilité des preuves
complètes sur nato, puis réconcilier le manifeste avant de déterminer les
paires manquantes. Ne pas déduire « 7 paires admissibles » des 7 jobs en succès.

Le téléchargement est actuellement refusé sur les domaines Azure Blob utilisés
par GitHub Actions. Les dix domaines observés ont été ajoutés au brouillon
réseau en conservant `api.github.com` ; cette sauvegarde n'applique pas la
politique à la machine. Revoir et enregistrer ces changements dans les
paramètres, puis publier l'environnement pour permettre une nouvelle tentative.


### Accès rétabli et lecture des comparaisons

Après enregistrement des paramètres réseau, les artefacts Actions sont
accessibles. Le [journal du pilote](../../benchmarks/experiments/policy-comparison/pilot-2026-10-preflight.md#récupération-des-artefacts-actions--2026-10-16)
consigne leur récupération : les trois comparaisons S1 sont marquées comparables ;
S14 r1–r3 et S15 r1 sont incomparables avec dépassement du budget du bras LLM
(200 appels atteints). Ce statut ne valide pas encore les preuves ni les
précontrôles ; les archives complètes restent à récupérer sur nato.
Le manifeste local n'est pas rempli à partir de ces seuls extraits.
La priorité devient la réconciliation des tentatives et du plafond d'appels,
avant une relance ou un changement de gel.


### Diagnostic vérifié sur nato et suite du programme

Le [diagnostic hors ligne du 16 octobre](../../benchmarks/experiments/policy-comparison/pilot-2026-10-preflight.md#diagnostic-hors-ligne-sur-nato--2026-10-16)
a vérifié les cinq archives disponibles sur nato (483 fichiers). Le plafond de
200 appels laisse seulement un appel de vérification au LLM sur S15, après
199 en analyse. Les anciens échecs restent des résultats opérationnels du gel.
Les archives originales S1 ne sont pas dans ce magasin. La réconciliation
ultérieure retrouve les exports de runs par l'API, avec les limites précisées
dans le statut courant en tête du document.

Le `main` courant (`7911b7b` lors de la reprise) contient de nouvelles ressources
applicatives ; il n'est plus compatible avec le gel historique. La prochaine
campagne doit avoir un nouveau manifeste et une calibration explicite du budget
commun. Il faut d'abord qualifier un essai S15 et le contrôle sain, avant de
relancer une série de paires. Aucun nouveau gel ni audit n'est créé ici.
