# LANCE et IoTChainBench : rapport d'ensemble du projet

**Cycle de vie : Conclu — synthèse d'état** — rapport commencé le **2026-10-15**.
C'est un état daté, pas une page de référence courante : il ne fait pas autorité
sur le comportement actuel du système.
Dernière révision : **2026-10-30 10:15 (Europe/Brussels, UTC+01:00)** —
nouveau rapport [architecture, protocoles et avancement](etat-2026-10-30.pdf),
19 pages, cinq volets relus contre le code ; le rapport du 15 octobre reste
conservé ci-dessous.
Statut : **bilan documentaire approfondi, résultats historiques attribués et travaux proposés identifiés**.

## Question et périmètre

Quels sont les objectifs du projet, comment ses composants fonctionnent-ils et
quel est leur état d'avancement ? Le rapport développe le périmètre disponible
dans le dépôt : graphe et connaissances, moteur d'agents, infrastructure réseau,
sécurité probatoire, application, spécialisation des modèles et évaluation.
Le programme NATO SPS G6259 fournit le contexte institutionnel ; les résultats
propres aux autres partenaires restent attribués à leurs documents de suivi.

Cette révision de fond remplace la première synthèse de onze pages du même jour.
Elle conserve les noms stables des livrables et le dossier d'origine. Six
rédacteurs spécialisés ont produit les parties, intégrées dans un rapport unique
et relues indépendamment.

La relecture pédagogique complète les notions au moment de leur emploi et
ajoute des exemples de fonctionnement et de calcul. Les renvois entre chapitres
ont été retirés ; chaque partie fournit les explications nécessaires à sa lecture.
Le sommaire, les références aux sources et les renvois aux figures ou tableaux
de la même partie sont conservés.

La dernière relecture adopte le regard d'une personne découvrant le projet.
Elle clarifie le rôle respectif de LANCE, du benchmark et de l'entraînement,
le déroulement complet d'un audit, les types d'entrée et le contenu du rapport
produit. Le résumé distingue les essais historiques déjà réalisés des
comparaisons et gains scientifiques restant à établir.

## Documents et parcours de lecture

### Rapport au 30 octobre 2026 : architecture, protocoles et avancement

Cette révision développe ce que le premier rapport survolait et couvre les
chantiers d'octobre.

- [Rapport PDF](etat-2026-10-30.pdf) : **21 pages**, **en anglais**, résumé
  exécutif et deux figures d'ensemble, cinq parties rédigées par des volets
  spécialisés et relues contre le code, puis une synthèse transverse.
- [Version française](archive-fr/etat-2026-10-30-fr.pdf) : conservée comme
  archive ; elle précède la traduction et n'est plus maintenue.
- Source LaTeX et fragments éditables : [résumé et vue d'ensemble](partie-intro.tex),
  [architecture](partie-architecture.tex), [protocoles](partie-protocoles.tex),
  [harnais](partie-harnais.tex), [infrastructure](partie-infrastructure.tex),
  [benchmark](partie-benchmark.tex), [synthèse](partie-synthese.tex), assemblés
  par [etat-2026-10-30.tex](etat-2026-10-30.tex). Compilation :
  `latexmk -pdf etat-2026-10-30.tex`.

La synthèse relève quatre contradictions entre volets, toutes vérifiées avant
d'être retenues : le seuil du contrôle V0 n'est pas appliqué par la porte, le
corpus H2 ne code pas le mode d'échec que le protocole décrit, le blocage de
l'inférence n'est pas la condition d'admission mais l'absence de familles
indépendantes, et la panne de routage du 29 octobre n'est consignée nulle part.

### Rapport du 15 octobre 2026

### Rapport au 30 octobre 2026 : architecture, protocoles et avancement

Cette révision de fond développe ce que le premier rapport survolait et couvre
les chantiers d'octobre.

- [Rapport PDF](etat-2026-10-30.pdf) : **19 pages**, cinq parties rédigées par
  des volets spécialisés, relues contre le code, puis synthèse transverse.
- [Source LaTeX](etat-2026-10-30.tex) et fragments éditables
  ([architecture](partie-architecture.tex), [protocoles](partie-protocoles.tex),
  [harnais](partie-harnais.tex), [infrastructure](partie-infrastructure.tex),
  [benchmark](partie-benchmark.tex), [synthèse](partie-synthese.tex)).
  Compilation : `latexmk -pdf etat-2026-10-30.tex`.

La synthèse relève quatre contradictions entre volets, toutes vérifiées avant
d'être retenues : le seuil du contrôle V0 n'est pas appliqué par la porte, le
corpus H2 ne code pas le mode d'échec que le protocole décrit, le blocage de
l'inférence n'est pas la condition d'admission mais l'absence de familles
indépendantes, et la panne de routage du 29 octobre n'est consignée nulle part.

### Rapport du 15 octobre 2026

- [Rapport PDF](report.pdf) : **44 pages**, huit figures éditables, dix tableaux,
  un glossaire et 136 références locales.
- [Source LaTeX éditable](report.tex) : document autonome, schémas TikZ et
  bibliographie intégrés ; source unique pour les révisions suivantes.
- [Manifeste des sources](sources-locales.json) : fichiers, empreintes et
  recomptages du catalogue et du pilote.
- [Validation et relectures](validation.md) : auteurs, regards indépendants,
  périmètre des inspections et limites.

| Partie | Contenu développé | Début dans le PDF |
| --- | --- | --- |
| Contexte et objectifs | Programme G6259, finalité, trajectoire historique et critères de réussite | [Page 4](report.pdf#page=4) |
| Méthode du bilan | Sources locales et sens des états d'avancement | [Page 6](report.pdf#page=6) |
| Architecture | Graphe NetworkX, risque, NVD/CPE, six phases, contextes, outils, profils, mémoire et coûts | [Page 7](report.pdf#page=7) |
| Réseaux et infrastructure | Proxmox, segmentation, familles IoT/OT, composition, déploiement, reset, verrou et CI | [Page 12](report.pdf#page=12) |
| Sécurité | Confiance, provenance, contrats par protocole, accès, pivots, frontières et administration | [Page 17](report.pdf#page=17) |
| Application | Parcours opérateur, moteurs, configuration, suivi SSE, historique, comparaison et exploitation | [Page 21](report.pdf#page=21) |
| Modèles et entraînement | QLoRA, quatre adaptateurs, corpus, masques, service HMoE, feedback et évaluations | [Page 25](report.pdf#page=25) |
| Benchmark | Métriques, comparateurs, parité, campagnes historiques, pilote, corpus V2 et SSH | [Page 30](report.pdf#page=30) |
| Synthèse | Maturité par volet, portefeuille de recherche et dépendances | [Page 36](report.pdf#page=36) |
| Priorités et conclusion | Critères de sortie, diffusion et suite du projet | [Page 37](report.pdf#page=37) |
| Glossaire | Repères de vocabulaire technique | [Page 44](report.pdf#page=44) |

## Synthèse de l'avancement

Le projet dispose d'un moteur instrumenté, de quatre modes applicatifs, d'un
graphe et d'outils de connaissance, d'un laboratoire décrit et automatisé, de
contrats de preuve, d'un benchmark de 29 scénarios et d'une chaîne de préparation,
d'entraînement et de service des adaptateurs. Des essais historiques et des
qualifications logicielles sont documentés.

La preuve d'un avantage du LLM ou de la spécialisation demeure une question
expérimentale. Le manifeste local du pilote de douze paires reste sans dossier
de bras renseigné. Le corpus V2 constitue une proposition détaillée, avec un
premier incrément SSH qualifié logiciellement. Les limites de simulation, de
reproduction, d'indépendance des tests et de preuve des pivots sont explicites.

## Études et références liées

- [Documentation de référence](../../docs/README.md).
- [Agent contre automatisation](../2026-09-27-agent-vs-automation/README.md).
- [Première campagne Qwen](../2026-10-05-benchmark-coverage/README.md).
- [Diagnostic de la campagne corrective](../2026-10-05-corrections-lance/README.md).
- [Recentrage et corpus V2](../2026-10-12-recentrage-corpus/README.md).
- [Scalabilité du contexte](../2026-09-29-context-scalability/README.md).
- [Méthodes d'audit](../2026-10-07-methodes-audit/README.md).
- [Spécialisation IoMT proposée](../2026-09-29-iomt/README.md).
- [Objectifs AsiaCCS 2027](../../objectifs/asiaccs-2027/README.md).

## Points ouverts et reproduction

Qualifier les environnements réels, relier chaque essai à sa configuration,
compléter les campagnes et dossiers de preuve, aligner les analyses avec les
mesures gelées, évaluer les adaptateurs et préparer un extrait reproductible.
La disponibilité du laboratoire et des services GPU n'a pas été contrôlée pour
la rédaction. Aucun nouvel audit, déploiement ou entraînement n'a été exécuté.

Compiler la source avec l'éditeur LaTeX intégré ou `latexmk -pdf`, placer les
intermédiaires hors de ce dossier, puis exporter le PDF correspondant. Toute
révision de fond exige de mettre à jour les dates et empreintes et de réinspecter
le rendu selon les [conventions de recherche](../README.md).
