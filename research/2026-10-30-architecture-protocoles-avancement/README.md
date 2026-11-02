# Architecture, protocoles et état d'avancement au 30 octobre 2026

> **Checkpoint remplacé par → [le checkpoint du 2 novembre 2026](../2026-11-02-rapport-vue-ensemble/README.md).**
> Conservé comme archive de son état, et comme source du détail d'implémentation
> (modules, chaînes de configuration, identifiants de commits) que le checkpoint
> suivant a déplacé hors du fil de lecture. Ne pas le modifier : corriger une
> erreur factuelle se fait, daté, dans le checkpoint courant.

**Cycle de vie : Remplacé — checkpoint** — rapport commencé le **2026-10-30**.
C'est un état daté, pas une page de référence courante : il ne fait pas autorité
sur le comportement ultérieur du système.
Dernière révision : **2026-10-30 10:15 (Europe/Brussels, UTC+01:00)**.
Statut : **rapport documentaire ; aucune expérience nouvelle, aucun run nouveau**.

## Question et périmètre

Comment le système est-il construit, et où en est-il réellement ? Le rapport
développe ce que le bilan du 15 octobre survolait : l'architecture du pipeline
phase par phase, les protocoles d'audit et leurs contrats de preuve, les harnais
et leur bac à sable, l'infrastructure d'exécution et le circuit de livraison, puis
l'état réel du benchmark.

Ce dossier est distinct de [celui du 15 octobre](../2026-10-15-bilan-projet/README.md),
qui reste l'archive du premier bilan et n'est plus modifié. Chaque révision de
fond ouvre désormais son propre dossier daté.

## Documents

- [Rapport PDF](report.pdf) : **25 pages, en anglais**, résumé
  exécutif, deux figures d'ensemble, cinq parties rédigées par des volets
  spécialisés et relues contre le code, puis une synthèse transverse.
- Source LaTeX et fragments éditables : [résumé et vue d'ensemble](partie-intro.tex),
  [architecture](partie-architecture.tex), [protocoles](partie-protocoles.tex),
  [harnais](partie-harnais.tex), [infrastructure](partie-infrastructure.tex),
  [benchmark](partie-benchmark.tex), [synthèse](partie-synthese.tex), assemblés
  par [report.tex](report.tex). Compilation :
  `latexmk -pdf report.tex`.
- ~~Version française `archive-fr/`~~ : **supprimée le 2026-11-02**, avec ses
  sources. Elle précédait la traduction en anglais, n'était plus maintenue, et
  aucun document du dépôt ne la citait comme référence. Le texte qu'elle
  portait reste lisible dans l'historique Git : `git show 2ff0f78:research/
  2026-10-30-architecture-protocoles-avancement/archive-fr/etat-2026-10-30-fr.tex`.

## Synthèse

Le système est construit, instrumenté et documenté. Sa chaîne de preuve est
sérieuse : oracle séparé, évaluateur qui recompte, journal qui ne pardonne pas une
preuve perdue, garde-fou qui déclare ses angles morts.

La question scientifique reste ouverte. Aucune supériorité du modèle n'est
établie, aucun intervalle de confiance n'est calculable, et le module d'inférence
produit en l'état l'apparence d'une mesure qu'il ne fournit pas.

Le rapport relève quatre contradictions entre volets, toutes vérifiées avant
d'être retenues :

1. le seuil du contrôle V0 n'est pas appliqué par la porte ;
2. le corpus H2 ne code pas le mode d'échec que le protocole décrit ;
3. le blocage de l'inférence vient de l'absence de familles indépendantes, non de
   la condition d'admission ;
4. la panne de routage du 29 octobre n'est consignée nulle part.

Une affirmation d'un rédacteur a été vérifiée puis écartée : la condition de
parité de budget refuse bien un budget absent.

## Points encore ouverts

- Corriger ou retirer le module d'inférence du chemin de décision.
- Trancher la condition d'ouverture qui rend plusieurs familles indécidables.
- Produire trois familles indépendantes, ou publier un résultat méthodologique
  borné en le déclarant tel.
- Consigner les pannes d'infrastructure : celle du 29 octobre n'existe dans aucun
  document et se reproduira au prochain redémarrage du routeur.
