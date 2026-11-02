# Rapport d'état au 2 novembre 2026 : vue d'ensemble d'abord

**Cycle de vie : Conclu — synthèse d'état** — rapport ouvert le **2026-11-02**.
C'est un état daté, pas une page de référence courante : il ne fait pas autorité
sur le comportement ultérieur du système.
Dernière révision : **2026-11-02 17:00 (Europe/Brussels, UTC+01:00)**.
Statut : **rapport documentaire ; aucune expérience nouvelle, aucun run nouveau.**

## Question et périmètre

Comment le système est-il construit, et où en est-il réellement ?

Cette révision ne change aucun fait par rapport au
[rapport du 30 octobre](../2026-10-30-architecture-protocoles-avancement/README.md) :
entre les deux dates, aucun commit n'a touché le dépôt (`git rev-list --count
9b63088..HEAD` vaut 0). Ce qui change est la lecture.

- **L'état vient d'abord.** Une page d'ouverture de six pages
  ([Where the project stands](partie-etat.tex)) donne la réponse entière avant
  la preuve : ce que fait un audit et qui décide à chaque étape, les trois
  politiques comparées, ce qui bloque la conclusion, et un tableau d'état
  renvoyant à chaque partie.
- **Trois schémas portent l'argument.**
  [Figure 1](partie-etat.tex) : les six phases, et la frontière de la liberté du
  modèle (seules les phases 2, 3 et 4 lui laissent un choix réel).
  [Figure 2](partie-etat.tex) : `scripted`, `rules` et le troisième bras
  `llm_on_evidence`, qui n'existe pas encore.
  [Figure 3](partie-etat.tex) : la chaîne scénario → famille → test de clôture →
  mesure, et la boucle du 30 octobre.
- **Le code sort du fil.** Les parties de preuve ouvrent chacune sur deux
  paragraphes (« In brief », « What the code enforces, and what it does not »),
  et les noms de fichiers, fonctions et commits sont regroupés dans un bloc
  « Where this lives » en fin de partie. Les descriptions d'implémentation les
  plus détaillées sont ramenées au niveau du comportement ; aucune n'est
  supprimée sans que son fait soit conservé.

Les cinq parties factuelles sont reprises du rapport précédent : architecture
([partie-architecture.tex](partie-architecture.tex)), protocoles
([partie-protocoles.tex](partie-protocoles.tex)), harnais et bac à sable
([partie-harnais.tex](partie-harnais.tex)), infrastructure
([partie-infrastructure.tex](partie-infrastructure.tex)) et benchmark
([partie-benchmark.tex](partie-benchmark.tex)). Le vocabulaire
([partie-glossaire.tex](partie-glossaire.tex)) et la conclusion
([partie-synthese.tex](partie-synthese.tex)) sont conservés, la conclusion
rebaptisée « What this report can say, and what it cannot ».

## Documents

- [Rapport PDF](etat-2026-11-02.pdf) : **26 pages, en anglais**, compilé à
  `2026-11-02 17:00` (Europe/Brussels), **sans erreur LaTeX, sans débordement
  ni renvoi cassé**, et vérifié page par page sur rendu image. Révision du
  2 novembre après deux relectures indépendantes : les quatorze affirmations
  fausses ou trop fortes ont été corrigées, les trois décisions et les quatre
  modes d'exécution sont revenus dans l'ouverture, et les notes de marge sont
  devenues un bloc « Where this lives » en fin de partie.
- Source : [etat-2026-11-02.tex](etat-2026-11-02.tex), compilée par
  `latexmk -pdf etat-2026-11-02.tex`.

## Synthèse

Le système est construit, instrumenté et documenté ; sa chaîne de preuve tient.
La question scientifique reste ouverte, et le rapport nouvellement l'énonce
d'emblée plutôt qu'en page 23 :

1. le modèle ne décide que là où il interprete réellement, et le score ne vient
   pas de lui ;
2. la comparaison à trois politiques n'a que deux bras sur trois ;
3. le blocage est l'absence de familles indépendantes, pas le calcul.

## Points encore ouverts

- Rédiger le troisième bras `llm_on_evidence`, ou déclarer que la comparaison
  mesure la vérification et non l'interprétation.
- Construire une famille qu'aucune règle d'une ligne ne franchit, en exécutant
  le test de clôture avant toute relecture.
- Trancher la condition d'ouverture D1+.
- Le détail ingénierie retiré des parties 4, 6 et 7 n'a pas de page de référence
  `docs/` dédiée : le prendre dans le
  [rapport du 30 octobre](../2026-10-30-architecture-protocoles-avancement/README.md)
  tant qu'une page n'est pas écrite.
