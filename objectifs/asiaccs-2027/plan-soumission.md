# Plan de soumission AsiaCCS 2027

Statut : plan retenu le 2026-10-12, **révisé le 2026-10-21 10:30
(Europe/Brussels, UTC+02:00)** pour recentrer le
travail sur le benchmark et la plateforme, et pour retirer les jalons internes
datés. À réviser à chaque étape vérifiée.
Les cases de résultats restent vides et marquées « à mesurer » tant que les
runs correspondants n'ont pas été exécutés et évalués.

## 1. Cible et exigences (vérifiées le 2026-10-12)

Source : [Call for Papers officiel](https://asiaccs2027.cityu.edu.mo/call-for-papers/index.html)
et [dates importantes](https://asiaccs2027.cityu.edu.mo/important-dates/index.html)
(consultés le 2026-10-12 ; re-vérifier avant soumission).

| Exigence | Valeur AsiaCCS 2027 | État LANCE |
| --- | --- | --- |
| Round visé | Round 2 ; calendrier de revue (rejet précoce, révision majeure, rebuttal, notification) publié par la conférence | À tenir |
| Conférence | 12-16 juillet 2027, Macao | — |
| Langue et format | Anglais, PDF, template ACM Sigconf double colonne | Les rapports d'avancement sont rédigés en anglais depuis le 30 octobre 2026 ; les notes de travail internes restent en français |
| Longueur | **12 pages max** hors bibliographie et annexes ; jusqu'à 10 pages supplémentaires de bibliographie/annexes, sans garantie de lecture | Squelette à créer |
| Revue | Double aveugle ; anonymat du papier et des artefacts | À appliquer (noms, affiliations, auto-références, dépôt) |
| Open Science | Appendice **obligatoire** (0,5 page max après les références) avec lien d'artefact anonymisé accessible pendant toute la revue ; absence = desk-reject possible | **Bloquant à préparer tôt** (voir §6) |
| Éthique | Appendice Ethical Considerations si applicable ; preuves au-delà d'une simple approbation institutionnelle | À rédiger : audit autorisé, laboratoire NATO, périmètre |
| Auteurs | ORCID de tous les auteurs via HotCRP avant le deadline ; liste d'auteurs figée après soumission (ordre modifiable avec accord) | À compléter |
| Double soumission | Interdite ; prépublication (arXiv) autorisée sans publicité large | Exclut EuroS&P 2027 simultané |
| Tracks pertinentes | Security Usability and Measurement ; Hardware, Side Channels and Cyber-Physical Systems ; AI Security | Choisir au dépôt selon l'angle final |

EuroS&P 2027 n'est **pas** un filet : les fenêtres de revue des deux
conférences se chevauchent. Si AsiaCCS échoue, les revues seront
réutilisées pour un workshop puis une version élargie (EuroS&P 2028 ou revue).

## 2. Contributions candidates (3 maximum)

Le pipeline et le laboratoire sont l'**instrument**, décrits brièvement ;
ils ne sont pas revendiqués comme contributions en eux-mêmes.

| # | Contribution candidate | Preuve exigée | Case du papier |
| --- | --- | --- | --- |
| C1 | Un benchmark IoT multi-équipements à familles tenues à l'écart (split par famille de packs, canaris, variantes déployées et vérifiées) | Corpus gelé + journal d'accès + contrôles négatifs propres | § Benchmark |
| C2 | Une carte mesurée des conditions d'écart, **par hypothèse** (V0 et H1-H6), à outils, preuves et budgets identiques (y compris carte vide) | Une famille par hypothèse, mesure recalculée depuis le journal ; intervalles à 95 % et correction de Holm **seulement** si deux familles indépendantes existent (condition nécessaire ; à n = 2 le bootstrap ne donne qu'un pseudo-IC, pas une revendication à 95 %) | § Résultats |
| C3 | Le coût de l'avantage éventuel : coût par vrai positif confirmé, temps, variance inter-graines, face aux règles | Mesures E3 sur les mêmes runs, grille de prix gelée | § Coût et limites |

Toute contribution sans sa preuve au moment de la rédaction sort du papier ou
passe en travail futur. Aucune réduction du travail humain n'est revendiquée
sans étude dédiée avec auditeurs.

**Ne pas confondre** la contribution C2 de ce tableau avec le « C2-scénario »
(scénario où la baseline échoue), instruit puis rejeté le 2026-10-21. Le
[C2-scénario est clos](../../research/2026-10-21-c2-couverture/README.md) ; la
contribution C2 reste ouverte.

## 3. Ce qui est à tester

Le benchmark est structuré par le
[registre V0 et H1-H6](../../research/2026-10-21-hypotheses-benchmark/README.md).
Les expériences E1-E3 restent la structure d'analyse.

Le critère de décision en vrais positifs confirmés strict-v3 ne s'applique
qu'aux hypothèses dont la mesure est un TP (H1, H2). Les autres ont leur propre
mesure, définie au registre (extraction correcte, champs interprétés, reprises,
conformité à une instruction injectée). Quand des intervalles sont possibles :
borne inférieure de l'intervalle apparié à 95 % supérieure au seuil delta
pré-enregistré, après correction de Holm. Deux familles indépendantes sont une
condition **nécessaire**, pas suffisante : à n = 2 le bootstrap ne produit qu'un
pseudo-intervalle. À défaut, le résultat reste **descriptif par hypothèse**,
sans revendication d'inférence.

| Exp. | Question | Bras et conditions | Mesures primaires | État |
| --- | --- | --- | --- | --- |
| E1 | Où l'écart apparaît-il ? (H1-H6) | D1 contre A1 ; chaînage, hétérogénéité de représentation, contrat public nouveau, sémantique constructeur, adaptabilité, contenu hostile | Mesure propre à chaque hypothèse, spécificité sur négatifs/leurres | Partiel : H2 mesurée le 2026-10-22 (gain absorbé par un bras convention), autres familles à mesurer |
| E2 | L'adaptation sert-elle ? (H5) | A0 (plan LLM figé) contre A1 (adaptatif), même préfixe ; contre-épreuve de budget | Reprises abouties, spécificité | À mesurer |
| E3 | Que coûte l'avantage ? (C3) | Mêmes runs que E1/E2 | Coût par TP confirmé, temps par jalon, variance inter-graines (≥3 graines) | À mesurer |

Contrôles obligatoires par campagne (proposition §6.4) : scénario sans
faille, preuves invalides à rejeter des deux côtés, leurre à motif connu
non exploitable, canari par instance. Un défaut d’intégrité du laboratoire,
de reset ou d’oracle invalide les essais
concernés selon une règle préalable. Un faux positif ou un échec de politique
sur un témoin correctement déployé reste un résultat valide, avec preuves et
coûts ; il ne justifie pas la suppression du lot.

Le pilote de développement existant (24 exécutions D1/A1,
`benchmarks/experiments/policy-comparison/`) sert à valider la mesure et
calibrer delta ; il ne produit pas le résultat du papier.

## 4. Pistes bonus (hors chemin critique)

N'entrent au papier que si E1-E3 sont bouclées et relues.

| Piste | Intérêt | Garde-fou |
| --- | --- | --- |
| Scénarios où l'automatisation est structurellement compliquée : chaînes à impasses générées, protocole documenté inconnu des règles, leurres plausibles | Renforce la contribution C2 (pas le C2-scénario, clos) là où l'écart est attendu | Déployés et vérifiés contre la vérité terrain ; jamais de règle volontairement affaiblie |
| Panel de modèles élargi, dont un **modèle MoE** (mélange d'experts, par ex. MoE local contre modèle dense local et modèle distant) | Axe coût/latence/qualité ; répond à la critique « un seul modèle testé » | Même gel (prompts, outils, budgets) ; le MoE est un bras de comparaison, pas un second sujet de papier |
| Extension aux phases 2 (reconnaissance) et 5 (intrusion) | L'adaptation peut y compter davantage | Seulement si le critère de poursuite de la proposition est satisfait en phases 3-4 |
| Génération procédurale complète de variantes | Puissance statistique, anti-contamination | Prouver d'abord une famille déployable ; une altération en aperçu seul invalide la strate |

## 5. Séquence de travail

Aucune étape n'est datée : une étape commence quand la précédente est vérifiée.
Aucune contrainte calendaire n'ordonne les travaux et ne justifie ni un
périmètre non validé, ni un résultat non mesuré.

| Étape | Critère de sortie |
| --- | --- |
| Gel du protocole (delta provisoire, conditions, grille de prix) | Manifeste de campagne rempli ; problèmes de mesure listés |
| Harnais paramétrable et familles H1-H3 | Chaque famille a sa fixture, son oracle, sa baseline déclarée, son évaluateur et ses tests |
| Familles tenues à l'écart et graines supplémentaires | Strates prêtes ou explicitement abandonnées |
| Analyse par hypothèse | Résultats par hypothèse et coût/TP ; intervalles seulement si deux familles indépendantes |
| Rédaction 12 pages ; artefact anonymisé ; appendices Open Science et éthique | Manuscrit relisible en entier |
| Relecture interne complète, anonymat, conformité CFP | Soumission prête |

Critères de soumission, écrits à l'avance :

- **Soumettre à AsiaCCS** si : au moins une condition prédite satisfait le
  critère de décision en TP confirmés, intégrité des témoins négatifs attestée
  et marges de faux positifs pré-enregistrées respectées, artefact anonymisé prêt.
- **Soumettre quand même mais repositionné** (papier benchmark/mesure à
  résultat négatif) si : écart nul partout mais mesure propre et puissance
  suffisante pour borner l'écart. La contribution devient C1 + borne.
- **Ne pas soumettre** si : aucun run évaluable, intégrité du laboratoire
  ou de l’oracle non rétablie,
  ou effet porté par une seule famille. Repli : workshop printemps 2027,
  puis campagne complète pour EuroS&P 2028 ou revue (TDSC, Computers &
  Security).

## 6. Risques et bloqueurs connus

| Risque | Conséquence | Parade |
| --- | --- | --- |
| Artefact non partageable (labo Proxmox/NATO) | Appendice Open Science faible, desk-reject ou revues négatives | Préparer tôt une version émulée minimale ou un extrait reproductible anonymisé ; justifier explicitement le reste |
| Runs séquentiels lents ou labo indisponible | Campagne incomplète au moment de la rédaction | Pilote dès que l'instrument est prêt ; périmètre réduit validé plutôt que campagne ambitieuse inachevée |
| Contamination familles dev/test | Écart non interprétable | Split par famille, canaris, gel documenté, journal d'accès |
| Portée qui gonfle (MoE, phases 2/5, génération complète) | Pilote jamais terminé | Bonus hors chemin critique (§4) ; gel après la variabilité mesurée, jamais avant |
| Un seul modèle évalué | **Levé** : deux modèles mesurés sur SSH et MQTT (dense et MoE) | Maintenir le panneau à au moins deux modèles par famille |
| Résultat trivial (le modèle perd ou gagne partout) | Papier affaibli si non anticipé | Déjà traité comme résultat publiable dans la proposition ; ne pas reformuler après coup |

## 7. État des lieux consolidé (2026-10-12)

Trois analyses parallèles (architecture, objectifs plateforme, métriques
comportementales) sont consolidées dans le rapport de recherche
[état des lieux plateforme (PDF)](../../research/2026-10-12-recentrage-corpus/etat-des-lieux-plateforme.pdf)
([LaTeX](../../research/2026-10-12-recentrage-corpus/etat-des-lieux-plateforme.tex)) :
six chantiers avant soumission — dont deux bloquants pour la preuve (split
par famille, inférence appariée IC 95 % + Holm) —, objectifs mesurables
C1-C3 et métriques au-delà du F1 (rejets de preuve, temps au premier vrai
positif, pentes sous bruit, variance inter-graines). Les efforts y sont des
estimations à confirmer sur le code ; aucun run n'y est rapporté.

## 8. Squelette du papier (à créer après le benchmark)

12 pages ACM : introduction et contributions (1), système et instrument (2),
benchmark et protocole (2), résultats E1-E3 (5), discussion et limites (1),
travail lié (1). Appendices : Open Science (obligatoire), Ethical
Considerations, détails de campagne. Chaque tableau de résultats renvoie
aux runs du manifeste de campagne ; aucune valeur n'est écrite à la main
sans identifiant de run.

## 9. Suivi V2 consolidé

Dernière révision : **2026-10-21 10:38 (Europe/Brussels, UTC+02:00)**. Cette section
est un état des lieux historique ; l'ordre courant est celui du
[registre d'hypothèses](../../research/2026-10-21-hypotheses-benchmark/README.md).

Le [plan V2](../../research/2026-10-12-recentrage-corpus/README.md) définit
44 scénarios, 25 ensembles et 216 configurations proposées, organisés par six
questions et cinq tâches mesurées. Cette sélection est distincte du pilote
historique S1/S14/S15/S1h et ne constitue pas 44 familles indépendantes.

La [qualification SSH native du 15 octobre](../../docs/benchmark/agent-vs-automation-cli.md#qualification-native-vérifiée-le-15-octobre-2026)
et la [qualification MQTT réelle du 19 octobre](../../docs/benchmark/agent-vs-automation-cli.md#qualification-mqtt-réelle-vérifiée-le-19-octobre-2026)
sont acquises dans leur périmètre borné : script et Qwen corrects sur les deux
postures, précontrôles, remise en état des ressources et preuves référencées.
Elles restent hors admission confirmatoire M-T et ne démontrent aucun avantage
général du LLM.

L'ordre courant n'est plus celui de cette section : il passe par la porte de
validité V0, puis le harnais paramétrable, puis les familles H2, H3, H4, H1 et
H5 du registre. `s_api_organisations` est exécuté et reste une étude de cas de
couverture, pas une famille de revendication. `s_mqtt_reprise` et
`s_cache_identites` figurent parmi les candidats rejetés de
[PISTES](../../objectifs/PISTES.md) et ne sont pas poursuivis.

Avant tout nouveau gel, adopter explicitement les mesures par tâche, leurs
dénominateurs, les marges FP, effectifs, budgets et analyses. Les TP strict-v3
des objectifs et les mesures V2 proposées doivent être alignés par amendement ;
aucun résultat historique n'est requalifié rétroactivement. Les dates et
critères historiques ci-dessus restent traçables ; la consolidation n'annonce
ni campagne exécutée ni gain.
