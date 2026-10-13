# Plan de soumission AsiaCCS 2027

Statut : plan retenu le 2026-10-12, à réviser à chaque jalon.
Les cases de résultats restent vides et marquées « à mesurer » tant que les
runs correspondants n'ont pas été exécutés et évalués.

## 1. Cible et exigences (vérifiées le 2026-10-12)

Source : [Call for Papers officiel](https://asiaccs2027.cityu.edu.mo/call-for-papers/index.html)
et [dates importantes](https://asiaccs2027.cityu.edu.mo/important-dates/index.html)
(consultés le 2026-10-12 ; re-vérifier avant soumission).

| Exigence | Valeur AsiaCCS 2027 | État LANCE |
| --- | --- | --- |
| Round visé | Round 2, soumission **2026-12-11 (AoE)** ; rejet précoce 2027-02-05 ; révision majeure 2027-02-12 ; rebuttal 8-12 mars 2027 ; notification 2027-03-31 | À tenir |
| Conférence | 12-16 juillet 2027, Macao | — |
| Langue et format | Anglais, PDF, template ACM Sigconf double colonne | À produire (les documents internes restent en français) |
| Longueur | **12 pages max** hors bibliographie et annexes ; jusqu'à 10 pages supplémentaires de bibliographie/annexes, sans garantie de lecture | Squelette à créer |
| Revue | Double aveugle ; anonymat du papier et des artefacts | À appliquer (noms, affiliations, auto-références, dépôt) |
| Open Science | Appendice **obligatoire** (0,5 page max après les références) avec lien d'artefact anonymisé accessible pendant toute la revue ; absence = desk-reject possible | **Bloquant à préparer tôt** (voir §6) |
| Éthique | Appendice Ethical Considerations si applicable ; preuves au-delà d'une simple approbation institutionnelle | À rédiger : audit autorisé, laboratoire NATO, périmètre |
| Auteurs | ORCID de tous les auteurs via HotCRP avant le deadline ; liste d'auteurs figée après soumission (ordre modifiable avec accord) | À compléter |
| Double soumission | Interdite ; prépublication (arXiv) autorisée sans publicité large | Exclut EuroS&P 2027 simultané |
| Tracks pertinentes | Security Usability and Measurement ; Hardware, Side Channels and Cyber-Physical Systems ; AI Security | Choisir au dépôt selon l'angle final |

EuroS&P 2027 (soumission 2026-12-02) n'est **pas** un filet : le papier y
serait encore en revue le 2026-12-11. Si AsiaCCS échoue, les revues seront
réutilisées pour un workshop puis une version élargie (EuroS&P 2028 ou revue).

## 2. Contributions candidates (3 maximum)

Le pipeline et le laboratoire sont l'**instrument**, décrits brièvement ;
ils ne sont pas revendiqués comme contributions en eux-mêmes.

| # | Contribution candidate | Preuve exigée | Case du papier |
| --- | --- | --- | --- |
| C1 | Un benchmark IoT multi-équipements à familles tenues à l'écart (split par famille de packs, canaris, variantes déployées et vérifiées) | Corpus gelé + journal d'accès + contrôles négatifs propres | § Benchmark |
| C2 | Une carte mesurée des conditions d'écart A1-D1 à outils, preuves strict-v3 et budgets identiques (y compris carte vide) | Campagne appariée E1, intervalles à 95 %, correction Holm, résultats par famille | § Résultats |
| C3 | Le coût de l'avantage éventuel : coût par vrai positif confirmé, temps, variance inter-graines, face aux règles | Mesures E3 sur les mêmes runs, grille de prix gelée | § Coût et limites |

Toute contribution sans sa preuve au 2026-11-16 sort du papier ou passe en
travail futur. Aucune réduction du travail humain n'est revendiquée sans
étude dédiée avec auditeurs.

## 3. Ce qui est à tester

Reprise des hypothèses H0-H3 de la
[proposition](../../research/2026-10-12-recentrage-corpus/proposition-conditions.tex).
Critère de décision unique : borne inférieure de l'intervalle de confiance
apparié à 95 % de l'écart (delta A1-D1 en vrais positifs confirmés strict-v3)
supérieure au seuil delta pré-enregistré, après correction de Holm.

| Exp. | Question | Bras et conditions | Mesures primaires | État |
| --- | --- | --- | --- | --- |
| E1 | Où l'écart apparaît-il ? (H0/H1) | D1 contre A1 ; nouveauté de famille, variation de surface, bruit/leurres, chaînage, failles logiques, protocole inconnu | TP confirmés, spécificité sur négatifs/leurres, jalons | À mesurer |
| E2 | L'adaptation sert-elle ? (H2) | A0 (plan LLM figé) contre A1 (adaptatif), même préfixe ; pentes par bras sous bruit croissant | TP confirmés par niveau de bruit, spécificité | À mesurer |
| E3 | Que coûte l'avantage ? (H3) | Mêmes runs que E1/E2 | Coût par TP confirmé, temps par jalon, variance inter-graines (≥3 graines) | À mesurer |

Contrôles obligatoires par campagne (proposition §6.4) : scénario sans
faille, preuves invalides à rejeter des deux côtés, leurre à motif connu
non exploitable, canari par instance. Un lot qui échoue à un contrôle est
invalidé, pas interprété.

Le pilote de développement existant (24 exécutions D1/A1,
`benchmarks/experiments/policy-comparison/`) sert à valider la mesure et
calibrer delta ; il ne produit pas le résultat du papier.

## 4. Pistes bonus (hors chemin critique)

N'entrent au papier que si E1-E3 sont bouclées et relues.

| Piste | Intérêt | Garde-fou |
| --- | --- | --- |
| Scénarios où l'automatisation est structurellement compliquée : chaînes à impasses générées, protocole documenté inconnu des règles, leurres plausibles | Renforce C2 là où l'écart est attendu | Déployés et vérifiés contre la vérité terrain ; jamais de règle volontairement affaiblie |
| Panel de modèles élargi, dont un **modèle MoE** (mélange d'experts, par ex. MoE local contre modèle dense local et modèle distant) | Axe coût/latence/qualité ; répond à la critique « un seul modèle testé » | Même gel (prompts, outils, budgets) ; le MoE est un bras de comparaison, pas un second sujet de papier |
| Extension aux phases 2 (reconnaissance) et 5 (intrusion) | L'adaptation peut y compter davantage | Seulement si le critère de poursuite de la proposition est satisfait en phases 3-4 |
| Génération procédurale complète de variantes | Puissance statistique, anti-contamination | Prouver d'abord une famille déployable ; une altération en aperçu seul invalide la strate |

## 5. Rétroplanning (décision au 2026-11-16)

| Période | Travail | Livrable de sortie |
| --- | --- | --- |
| 12-26 oct. 2026 | Gel du protocole (delta provisoire, conditions, grille de prix) ; lancement du pilote 24 runs sur nato | Manifeste de campagne rempli ; problèmes de mesure listés |
| 27 oct.-9 nov. | Variantes minimales déployables (surface, logique f11, chemins tenus à l'écart f20) ; graines supplémentaires | Strates prêtes ou explicitement abandonnées |
| 10-16 nov. | Analyse appariée, intervalles, coût/TP | **Décision du 16 nov.** (voir §6 du README et ci-dessous) |
| 17-30 nov. | Rédaction 12 pages ; artefact anonymisé ; appendices Open Science et éthique | Manuscrit relisible en entier |
| 1-11 déc. | Relecture interne complète, anonymat, conformité CFP | Soumission le **2026-12-11 (AoE)** au plus tard |

Critères de décision du 2026-11-16, écrits à l'avance :

- **Soumettre à AsiaCCS** si : au moins une condition prédite satisfait le
  critère de décision en TP confirmés, contrôles négatifs propres, artefact
  anonymisé prêt.
- **Soumettre quand même mais repositionné** (papier benchmark/mesure à
  résultat négatif) si : écart nul partout mais mesure propre et puissance
  suffisante pour borner l'écart. La contribution devient C1 + borne.
- **Ne pas soumettre** si : aucun run évaluable, contrôle négatif en échec,
  ou effet porté par une seule famille. Repli : workshop printemps 2027,
  puis campagne complète pour EuroS&P 2028 ou revue (TDSC, Computers &
  Security).

## 6. Risques et bloqueurs connus

| Risque | Conséquence | Parade |
| --- | --- | --- |
| Artefact non partageable (labo Proxmox/NATO) | Appendice Open Science faible, desk-reject ou revues négatives | Préparer tôt une version émulée minimale ou un extrait reproductible anonymisé ; justifier explicitement le reste |
| Runs séquentiels lents ou labo indisponible | Campagne incomplète au 16 nov. | Pilote dès cette semaine ; périmètre réduit validé plutôt que campagne ambitieuse inachevée |
| Contamination familles dev/test | Écart non interprétable | Split par famille, canaris, gel documenté, journal d'accès |
| Portée qui gonfle (MoE, phases 2/5, génération complète) | Pilote jamais terminé | Bonus hors chemin critique (§4) ; gel au 9 nov. |
| Un seul modèle évalué | Critique majeure en revue | Panel minimal : D1 + au moins 2 modèles, MoE en bonus si le temps le permet |
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

## 8. Squelette du papier (à créer après le pilote)

12 pages ACM : introduction et contributions (1), système et instrument (2),
benchmark et protocole (2), résultats E1-E3 (5), discussion et limites (1),
travail lié (1). Appendices : Open Science (obligatoire), Ethical
Considerations, détails de campagne. Chaque tableau de résultats renvoie
aux runs du manifeste de campagne ; aucune valeur n'est écrite à la main
sans identifiant de run.
