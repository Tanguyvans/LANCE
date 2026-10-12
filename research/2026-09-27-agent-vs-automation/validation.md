# Validation locale de la revue du 29 septembre 2026

**Statut : observations logicielles, aucune campagne de performance.** Cette page
relie la recherche à ses preuves reproductibles. Elle ne certifie ni le laboratoire
ni un avantage LLM. Les vérifications de recherche ne lancent aucun audit réseau
ni campagne ; leur publication par commit et push a ensuite été demandée.

## Base et provenance

- Révision source : `45c8dab892ecb4e5f513813387090e0cded1b85d`.
- Le checkout comportait déjà une réorganisation documentaire : changements d'AGENTS.md, README, docs et research, avec fichiers non suivis. Ces travaux ont été conservés. Les documents consultés ne sont donc pas intégralement représentés par le SHA.
- Empreinte retournée par `src.agent.audit_experiment.resource_manifest()` avant cette étude : `3c2b0fc31533d629b537bd342dd4af291feeec67022fda1beccd729dba6dd54c`. Elle couvre les ressources sélectionnées de `src/agent` et `src/benchmark`, pas les définitions du laboratoire ni l'environnement système.
- Seuls des documents, index et scripts de reproduction sont ajoutés/modifiés par cette étude. Aucun correctif du runtime, du calcul des métriques ou des tests existants n'est livré.
- Les [scripts conservés](../../benchmarks/experiments/research-review/README.md) se lancent depuis la racine ; leurs entrées synthétiques ne nécessitent aucune cible réelle.

## Vérifications obtenues

| Vérification | Résultat observé | Limite |
| --- | --- | --- |
| Inventaire catalogue, GT et sidecar | 29 empreintes GT concordantes ; 288 GT, 88 contrôles dont 77 mappés à types interdits ; 249 instances services, 67 chemins déclarés. | Définitions uniquement ; contrôles de vivacité non assimilables à des négatifs ; familles non indépendantes. |
| `python3.12 benchmarks/tools/compose_gt.py --validate` | Code 0 ; 31 GT examinées, dont 13 `LEGACY-DIFF` descriptifs S1–S13 et 18 correspondances strictes, variantes S1h/S4h incluses. | Pas `--strict-all` ; ni déploiement ni couverture effective prouvés. |
| Probe taux de tentative | Un candidat, deux TIMEOUT avec `verification_attempted:false` donnent `inconclusive=1`, `not_tested=0`, taux `1.0`. | Contre-exemple local ; fréquence terrain inconnue. |
| Probe oracle OTA | Une trace déclarant signature valide donne `EXPLOITED`, niveau 2. | Aucun certificat, serveur ou score complet testé ; le défaut porte sur le synthétiseur. |
| Probe oracle code injection | Une réponse d'aide contenant `uid=1000(user)` donne `EXPLOITED`, niveau 3. | Observation insuffisante admise ; pas d'exécution réelle. |
| Cinq probes contexte | Marqueur central perdu avec zéro entrée omise ; 20 services réduits à 6 ; 16 observations tronquées ; blocs `[2,2,2,14]` ; deux mémos incomplets non rejetés. | Assertions de caractérisation de la version actuelle, pas performances des modèles. |
| Manifeste pilote exemple, bilan hors ligne | 12 paires prévues, 0 admissible, 24 bras non exécutés, 8 champs de configuration non fixés, consommations inconnues. | Décrit uniquement l'exemple ; ne démontre pas l'absence de runs ailleurs. |
| Tests ciblés après préparation de l'environnement | **381 tests réussis en 8,35 s**. | Fournisseurs/outils simulés ; suite complète non exécutée. Les défauts identifiés montrent les limites de la couverture de tests. |

## Commandes et environnement

L'environnement initial ne permettait pas la suite : Python 3.12 sans pytest ;
Python 3.11 avec plugin global web3 cassé et syntaxe source incompatible. Un venv
temporaire avec accès aux packages système Python 3.12 a été créé sous
`/private/tmp/lance-research-venv`. Aucun environnement du dépôt n'a été modifié.

Versions ajoutées au venv : Python 3.12.2, pytest 9.1.1, paho-mqtt 2.1.0,
pydantic 2.13.5 / pydantic-core 2.46.5, fastapi 0.142.0, starlette 1.7.0,
sse-starlette 3.5.0 et aiofiles 25.1.0. Les autres dépendances proviennent du
Python système ; ce venv n'est pas un lockfile de reproduction de laboratoire.

Les premières tentatives ont rencontré imports Pydantic/SSE et absence de paho ;
ces problèmes ont été résolus dans le venv, puis la sélection entière relancée.
Le compte final ci-dessus remplace les tentatives incomplètes, sans les présenter
comme des régressions du logiciel.

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /private/tmp/lance-research-venv/bin/python -m pytest -q --tb=short \
  tests/test_audit_policy.py tests/test_evaluator_strict_v3.py \
  tests/test_evaluation_funnel.py tests/test_funnel_consistency.py \
  tests/test_preflight_evaluation_boundary.py tests/test_tool_loader.py \
  tests/test_report_sections.py tests/pipeline/test_analysis_block_recovery.py \
  tests/pipeline/test_intrusion_context.py tests/pipeline/test_phase3_status_propagation.py

python3.12 -m src.benchmark.policy_campaign \
  --manifest benchmarks/experiments/policy-comparison/pilot.example.json \
  --output /private/tmp/lance-pilot-summary.json \
  --csv /private/tmp/lance-pilot-trials.csv
```

Les [trois commandes de probes](../../benchmarks/experiments/research-review/README.md)
ont été rejouées par l'orchestrateur. Le journal pytest final local est
`/private/tmp/lance-research-tests-final.log`, les sorties consolidées
`/private/tmp/lance-reviewed-inventory.json` et
`/private/tmp/lance-reviewed-evaluation.txt`. Ces chemins sont temporaires ; les
scripts et observations essentielles conservés dans le dépôt permettent de
reproduire le diagnostic sans dépendre de leur persistance.

## Limites et contrôles éditoriaux

Les sources primaires, dates et portions lues figurent dans chaque analyse.
Les artefacts historiques `output/agent/2026-09-*` lus ont une provenance
insuffisante pour en inférer une performance actuelle ; ils peuvent inclure des
fixtures. Aucun score d'ancienne campagne n'a été agrégé avec le contrat courant.
Le constat de préparation nato du 28 septembre n'est pas une vérification de
disponibilité du laboratoire aujourd'hui ; aucune nouvelle connexion n'a été faite.

Les liens locaux des études, index et pages déplacées ont été vérifiés sans lien
manquant après intégration des PDF ;
`git diff --check` réussit. L'empreinte des ressources source est inchangée.
La contre-revue Muse n'est pas comptée comme exécutée tant
que l'autorisation de transmission reste en attente ; voir les
[arbitrages de revue](adversarial-review.md).


## Livraison LaTeX et PDF

Version de lecture du 29 septembre 2026, rédigée depuis les analyses et
contre-revues conservées, puis remise en forme depuis la publication `26431ad`. Chaque étude fournit un document autonome, sans
fichier graphique ou bibliographique externe :

| Étude | Source et PDF | Pages exportées |
| --- | --- | --- |
| Synthèse et apport LLM | [LaTeX](report.tex) · [PDF](report.pdf) | 9 |
| Couverture et évaluation | [LaTeX](../2026-09-29-benchmark-coverage/report.tex) · [PDF](../2026-09-29-benchmark-coverage/report.pdf) | 10 |
| Contexte du pipeline | [LaTeX](../2026-09-29-context-scalability/report.tex) · [PDF](../2026-09-29-context-scalability/report.pdf) | 10 |

Les trois sources finales ont compilé avec succès dans l'éditeur LaTeX intégré
de Codex. Ce compilateur ne fournit pas un export sur disque via son outil de
diagnostic ; les PDF conservés ont donc été générés avec l'installation TeX
existante : latexmk 4.88, pdfTeX 3.141592653-2.6-1.40.29, TeX Live 2026.
Aucun package ni environnement LaTeX n'a été installé.

Commande d'export, depuis la racine, en remplaçant `<dossier-date>` par le nom
complet du dossier de l'étude (par exemple `2026-09-27-agent-vs-automation`) :

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir=/private/tmp/lance-research-pdf/<dossier-date> research/<dossier-date>/report.tex
```

Les PDF ont été rendus en PNG avec Poppler et inspectés visuellement : titre,
résumé, sommaire, figures, tableaux, légendes, références et pagination.
Les 29 pages finales sont numérotées ; les 72 destinations du sommaire existent
et correspondent aux pages annoncées. Les identifiants de figures/tableaux et
les clés bibliographiques de la première version sont conservés, ainsi que
les six figures TikZ. Aucun débordement `Overfull` ni glyphe manquant détecté.

La présentation suit les [conventions scientifiques](../README.md#structure-scientifique-classique) :
titre centré, résumé bref, table des matières cliquable, sections numérotées,
méthode identifiable, conclusion et références. Le PDF de référence fourni par
l'utilisateur a servi uniquement à étudier la présentation ; ses données et
instructions scientifiques ne font pas partie du travail LANCE.
Les résumés et conclusions synthétisent les constats existants, sans ajouter
une mesure ou présenter un protocole proposé comme exécuté.

L'exporteur local signale toujours l'absence de motifs français préchargés ;
le rendu livré a été vérifié. La substitution de graisse petites capitales
observée lors du premier export a été supprimée. Les fichiers de compilation
et images de contrôle restent temporaires, hors du dépôt.

Cette livraison modifie la présentation et la navigation, pas les résultats
expérimentaux ni le runtime. Les 381 tests ci-dessus ne sont pas présentés comme
une validation scientifique des propositions ou de la mise en page.

## Classement par date et étude

Réorganisation du 29 septembre 2026 depuis la publication `a356d96` : les quatre
dossiers suivent désormais `AAAA-MM-JJ-nom-etude`. La première date documentée de
l'étude agent / automatisation est le 27 septembre ; les nouvelles études de
couverture et de contexte commencent le 29 septembre. Pour IoMT, la date de
classement est utilisée explicitement car le début reste inconnu. Les règles
sont conservées dans l'index de recherche, avec un rappel dans `AGENTS.md`.

Les liens des index, guides, notes et sources LaTeX ont été actualisés. Les trois
sources ont de nouveau compilé dans l'éditeur intégré et les PDF ont été exportés
avec l'installation TeX existante. Les 424 liens Markdown locaux contrôlés sont
valides, sans ancienne référence aux dossiers déplacés. Les liens locaux des PDF
et leurs 72 destinations de sommaire sont valides ; la pagination reste 9/10/10.

Le rendu des 29 pages a été comparé à la publication précédente : seuls la page 8
du rapport principal et les pages 6 et 7 du rapport contexte changent visuellement,
en raison des chemins plus longs. Ces pages et les vues d'ensemble ont été
inspectées, sans débordement ni glyphe manquant. Les six figures sont conservées.
Aucun code d'exécution n'a changé ; les tests applicatifs n'ont pas été relancés
pour ce classement documentaire.

## Horodatage des rapports

Révision de présentation : **2026-09-30 21:55 (Europe/Brussels, UTC+02:00)**.
Les trois premières pages affichent désormais la date et l'heure de dernière
révision, avec le fuseau horaire. Les README et l'index reprennent ce même instant ;
les règles demandent un horodatage fixé dans la source, distinct des dates de
recherche, de consultation et d'expérience. Les noms des dossiers restent fixes.

Les trois sources compilent avec succès dans l'éditeur LaTeX intégré. Les PDF ont
été exportés avec l'installation TeX existante et leurs premières pages rendues
en PNG ont été inspectées. La comparaison des 29 pages avec la version précédente
montre un changement sur la première page de chaque rapport seulement : les 26
autres pages sont identiques visuellement et textuellement. Aucun débordement ni
glyphe manquant détecté ; pagination 9/10/10 et 72 destinations de sommaire
conservées. Les liens locaux des PDF sont valides et les six figures TikZ restent
inchangées. Cette retouche ne renouvelle pas les constats ni les résultats de
validation logicielle du 29 septembre ; aucun test applicatif n'a été relancé.

## Relecture indépendante du 1er octobre 2026

**Version finale des rapports : 2026-10-01 10:23 (Europe/Brussels, UTC+02:00).**
Auteur des corrections : Codex, agent principal. Relecteurs distincts : les
sous-agents Codex `review_clarity` (texte et cohérence) et `review_figures`
(rendu visuel). La relecture porte sur les quatre rapports courants et leurs
README ; les notes détaillées ont servi à retrouver la provenance. Les notes
complémentaires et archives n'ont pas toutes été relues ni rendues ; le Word
historique IoMT reste inchangé. Aucune revue Muse n'a été exécutée à cette étape.

### Corrections retenues

- Définition de D1/A1 dès le résumé du rapport principal, vocabulaire de mesure
  et repères de lecture ; pilote expliqué comme 12 paires et 24 exécutions prévues.
- Distinction entre hypothèses proposées par l'agent et vérité terrain utilisée
  après l'audit ; aucune réponse attendue n'est ajoutée à l'entrée publique.
- Contexte : conversation indépendante par invocation de boucle outils, avec
  historique repris entre requêtes ; R1 identifié comme dispositif expérimental
  à outils de lecture communs ; observation archivée distincte de preuve validée.
- Benchmark : légende explicite et pourcentages des catégories du graphique,
  colonnes de tableaux alignées à gauche ; figures et tableaux placés à des
  frontières de paragraphes ; bibliographie et sommaire corrigés.
- IoMT : première version LaTeX/PDF depuis la proposition historique, avec
  périmètre simulé, distinctions passif/actif, F1 conforme au contrat courant,
  limites cliniques et faisabilité encore ouverte. Lecture ciblée des sections
  de sécurité HTTP/DICOM d'Orthanc et du profil DICOM PS3.15 2026d B.12.

### Vérifications obtenues

La relecture initiale a inspecté les 29 pages des trois anciens PDF. Après
correction et ajout du rapport IoMT, les 38 pages intermédiaires ont été vues ;
les dernières corrections de bibliographie ont ramené le total à **37 pages**.
Les pages affectées et les quatre couvertures finales ont été revérifiées par
le relecteur visuel. Toutes les remarques signalées de compréhension et de rendu
ont été résolues dans ce périmètre. Les sources ont été relues une seconde fois.

Les quatre sources finales compilent dans l'éditeur LaTeX intégré de Codex.
Les PDF sur disque sont exportés par l'installation TeX existante (`latexmk` et
`pdflatex`), puis rendus par `pdftoppm` à 1 400 pixels sur le plus grand côté.
Aucun fichier de compilation n'est conservé dans les dossiers d'étude.
Les exports ne signalent ni débordement `Overfull`, ni glyphe manquant, ni
référence ou citation indéfinie. L'avertissement historique de motifs de césure
français non préchargés reste présent ; les pages rendues ont été inspectées.

Les **86 destinations de sections et sous-sections enregistrées dans les
sommaires sources** existent et correspondent à leur numéro de page PDF,
vérifiées avec `pypdf`. Certaines sous-sections sont masquées dans les sommaires
affichés de niveau 1. Les liens Markdown locaux modifiés et `git diff --check`
sont vérifiés. Aucun test du runtime ni run de laboratoire n'a été lancé pour
cette révision documentaire ; les 381 tests historiques ci-dessus ne sont pas
réétiquetés comme une nouvelle validation.

### PDF finaux relus

| Dossier | Pages | SHA-256 du PDF |
| --- | ---: | --- |
| 2026-09-27-agent-vs-automation | 10 | `43146eff137ee7bc423220fddc5a13691e0822f66652827def733bbe7b16e435` |
| 2026-09-29-benchmark-coverage | 10 | `264ff783388916288c78b0981277c0bf9582fc50debab2c78f5aef5391976512` |
| 2026-09-29-context-scalability | 11 | `edd203a47988dcb46b9517bbbd3ae0f462ca2e46c65339b81d4154374834082d` |
| 2026-09-29-iomt | 6 | `8b8a7dbab1ddeca34c4728e092f50b350a788815f1db305ec286fcbdb3d5e069` |

Les empreintes identifient les exports de cette relecture. Les sources éditables
restent les `report.tex` correspondants ; les dates d'étude et des observations
historiques restent distinctes de l'horodatage de révision documentaire.

<a id="relecture-sans-llm-2026-10-07"></a>

## Contre-relecture indépendante du 7 octobre 2026 : méthodes sans LLM

**Périmètre : approfondissement de recherche et protocoles proposés.** Les
résultats et tests historiques ci-dessus restent inchangés et attribués à leurs
dates. Trois agents ont rédigé les rapports spécialisés : `sans_llm_outils`,
`sans_llm_raisonnement` et `sans_llm_experiences`. Codex `/root` a rédigé la
synthèse. Deux nouveaux agents distincts des auteurs ont assuré une contre-revue
scientifique et l'inspection des PDF ; ils n'ont pas modifié les textes relus.

### Versions et périmètres effectivement relus

Tous les instants ci-dessous sont le **7 octobre 2026, Europe/Brussels,
UTC+02:00**. Les auteurs ont inspecté tous leurs rendus ; les relecteurs ont
aussi rendu les PDF et inspecté toutes les pages, après correction.

| Document | Révision finale | Pages finales | Relecteur indépendant | Recontrôle final terminé |
| --- | --- | ---: | --- | --- |
| `sans-llm-outils.tex/pdf` | 14:27 | 9 | `/root/sans_llm_relecture_methodes` | 14:32 |
| `sans-llm-raisonnement.tex/pdf` | 14:28 | 9 | `/root/sans_llm_relecture_methodes` | 14:34 |
| `sans-llm-experiences.tex/pdf` | 14:43 | 9 | `/root/sans_llm_relecture_experiences` | 14:45 |
| `sans-llm.tex/pdf` | 14:44 | 8 | `/root/sans_llm_relecture_experiences` | 14:46 |

La première revue des méthodes a couvert sources LaTeX et registres complets,
et les 17 pages initiales (8 outils, 9 raisonnement), à 14:24. Le relecteur a
contre-vérifié certains passages primaires : NIST SP 800-115 résumé exécutif
et section 2 ; guide CycloneDX, date/édition, pedigree et complétude ; Cedar,
conditions de mesure et limites de la traduction concordante. Il ne prétend
pas avoir reproduit ces sources ni revérifié intégralement chaque référence.

La première revue expérimentale a couvert source, registre et neuf pages du
rapport révisé à 14:22, à 14:40. Le relecteur a ensuite relu les corrections et
inspecté les neuf pages du PDF révisé à 14:43, puis la source et les huit pages
de la synthèse à 14:44. Les rendus indépendants utilisent `pdftoppm` à 110 dpi
et `view_image` ; la simple extraction du texte n'a pas servi de verdict visuel.
Les 35 pages finales sont donc couvertes par une inspection indépendante.

### Objections scientifiques et corrections retenues

Les réserves suivantes ont modifié le protocole ; ce ne sont pas des résultats
de benchmark. Les localisations initiales désignent les versions antérieures
aux corrections et peuvent changer dans les PDF finaux.

| Réserve | Localisation initiale et gravité | Conséquence et correction vérifiée |
| --- | --- | --- |
| R1 — D1 existant / nouveau lecteur | Raisonnement, p. 1 et 3 ; majeure | Ne pas présenter un nouveau moteur de dossiers comme le D1 actuel phases 3–4. Le lecteur à règles est un adaptateur hors ligne proposé. |
| R2 — référence dite forte sans acceptation | Outils §5 ; raisonnement §6 ; moyenne | Une victoire sur des règles sous-conçues serait peu informative. Porte d'acceptation sur développement : critères, contextes, négatifs proches, inconnus, justifications, effort humain, gel et versionnement avant test. |
| R3 — mêmes avis ≠ mêmes connaissances | Outils §4.5 ; moyenne | Le préentraînement peut expliquer le gain. Limite déclarée, noms/avis fictifs cohérents proposés ; date récente et absence de web ne certifient pas un raisonnement pur. |
| R4 — branches enregistrées ≠ rejeu cohérent | Outils §5 ; moyenne | Si l'état dépend de l'historique, les réponses contrefactuelles peuvent être invalides. Restreindre aux lectures sans effet et indépendantes de l'historique, ou à des histoires fournies cohérentes ; sinon hors couverture. |
| R5 — rappel limité aux candidats LANCE | Outils §6 ; moyenne | L'univers doit être indépendant du collecteur et inclure ses omissions. Séparer rappel d'état, rappel conditionnel aux pièces observables et couverture. |
| R6 — sauts de page systématiques | Raisonnement, source ; mineure | Sept sauts forcés supprimés conformément aux conventions ; nouvelle pagination entièrement inspectée. |
| RE1 — oracle et dénominateurs | Expériences §4 / métriques, p. 4 ; majeure | Séparer état réel et suffisance des preuves accessibles. Publier les deux rappels ; conserver non-observables, abstentions, incomplets et échecs dans les totaux et la couverture. |
| RE2 — matrice normative assimilée à une fuite | Expérience d'autorisation, p. 6 ; majeure | La politique sujet–ressource–action est une entrée légitime commune. Seule l'étiquette privée par dossier ou la conclusion attendue fuit l'oracle. |
| RE3 — divergences des rapports exclues | Expérience humaine, p. 7 ; majeure | Les dossiers sources et contraintes restent communs. Omissions et inventions des rapports générés sont des erreurs mesurées et conservées avec leur coût ; ne pas suspendre le test à cause d'elles. |
| RE4 — F1 sain toujours indéfini | Expérience cas sains, p. 5 ; moyenne | Via 2TP/(2TP+FP+FN), F1 vaut zéro si FP>0 ; dénominateur nul dépend de la convention. Préférer taux de fausses alertes/spécificité et publier leurs dénominateurs. |
| RE5 — échec du parseur retiré | Expérience de variations, p. 6 ; moyenne | La perte d'information invalide le contraste sémantique normalisé. Dans la strate brute, l'échec de parsing reste un résultat mesuré. |
| RE6 — expériences confondues avec familles indépendantes | Synthèse, tableau des tests / §6.2 ; moyenne | Colonne renommée « Expérience ». Une famille d'origine dépend du générateur, de l'implémentation, du service ou de la structure partagés ; ses variantes ne sont pas indépendantes. |

La réserve sur l'attribution « examen, entretien, test » au NIST a été
contre-vérifiée : SP 800-115 l'étaye effectivement ; aucune correction arbitraire
de source n'a été imposée. Les deux relecteurs recommandent une référence à
règles compétente, les expériences routine/cas sains puis les variations sur le
même corpus. Les droits et jointures deviennent prioritaires seulement si les
pièces et la difficulté contextuelle le justifient ; la restitution humaine
reste une expérience distincte. Firmware, apprentissage classique, NetPlumber
et vérification de configuration restent conditionnés par les artefacts et la
question, sans conclusion empirique défavorable à ces méthodes.

### Vérifications documentaires et limites

Compilation des quatre sources avec `latexmk`/`pdflatex`, rendus complets et
recontrôles finaux terminés. Aucun défaut bloquant de compréhension ou de rendu
ne reste dans le périmètre relu. Les références et destinations des liens
internes existent ; les liens vers les rapports et registres locaux sont
vérifiés. Les registres JSON sont valides et distinguent les sections réellement
lues des documents non parcourus intégralement. Le registre consolidé dénombre
29 lectures pour 27 URL primaires distinctes ; ce n'est ni un nombre d'articles
ni une revue systématique. Les statuts d'auteur contenus dans les registres
spécialisés décrivent leur instant de production ; le présent journal consigne
la contre-relecture postérieure.

Les compilations finales ne présentent pas de débordement `Overfull` ni de
référence indéfinie. L'avertissement de motifs de césure française non
préchargés demeure ; aucun défaut correspondant n'a été observé dans les
rendus. Les contrôles ciblés de blancs et de marqueurs des nouveaux fichiers
passent. Le `git diff --check` global reste en échec sur les conflits déjà
présents, notamment dans la documentation du benchmark et le code ; cette
recherche ne les résout pas. Les sources historiques, le code et les guides
inspectés ont été préservés ; l'index, le README et ce journal sont complétés.

Aucun test applicatif, appel LLM expérimental, run de laboratoire ou déploiement
n'a été exécuté. Le corpus éligible, l'oracle indépendant, la compétence réelle
des comparateurs, l'indépendance des familles, les seuils, effectifs, coûts et
compatibilités restent à valider. Les verdicts des relecteurs acceptent la
recherche et les protocoles proposés ; ils n'établissent aucun gain, absence
de gain ou équivalence expérimentale.

### Empreintes finales des PDF inspectés

| PDF | SHA-256 |
| --- | --- |
| `sans-llm.pdf` | `42ecf817a9741655de78957670eb0da88087cec14bfecbc5e48649fa53d40c60` |
| `sans-llm-outils.pdf` | `d8dcc4d4364a1297fbfe45420276703a68fad5263f679538da8fd9d7256886bd` |
| `sans-llm-raisonnement.pdf` | `cf412d714a0c4f50d79efa5713e9a628a5d667d067b3f76685fda3cff60a9f72` |
| `sans-llm-experiences.pdf` | `05738cb827891ffe8528df09c8d7af4a478a560f9baaec46679def4ac30b9a61` |

Sources LaTeX finales contrôlées : synthèse
`1670e7286ad54e027eecc32217618018b5784b7685d8d09c8e459f5ab018b507`, outils
`64c346e3fd1b8731068a08629a8b121e9647a8ca2635ca230f5f0d1af44c1b0b`, raisonnement
`15ff0fce557e13c1632b5d7898226024d4ded3539cd723be754005e4c137a104`, expériences
`a9f15d2c7634c42b21ede6b1bcf2318652f82633094cd4117c545ee6b41d34f4`.
