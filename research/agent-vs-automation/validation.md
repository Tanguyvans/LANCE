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
| Couverture et évaluation | [LaTeX](../benchmark-coverage/report.tex) · [PDF](../benchmark-coverage/report.pdf) | 10 |
| Contexte du pipeline | [LaTeX](../context-scalability/report.tex) · [PDF](../context-scalability/report.pdf) | 10 |

Les trois sources finales ont compilé avec succès dans l'éditeur LaTeX intégré
de Codex. Ce compilateur ne fournit pas un export sur disque via son outil de
diagnostic ; les PDF conservés ont donc été générés avec l'installation TeX
existante : latexmk 4.88, pdfTeX 3.141592653-2.6-1.40.29, TeX Live 2026.
Aucun package ni environnement LaTeX n'a été installé.

Commande d'export, depuis la racine, en remplaçant `<sujet>` par le dossier :

```bash
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir=/private/tmp/lance-research-pdf/<sujet> research/<sujet>/report.tex
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
