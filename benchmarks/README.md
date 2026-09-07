# IoTChainBench

IoTChainBench évalue un même harness LLM sur des réseaux IoT déployés sur Proxmox.
La version 3.2.0 contient 29 scénarios publics : 19 de développement et 10 réservés
au test. Le [catalogue](catalog.yaml) est la seule référence pour leurs identifiants
et leurs groupes.

## Organisation

```text
benchmarks/
├── catalog.yaml
├── scenarios/
│   ├── dev/             # S1–S19 + contrôles historiques S1h/S4h
│   └── test/            # S20–S29
├── ground_truth/
│   ├── dev/
│   ├── test/
│   └── matching_contracts.yaml  # Contrat commun de l’évaluateur
├── topologies/          # Composants réutilisables
├── packs/               # Composants réutilisables
├── scenarios_manual/    # Spécifications de laboratoire
├── ansible/             # Déploiement et vérification
└── tools/               # Composition et validation des données

src/agent/               # Un seul harness, phases et profils d’exécution
src/benchmark/           # Un seul évaluateur
src/learning/            # Amélioration à partir du développement uniquement
```

Les noms des dossiers sont `dev` et `test`. Les métadonnées conservent
`dev-public` et `test-public` pour rester compatibles avec les runs existants.
Les variantes S1h/S4h héritent du groupe de leur parent ; ce ne sont pas des
scénarios officiels supplémentaires et Ansible ne les déploie pas.

## Développement et test

- **dev** : diagnostic, modifications des prompts/outils/budgets, ablations,
  sélection de configuration et production de candidats d’apprentissage.
- **test** : évaluation d’une configuration préalablement figée. Les résultats
  ne servent pas à choisir ou améliorer cette configuration.

La répartition actuelle est conservée, mais son indépendance historique n’a pas
été vérifiée. S20–S29 sont donc un **jeu de test provisoire**, pas une garantie de
généralisation sur des données jamais consultées. Si leurs résultats ont déjà
guidé le développement, il faudra un nouveau jeu de test indépendant.
Voir le [protocole courant](docs/EVALUATION_PROTOCOL.md).

Les deux groupes sont publics et utilisent le même cycle de déploiement, le
même harness et le même évaluateur. Le support `eval-sealed` reste disponible
pour une future campagne ; aucun scénario courant n’appartient à ce groupe.

## Exécution sur la VM maître

Le dashboard FastAPI tourne sur la VM maître, pas sur la machine cliente.
Pour son installation et les variables d’infrastructure, voir [Ansible](ansible/).

Les playbooks déploient les templates (`01_create_templates`, `02_config_openwrt`),
puis le scénario (`03_deploy_scenario`), injectent les failles (`04_inject_vulns`),
vérifient l’état (`06_verify`) et nettoient les VMs du scénario (`99_teardown`).

Depuis le dépôt sur la VM maître :

```bash
# Itérer sur le développement
python -m src.agent --batch dev

# Une fois la configuration figée, évaluer le test
python -m src.agent --batch test

# Un test individuel, avec vérification explicite du groupe
python -m src.agent --scenario 20 --split test-public
```

Ces commandes lancent de vrais runs et peuvent déployer le laboratoire.
`--split auto` (par défaut) suit le catalogue. Un groupe explicite incompatible
avec le scénario est refusé avant de construire le fournisseur de modèle.
Les sélecteurs `public` et `all` peuvent contenir les deux groupes : les scores
restent séparés dans `per_split`, sans moyenne commune.

Les paramètres de scénario S14–S29 sont dans
`ansible/group_vars/all/scenarios_v2.yml`, fusionnés avec `main.yml`.
La CI valide le code avant toute mise à jour de la VM maître sur `main`.

## Ground truth et validation

Chaque définition `scenarios/{dev,test}/SN.yaml` correspond à
`ground_truth/{dev,test}/scenario_N.yaml`. Les chemins sont résolus depuis le
catalogue ; les topologies et packs ne sont pas dupliqués.
Les ground truths servent à l’évaluateur, pas de contexte d’entrée au harness.

```bash
# Lecture et comparaison seulement : tous les scénarios, dev comme test
python benchmarks/tools/compose_gt.py --validate

# Régénération explicite dans un répertoire séparé (conserve dev/ et test/)
python benchmarks/tools/compose_gt.py --scenario 1 --output-dir /tmp/lance-gt-review
```

La validation CI de cohérence des fichiers test est autorisée : ce n’est pas
une optimisation du harness sur leurs résultats. Les données historiques de
schéma v1 peuvent signaler une dérive `LEGACY-DIFF` non bloquante ; le schéma v2
est comparé strictement. `--strict-all` rend également la dérive v1 bloquante.

Le mineur et les exports SFT refusent les scénarios test, même avec un faux label
dev ou un marqueur custom. Les origines de variantes exportées sont aussi
contrôlées. Le mode custom nécessite une autorisation explicite au minage ;
il ne permet pas de réutiliser un scénario de test.
Voir la [boucle d’apprentissage](../docs/LEARNING_LOOP.md).

## Métriques

| Métrique | Description |
| --- | --- |
| Recall | Vrais positifs / (VP + faux négatifs) |
| Precision | Vrais positifs / (VP + faux positifs) |
| Raw Precision | Vrais positifs / (VP + faux positifs + findings bonus), pour rendre visible l'effet des exclusions |
| F1 Score | Moyenne harmonique precision/recall |
| Credited F1 | F1 donnant 1.0 à une correspondance structurelle exacte, 0.75 au type exact incomplet et 0.5 à une compatibilité explicitement autorisée |
| Quality-adjusted F1 | Credited F1 également pondéré par l'erreur de sévérité et la qualité de vérification ; score primaire de `strict-v3` |
| Verified F1 | F1 limité aux findings soutenus par un appel d'outil lié et explicitement réussi |
| Weighted Score | Score pondéré par sévérité (critical=4, high=3, medium=2, low=1) |
| Exploitation Coverage | TP avec niveau recalculé ≥ 2 et résultat d'outil lié explicitement positif / total TP |
| Multi-Hop Reach (MHR_1/2/3) | Recall conditionnel des vulns du ground truth à profondeur déclarée ≥ k ; variantes `_credited` (qualité du matching) et `_verified` (preuve d'outil) publiées séparément |
| Quality / Verified Path Coverage | Crédit minimal de qualité par chaîne complète ; la variante vérifiée exige aussi tous les findings prouvés et une chaîne Phase 5 ordonnée |
| Path Coverage | Chemins dont toutes les vulnérabilités attendues ont été détectées |
| Verified Path Coverage | Chemins précédents dont les appareils apparaissent aussi dans l'ordre dans une chaîne Phase 5 |
| Hallucination Rate | Faux positifs / (vrais positifs + faux positifs), hors bonus |
| Unmatched Finding Rate | Faux positifs + bonus / total findings |
| Phase 4 Completion Rate | Verdicts conclusifs Phase 4 / findings Phase 3 éligibles à l'exploitation |
| Coût | Tokens consommés par scénario (résumé par phase) |

Les répétitions sont moyennées au sein de chaque scénario, puis chaque scénario
a le même poids **dans son groupe**. Les contrôles sans vulnérabilité attendue
emploient la spécificité. Les métriques non disponibles restent `null`, pas zéro.
Un lot mixte garde ses compteurs et coûts globaux, mais ses scores uniquement
par groupe. Les résultats historiques ne sont ni déplacés ni réécrits.

## Faire évoluer le corpus

Modifier le catalogue, puis les définitions, ground truths et paramètres de
déploiement concernés ensemble. Valider les références et la composition en CI.
Un changement du corpus ou de la politique de scoring doit être versionné :
ne pas comparer silencieusement des campagnes fondées sur des définitions différentes.
