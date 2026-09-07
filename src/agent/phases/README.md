# Un pipeline, organisé par phase

`src.agent.pipeline.Pipeline` reste le point d'entrée de l'API, du CLI et des
benchmarks. Il initialise le run, résout le profil de chaque modèle, vérifie
les prérequis et garantit la finalisation. `registry.run_phase` appelle un seul
`run(context, config, stream_callback)` par phase, pour les deux profils. Sa table
référence directement les six modules : aucun chemin d'import n'est construit
dynamiquement et il n'y a pas de système de plugins à maintenir.

```text
agent/
├── pipeline.py
├── execution_profiles.py       # Budgets, résolution du profil, sélection d'outils
├── core/
│   ├── runner.py               # Boucle modèle/outils, transactions, événements
│   ├── lifecycle.py            # Préparation, déploiement, nettoyage
│   ├── runtime.py              # Dépendances d'infrastructure et catalogue d'outils
│   ├── probes.py               # Sondes protocolaires communes aux phases 4 et 5
│   └── memo.py                 # Contrôles structurels des mémos Markdown
└── phases/
    ├── registry.py             # Routage par numéro de phase, pas par profil
    ├── graph/                  # Phase 1 : run.py, compact.py
    ├── recon/                  # Phase 2 : run.py, compact.py
    ├── analysis/               # Phase 3 : run, compact, aggregation, evidence, prompts
    ├── verification/           # Phase 4 : run, contract, evidence, prompts
    ├── intrusion/              # Phase 5 : run, compact, evidence, scope
    └── report/                 # Phase 6 : run, compact, context, rendering, validation
```

Les éléments sous chaque phase sont des modules Python, pas des commandes shell
indépendantes. Chaque dossier contient son implémentation, pas une copie du moteur.

Les modèles de livrables sous `agent/templates/` portent directement le nom
configuré dans le registre : par exemple `06_report.md` pour le rapport. Le runner
n'a pas à compenser un ancien numéro de phase. La lecture des anciens rapports
enregistrés sous `05_report.md` reste prise en charge par l'application.

## Profils et responsabilités

- **Full** utilise le déroulement commun avec ses budgets et tous les outils
  autorisés par la phase. Il n'a plus de dossier de fichiers relais.
- **Compact** adapte la présentation des preuves, les outils et les budgets.
  Les guidages/récupérations spécifiques vivent dans le `compact.py` de la phase
  concernée. Une phase sans implémentation compacte distincte n'a pas ce fichier.
- **Paramètres** : modifier `execution_profiles.py` pour les budgets et le routage
  des outils ; ne pas recopier ces valeurs dans les phases.
- **Contrats et preuves** : modifier les fichiers de la phase concernée. Le contrat
  de vérification est commun : full reçoit ses exigences comme guidage, compact
  peut imposer leur exécution. Les règles d'intrusion compacte sont dans `scope.py`.
- **Infrastructure** : `core` porte le cycle de vie et les dépendances techniques,
  pas les règles métier des six phases.

Les conditions liées au moteur local restent inchangées. Choisir compact sur un
modèle distant n'active pas les récupérations locales ; utiliser un moteur local
avec full ne force pas compact. Le rapport choisit sa variante locale dans son
unique point d'entrée, avec les mêmes conditions et le même fallback qu'avant.

## Limites conservées explicitement

Les composants restent des mixins utilisant l'état du même `Pipeline`. Ce passage
clarifie la propriété du code ; il n'isole pas encore les phases dans des contextes
indépendants. Le runner coordonne encore certaines adaptations et les outils et
validateurs conservent des variables globales. Ce ne sont pas six moteurs autonomes.

L'API, le CLI et les workers passent par `Pipeline`. L'override `pipeline.OUTPUT_DIR`
reste disponible pour le worker isolé. Les helpers internes doivent être importés
depuis leur module propriétaire, pas depuis la façade. Les réexportations ajoutées
pendant la migration et les fichiers relais `agent/report_context.py` et
`agent/report_rendering.py` ont été retirés : seuls les tests les utilisaient.
Les anciens chemins internes `phases.shared`, `phases.full` et `phases.compact`
ont également été retirés.

Dans les tests, simuler les dépendances techniques via `src.agent.core.runtime`
et les règles métier dans leur module propriétaire. Les tests de structure
contrôlent le routage des deux profils, l'absence de fichiers relais et l'import
des phases sans passer par la façade.
