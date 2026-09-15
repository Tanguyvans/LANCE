# Entraînement des modèles

Ce dossier contient la préparation des données, l’entraînement QLoRA des modèles
et experts MoE, leurs configurations et les tests propres à ces outils.
Il ne contient pas les scénarios d’évaluation du benchmark.

```text
model_training/
├── README.md
├── configs/              # Hyperparamètres et chemins des données/modèles
├── templates/            # Formats de conversation pour l’entraînement
├── tests/                # Tests du code d’entraînement et de synchronisation
├── prepare_3b_datasets.py
├── preflight_3b.py
├── train_qlora_3b.py
├── train_qlora.py         # Parcours QLoRA antérieur conservé
├── requirements.txt      # Dépendances d’entraînement, distinctes de l’application
└── workspace_sync.json   # Liste explicite des fichiers à synchroniser vers le GPU
```

Les autres scripts de préparation, mutation, inspection d’adaptateurs et inférence
sont conservés. Ce rangement ne modifie ni les hyperparamètres, ni les jeux de
données, ni les chemins des checkpoints et adaptateurs existants.

## Guides

- [Experts Qwen2.5-3B](README_QWEN3B.md) : préparation, préflight et entraînement.
- [Feedback relu et accepté](README_FEEDBACK_TRAINING.md).
- [Synchronisation du workspace GPU](../docs/TRAINING_WORKSPACES.md).
- [Service HMoE / OpenWebUI](../docs/lance_hmoe_openwebui.md).
- [Scénarios d’évaluation](../docs/benchmark/v1/scenarios.md).

## Trois notions différentes

- `model_training/tests/` vérifie les outils d’entraînement, sans lancer une campagne GPU.
- `tests/` vérifie l’application, le pipeline, les preuves et l’évaluateur.
- `benchmarks/scenarios/test/` contient les scénarios d’évaluation d’une configuration figée.

Depuis la racine du dépôt :

```bash
# Tests dédiés à l’entraînement
python -m pytest -q model_training/tests

# Suite complète : les deux dossiers sont déclarés dans pytest.ini
python -m pytest -q
```

Les tests nécessitant `datasets` et `trl` restent ignorés si ces dépendances
optionnelles ne sont pas installées. Une suite réussie avec ce module ignoré ne
prouve pas le fonctionnement de l’entraînement sur GPU.

## Migration de training/ vers model_training/

Utiliser les nouveaux chemins dans les commandes locales, par exemple
`python model_training/preflight_3b.py --help`. Il n’existe pas de second dossier
source ou d’alias Python `training` à maintenir.

La synchronisation utilise maintenant les chemins `model_training/`. Elle reste
en aperçu par défaut, sans suppression distante. Après revue et synchronisation
explicite, adapter aussi les commandes ou lanceurs personnels sur la machine GPU.
Un ancien dossier `training/` distant n’est pas supprimé automatiquement et ne
doit plus être utilisé pour de nouveaux lancements. Aucun transfert ni entraînement
n’est déclenché par le renommage du dépôt.
