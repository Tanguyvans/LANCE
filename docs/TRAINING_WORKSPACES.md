# Architecture des workspaces d'entraînement

## Rôles

Les deux workspaces ont des responsabilités volontairement asymétriques :

| Workspace | Rôle | Git |
| --- | --- | --- |
| `/home/tanguy/LANCE` | Code, configurations, templates, tests et documentation canoniques | Seule origine des commits et push |
| `/home/leo/LANCE` | Datasets locaux, environnement CUDA, entraînements, checkpoints et adaptateurs | Aucun commit ni push |

Une correction faite directement chez Leo n'est pas livrée. Elle doit être
réimplémentée dans Tanguy, testée, puis resynchronisée.

## Frontière de synchronisation

La liste blanche est versionnée dans `training/workspace_sync.json`. L'outil
`scripts/training_workspace.py` applique les règles suivantes :

- aperçu en lecture seule par défaut ;
- aucune suppression dans le workspace Leo ;
- copie atomique des seuls fichiers explicitement listés ;
- hash SHA-256 de chaque fichier envoyé ;
- manifeste de provenance avec commit, branche et état dirty de Tanguy ;
- collecte limitée à des rapports JSON de petite taille ;
- refus des symlinks, traversées de chemins et destinations hors workspace ;
- exclusion structurelle de `.git/`, `data/`, `env/`, `output/` et `wandb/`
  dans le sens Tanguy vers Leo ;
- `pull-reports` ne collecte aucun poids `.safetensors`, checkpoint ou dataset ;
- `pull-adapters` collecte seulement les fichiers finaux explicitement autorisés
  des quatre experts, avec limites de taille et vérification SHA-256.

Le manifeste de provenance du dernier déploiement est écrit chez Leo dans
`output/training-source-manifest.json`.

## Workflow quotidien

Depuis Tanguy, inspecter les différences :

```bash
cd /home/tanguy/LANCE
python3 scripts/training_workspace.py status
```

Prévisualiser puis appliquer la synchronisation :

```bash
python3 scripts/training_workspace.py push
python3 scripts/training_workspace.py push --apply
```

Puis travailler chez Leo :

```bash
cd /home/leo/LANCE
PYTHONDONTWRITEBYTECODE=1 env/bin/python training/preflight_3b.py --strict-gpu-idle
PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  PYTHONPATH= env/bin/python training/train_qlora_3b.py --expert recon
```

Après un préflight ou un entraînement, prévisualiser puis collecter uniquement
les rapports autorisés :

```bash
cd /home/tanguy/LANCE
python3 scripts/training_workspace.py pull-reports
python3 scripts/training_workspace.py pull-reports --apply
```

Ils sont copiés sous `output/training-workspace/leo/`, répertoire ignoré par
Git.

Après validation des quatre sorties, prévisualiser puis rapatrier uniquement les
adaptateurs finaux :

```bash
python3 scripts/training_workspace.py pull-adapters
python3 scripts/training_workspace.py pull-adapters --apply
```

La source d’entraînement est le répertoire versionné
`output/adapters/lance-qlora_moe_3b_20260724/` chez Leo. Les fichiers finaux
sont promus localement sous `output/adapters/lance-qlora_moe_3b/`, chemin stable
consommé par le service HMoE. Les checkpoints, états du trainer, datasets,
environnements et sorties `wandb` ne sont jamais collectés par cette commande.

Un résultat destiné à une publication doit être synthétisé explicitement
dans un document versionné, avec le commit et les hashes du manifeste source.

## Ajouter un fichier synchronisé

1. Créer et tester le fichier dans Tanguy.
2. Ajouter son chemin relatif exact à `push_files` dans
   `training/workspace_sync.json`.
3. Ajouter ou adapter les tests de frontière.
4. Vérifier `status`, puis utiliser `push --apply`.

Ne jamais élargir la liste avec un glob couvrant `data/`, `output/`, `env/`,
`wandb/` ou des poids de modèle.

## Promotion d'un modèle

Un adaptateur produit chez Leo n'est pas une modification de code. Pour le
promouvoir :

1. collecter les rapports JSON ;
2. vérifier le modèle de base et les quatre experts avec `preflight_3b.py
   --require-adapters` ;
3. exécuter les benchmarks publics depuis le commit déclaré ;
4. produire un manifeste de release contenant hashes, métriques et configuration ;
5. modifier le déploiement dans Tanguy ;
6. commit et push uniquement depuis Tanguy.
