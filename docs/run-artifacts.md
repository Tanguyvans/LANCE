# Livrables : un dossier explicite par run

## À retenir

Créer un run B ne doit jamais rediriger les lectures, écritures ou validations
du run A. Le pipeline reste unique, avec les mêmes dossiers par phase.
Cette correction n'ajoute ni gestionnaire global de contexte ni nouvelle classe.

Trois règles suffisent :

1. `Pipeline.run_dir` désigne le dossier de ce run et reste fixe pendant celui-ci.
2. Les outils et validateurs reçoivent ce dossier explicitement.
3. Le nom du livrable attendu appartient à la transaction de la phase, pas au processus.

## Qui fait quoi ?

| Code | Responsabilité |
| --- | --- |
| `agent/pipeline.py` | Créer un dossier unique sous le parent demandé. |
| `agent/artifacts.py` | Résoudre un nom relatif, sans sortir du run. |
| `agent/tools/deliverable.py` | Lire, écrire, lister et agréger dans le dossier fourni. |
| `agent/core/executor.py` | Lier les outils au run avant les contrôles et la journalisation. |
| `agent/core/runner.py` | Lier les validateurs ; archiver et valider les soumissions avant publication. |
| `agent/validators/__init__.py` | Appliquer les règles de structure au dossier fourni. |

Les catalogues `DELIVERABLE_TOOLS` et `VALIDATORS` décrivent des fonctions, pas
un « run courant ». Les setters `set_output_dir` et `set_expected_deliverable`,
ainsi que les variables globales de dossier des outils/validateurs, sont supprimés.

## Création et appels

Le paramètre `output_dir` de `Pipeline` désigne le **parent** des runs :

```python
pipeline = Pipeline(provider=provider, output_dir=Path("output/agent"))
# pipeline.run_dir : output/agent/2026-09-15_120000, résolu en chemin absolu
```

Le format historique est conservé. Si le dossier existe déjà, un suffixe aléatoire
est ajouté ; sa création est exclusive. Même deux créations pendant la même
seconde ne réutilisent pas le même dossier. Aucun ancien dossier n'est effacé.
Le worker transmet lui aussi son parent avec ce paramètre.

Pour une phase, utiliser les chemins communs existants :

- `_resolve_tools(config)` lie les outils à ce run et les enveloppe pour journaliser leurs appels.
- `_apply_deliverable_transaction(...)` capture la configuration de la phase.
  Si le modèle omet `filename`, c'est `config.deliverable_file` qui est utilisé.
- `_validator(name)` retourne un validateur lié au dossier du run, y compris
  pour les lectures annexes du rapport en phases 4 et 5.

Dans un test ou un appel Python de bas niveau, le dossier est obligatoire :

```python
save_deliverable("result.json", '{"example": true}', output_dir=run_dir)
valid, reason = validate_json_valid("result.json", output_dir=run_dir)
```

Ces appels bas niveau ne remplacent pas la transaction du pipeline. Une simple
écriture n'est pas une soumission validée. Les signatures internes changent ; les
arguments exposés au modèle ne changent pas et n'incluent jamais `output_dir`.
La liaison n'autorise pas le modèle à remplacer le dossier par un argument caché.
Ne pas partager des fonctions d'outils déjà liées entre deux runs.

## Ce qui reste garanti

- Une tentative rejetée reste dans `.attempts/` de son run ; le livrable valide
  d'un autre run ne peut pas la remplacer.
- Les chemins absolus, les traversées vers un autre dossier et les liens
  symboliques existants qui en sortent sont refusés, y compris pour les tentatives.
- Les outils continuent de masquer la vérité terrain et `provider_events.jsonl`.
- Les appels d'outils conservent leur journal, leurs références et leurs contrôles.
- Une structure valide ne constitue pas une preuve de faille, d'accès ou de pivot.
- Full/compact, budgets, scores et versions des contrats d'évaluation sont inchangés.

## Limites : ce changement ne rend pas tout concurrent

L'isolation porte sur les livrables et leurs validateurs. D'autres états partagés
subsistent dans les outils, notamment le graphe et la politique de recherche CVE.
L'API garde sa restriction sur les exécutions simultanées ; ne pas la supprimer
sur la seule base de cette correction.

Ces contrôles applicatifs ne constituent pas un bac à sable système. Ils ne
protègent pas contre un autre processus capable de remplacer des liens ou
fichiers entre leur vérification et leur ouverture. Les runs scellés conservent
leur isolation de processus et de système de fichiers.

## Vérifier une modification

```bash
python -m pytest -q tests/test_run_artifact_isolation.py tests/test_deliverable_tools.py tests/test_validators.py tests/test_intrusion_structure_validator.py
python -m pytest -q tests
```

Les tests d'isolation créent de vrais objets `Pipeline`, mais ne lancent ni
modèle, ni scénario, ni accès réseau. Ils couvrent les deux runs, les écritures
concurrentes, les noms attendus par phase, les tentatives rejetées et les chemins
qui sortent du dossier. La suite complète couvre aussi le rapport, les profils,
le worker et les règles de preuve existantes.

Validation locale du 15 septembre 2026 sous Python 3.12 : **14 tests d'isolation
réussis ; suite complète : 2 456 réussis, 1 ignoré, 3 avertissements de dépréciation,
aucun échec**. Les tests nécessitant des sockets localhost ont été autorisés ;
aucun scénario S1 ni appel au fournisseur UMONS n'a été lancé.
