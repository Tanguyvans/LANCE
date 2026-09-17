# Livrables : un dossier explicite par run

## À retenir

Créer un run B ne doit jamais rediriger les lectures, écritures ou validations
du run A. Le pipeline reste unique, avec les mêmes dossiers par phase.
Cette correction n'ajoute ni gestionnaire global de contexte ni nouvelle classe.

Trois règles suffisent :

1. `Pipeline.run_dir` désigne le dossier de ce run et reste fixe pendant celui-ci.
2. Les outils et validateurs reçoivent ce dossier explicitement.
3. Le nom du livrable attendu appartient à la transaction de la phase, pas au processus.

## Appels au modèle : Séquentiel

Dans **Modèles → fournisseur**, le réglage « Appels au modèle » sélectionne
**Séquentiel** (par défaut) ou **Parallèle** (comportement antérieur).
Il est indépendant de full/compact et du mode blind. La migration des fournisseurs
existants sélectionne Séquentiel ; les prochains clients utilisent ce réglage.

En séquentiel, un verrou par origine HTTP (hôte et port, tous modèles confondus)
partage la capacité entre les runs et le juge du même processus serveur.
Les outils ne tiennent pas ce verrou. L'attente est interruptible pour le pipeline,
et les limites globales de phase restent applicables pendant l'attente.
Le timeout HTTP ne commence qu'après admission. Les journaux distinguent
`queue_wait_s` de `elapsed_s` pour les appels du pipeline.

Limites : ce verrou n'est pas distribué entre plusieurs processus, machines ou
clients externes d'Ollama. Utiliser une seule instance serveur pour ce réglage.
Les alias d'une même origine doivent tous être configurés en séquentiel ;
un fournisseur configuré en parallèle contourne explicitement cette protection.
Des adresses différentes vers le même serveur ne sont pas automatiquement identifiées.
Ce mode ne garantit pas l'absence de timeout et ne modifie ni les reprises,
ni les preuves, ni les scores. Vérifier son effet avec un nouveau run contrôlé.

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
- Les outils masquent la vérité terrain, `provider_events.jsonl` et les
  internes du laboratoire (`scenario_meta.json`, `run_meta.json`,
  `run_error.json`, `evaluation.json`, `evaluation_summary.json`, `ansible_*.log`) : voir la section
  « Visibilité des internes du laboratoire » ci-dessous.
- Les appels d'outils conservent leur journal, leurs références et leurs contrôles.
- Une structure valide ne constitue pas une preuve de faille, d'accès ou de pivot.
- Full/compact, budgets, scores et versions des contrats d'évaluation sont inchangés.

## Visibilité des internes du laboratoire

Les journaux Ansible (`ansible_<playbook>.log`), `scenario_meta.json` et les
autres sidecars de contrôle (`run_meta.json`, `run_error.json`,
`evaluation.json`, `evaluation_summary.json`) restent sur disque pour le
diagnostic opérateur et l'API, qui les lisent par chemin direct.

Côté agent, la frontière est appliquée dans le code, pas dans les prompts :

- `agent/artifacts.py` (`is_private_agent_artifact`) refuse les noms exacts
  et toute la classe `ansible_*.log`, sans énumérer les playbooks ;
  `is_private_agent_artifact_path` applique la même règle à la cible résolue,
  ce qui bloque les alias par lien symbolique.
- `agent/tools/deliverable.py` refuse ces fichiers en lecture, écriture et
  listage ; `aggregate_device_results` les ignore silencieusement pour ne pas
  confirmer leur existence.
- `agent/core/runner.py` (`previous_deliverables`) réutilise le même prédicat
  pour que l'invite ne propose jamais ce que les outils refusent.

Les livrables légitimes des phases (`01_*`, `02_*`, `03_device_*`,
`05_intrusion_context.json`, …) restent lisibles. Aucun score ni vérité
terrain n'est modifié par cette frontière.

## Diagnostic des erreurs de vérification

Chaque test de `04_exploitation.json` peut inclure `execution_errors` : étape
interrompue, catégorie (`timeout` ou `exception`), classe de l'exception et code
HTTP éventuel. Ces données proviennent du code d'exécution, jamais du verdict
ou du texte soumis par le modèle. Les messages bruts ne sont pas recopiés dans
ce champ, car ils peuvent contenir des identifiants ou des charges de requête.

Ces diagnostics sont enregistrés même si une preuve valide a été obtenue avant
l'erreur, ou par le mécanisme de secours compact. Ils ne changent ni le statut
issu des preuves, ni leur niveau, ni le score. Une nouvelle invocation de la
phase remet ce diagnostic à zéro ; les anciens runs ne sont pas migrés.

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
python -m pytest -q tests model_training/tests
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
