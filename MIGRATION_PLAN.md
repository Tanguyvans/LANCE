# Plan de migration — Split en sous-repos

Découpage du monorepo en repos indépendants pour que le benchmark soit réutilisable
seul par d'autres projets, tout en gardant l'artefact de l'article intact.

## Décisions actées

- **Repo actuel `Tanguyvans/LANCE`** : reste **figé tel quel** (artefact cité dans l'article ACSAC 2026). On n'y touche pas.
- **Nouveaux repos** : créés **à côté**, en **fresh init** (pas d'historique préservé).
- **Structure cible** : une **organisation GitHub** (= l'équivalent d'un groupe GitLab) contenant **2 repos indépendants**.
- **Lien LANCE → benchmark** : via **git submodule** (apporte le scorer *et* les `ground_truth/`, zéro duplication ; la copie vendored est écartée car elle ferait diverger les YAML).
- **Licence** : laissée ouverte pour l'instant (à trancher avant publication — sans `LICENSE`, pas de réutilisation légale).

## Structure cible

```
Org GitHub "LANCE"  (le « groupe »)
├── IoTChainBench     ← le benchmark, réutilisable seul          [PRÊT]
└── LANCE             ← l'agent, submodule vers IoTChainBench     [À FAIRE]

Tanguyvans/LANCE      ← artefact figé de l'article (inchangé, en parallèle)
```

## Pourquoi pas un monorepo

Le besoin initial — « si un autre projet veut utiliser le bench c'est chiant » — impose
que le benchmark soit son propre repo. Un monorepo, même bien rangé, force à tout cloner.
GitHub n'ayant pas de sous-groupes imbriqués comme GitLab, l'**organisation** est l'analogue :
namespace commun, repos indépendants et clonables séparément.

---

## Étape 0 — IoTChainBench  [FAIT]

Repo autonome préparé à `/Users/gaspard/Desktop/Code Stage/IoTChainBench`
(git init + tout stagé, **pas encore commité**).

- `iotchainbench/` : package = `evaluator.py` (scorer) + `vuln_taxonomy.py` (seul couplage extrait) + `__init__.py` exposant `evaluate()`, `canonicalize()`.
- Données à la racine : `scenarios/`, `ground_truth/`, `topologies/`, `packs/`, `ansible/`, `tools/`, `docs/`.
- Packaging : `pyproject.toml` (`pip install -e .`, CLI `iotchainbench-eval`), `.gitignore`, `README.md` réécrit pour la réutilisation.
- Tests : `tests/test_evaluator.py` — **52/52 passent**.
- Seules modifs de code : imports (`from src.agent.vuln_taxonomy` → `from .vuln_taxonomy`).
- Vérifié : 0 secret en clair (vault chiffré uniquement), pas de venv/output. 86 fichiers, 1.6M.

**Reste à faire** : `git commit` puis créer le repo distant et push.

```bash
cd "/Users/gaspard/Desktop/Code Stage/IoTChainBench" && git commit -m "feat: initial IoTChainBench standalone benchmark"
```

## Étape 1 — Organisation GitHub

Créer l'org qui sert de groupe, puis y créer les 2 repos.

```bash
# L'org se crée via l'UI GitHub (gh ne crée pas d'org). Ensuite :
gh repo create <ORG>/IoTChainBench --public --source "/Users/gaspard/Desktop/Code Stage/IoTChainBench" --remote origin --push
```

## Étape 2 — Push IoTChainBench

Une fois l'org créée, pousser le repo déjà prêt (commande ci-dessus, ou `git remote add` + `git push`).

## Étape 3 — Repo LANCE avec submodule  [À FAIRE]

1. Partir d'une copie propre du contenu agent du repo actuel (sans le dossier `benchmarks/` ni `src/benchmark/`).
2. Ajouter IoTChainBench en submodule :
   ```bash
   git submodule add https://github.com/<ORG>/IoTChainBench.git external/iotchainbench
   ```
3. Adapter les 3 points d'import qui consomment le bench :
   - `src/agent/batch.py:47` — `from src.benchmark.evaluator import evaluate`
   - `src/api/routes/pipeline.py:246` — idem
   - `src/api/routes/runs.py` (×3, ~L139/199) — idem
   → remplacer par `from iotchainbench import evaluate` (+ ajuster `sys.path`/install du submodule).
4. Repointer les chemins `ground_truth/` vers le submodule.
5. Lancer la suite de tests LANCE pour valider.

Estimation : ~30 min. Direction de dépendance saine : LANCE dépend de IoTChainBench, jamais l'inverse.

## Étape 4 — Licence

Choisir une licence (MIT ou Apache-2.0 recommandés pour un artefact académique), ajouter le
fichier `LICENSE` dans les deux repos, et réactiver le champ `license` dans `pyproject.toml`.

## Étape 5 — Nettoyage final

- Vérifier qu'aucun secret ne traîne (vaults chiffrés OK).
- README de l'org pointant vers les 2 repos.
- Optionnel : badge / note de citation croisée entre LANCE et IoTChainBench.

---

## Points en attente de décision

- **Nom de l'org GitHub** (le « groupe »).
- **Licence** à choisir.
- **Étape 3** : confirmer qu'on part bien d'une copie du repo actuel pour le repo LANCE (le repo actuel restant figé).
