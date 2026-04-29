# P1 — Implémentation MHR — terminée

> Phase 1 du `paper/plan_cai_comparison.md`. Date : 29 avril 2026.

## Modifications du code

### `src/benchmark/evaluator.py`

1. **`MatchResult`** — nouveau champ `gt_hop_depth: int = 0` (rétrocompatible).
2. **`EvaluationResult`** — nouveaux champs :
   - `mhr_1`, `mhr_2`, `mhr_3` : `float | None` (None si pas de GT à cette profondeur)
   - `gt_at_depth: dict` : histogramme `{"0": 5, "1": 3, ...}`
   - `tp_at_depth: dict` : histogramme matched
3. **`compute_mhr(matches, k)`** — nouvelle fonction publique. Retourne `None` si aucun GT à profondeur ≥ k, sinon ratio TP/GT (cumulatif `>= k`).
4. **`_depth_histograms(matches)`** — helper interne pour les histogrammes par profondeur.
5. **`evaluate()`** — câblage : lit `gt.get("hop_depth", 0)` dans la création de `MatchResult`, calcule MHR_1/2/3 + histogrammes après le compute des métriques classiques.
6. **`print_report()`** — nouvelle section `MULTI-HOP REACH` affichée après `PRIMARY METRICS`.

### `tests/test_evaluator.py`

- 5 tests unitaires `compute_mhr` (None, full recall, partial cumulative, zero match, string coercion)
- 5 tests d'intégration `evaluate` (flat scenario, multi-hop partiel, asdict round-trip, propagation gt_hop_depth, default 0 si manquant)

## Validation

```
$ python3 -m pytest tests/test_evaluator.py -v -p no:pytest_ethereum -p no:web3
============================== 52 passed in 0.19s ==============================
```

42 tests existants (passent toujours) + 10 nouveaux tests MHR.

## Vérification fonctionnelle sur un vrai run

```
$ python3 -m src.benchmark.evaluator \
    --run-dir output/agent/2026-03-20_151458 \
    --ground-truth benchmarks/ground_truth/scenario_1.yaml
...
  MULTI-HOP REACH
    MHR_1 (vulns at depth >= 1) : N/A
    MHR_2 (vulns at depth >= 2) : N/A
    MHR_3 (vulns at depth >= 3) : N/A
    Breakdown by depth          : d0: 0/12
```

Comportement attendu : scenario_1 est plat, donc MHR_1/2/3 = N/A et breakdown affiche `d0: TP/GT`.

## Annotation `hop_depth`

- **`scenario_1.yaml`** : 12/12 vulns annotées `hop_depth: 0` (réseau plat). Validé via parsing YAML.
- **Convention documentée** : `paper/notes/hop_depth_convention.md`.
- **Reste à annoter** : scenarios 2 à 7 (P2.2 du plan CAI).

## Backward compatibility

- GT YAML sans `hop_depth` → fallback `int(gt.get("hop_depth", 0))` → traité comme depth 0.
- Tests existants (qui n'utilisaient pas hop_depth) continuent de passer.
- `evaluator_score.json` produit a maintenant les champs MHR ; les consommateurs anciens (dashboard) ignorent simplement ces champs supplémentaires.

## Diff résumé

```
src/benchmark/evaluator.py        | +56 lignes / 0 supprimées
tests/test_evaluator.py           | +156 lignes / 4 modifiées
benchmarks/ground_truth/scenario_1.yaml | +12 lignes (annotation hop_depth)
paper/notes/hop_depth_convention.md     | nouveau (165 lignes)
paper/notes/p1_mhr_implementation.md    | nouveau (ce fichier)
```

## Prochaines étapes (J0+1)

- **P2.2** : annoter `scenario_{2..7}.yaml` selon la convention (~30 min au total)
- **P2.3** : audit cohérence (script `paper/notes/audit_hop.py`)
- **P3** : re-run pipeline complet sur scenario_3 pour valider que MHR remonte des chiffres significatifs
- **P4** : code CAI dans `scripts/baselines/cai/`
