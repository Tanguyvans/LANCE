# Index dérivé des étiquettes

`derived_index.json` est **généré** par
`python -m src.benchmark.derived_index` depuis les vérités terrain de
`benchmarks/ground_truth/`. Ne pas l'éditer à la main : corriger la
vérité terrain ou la règle de dérivation, puis régénérer.

Fonctionnement, champs et limites :
[docs/benchmark/derived-index.md](../../docs/benchmark/derived-index.md).

# Index de la taxonomie

`taxonomy_index.json` est **généré** par `python -m src.benchmark.taxonomy`
depuis les assets publics et `benchmarks/taxonomy.yaml`, avec la page
`docs/benchmark/couverture-axes.md`. Ne pas l'éditer à la main.
Règles et limites : [docs/benchmark/taxonomie.md](../../docs/benchmark/taxonomie.md).
