# Reproductions locales de la revue du 29 septembre 2026

Ces scripts caractérisent la révision
`45c8dab892ecb4e5f513813387090e0cded1b85d`. Ils lisent les définitions ou appliquent
les fonctions du logiciel à des traces synthétiques. Ils ne lancent ni outil
réseau, ni modèle, ni laboratoire. `probe-evaluation.py` utilise un répertoire
temporaire automatiquement nettoyé. Python 3.12 et les dépendances du projet
sont nécessaires ; l'inventaire requiert PyYAML.

Depuis la racine :

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3.12 benchmarks/experiments/research-review/inventory.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3.12 benchmarks/experiments/research-review/probe-evaluation.py
python3.12 -B benchmarks/experiments/research-review/probe-context.py
```

- `inventory.py` vérifie les empreintes du sidecar, fusionne les contrats et compte les définitions, pas la couverture réellement déployée.
- `probe-evaluation.py` expose trois contre-exemples : taux de tentative ambigu, mise à jour signée et texte d'aide pris pour exécution. Le score complet n'est pas simulé.
- `probe-context.py` caractérise cinq transformations : perte du milieu, omissions, coupe des observations, dernier bloc surchargé et limites d'une heuristique de mémo.

Les assertions du dernier script décrivent des défauts actuels, **pas le
comportement souhaité après correction**. Elles ne remplacent pas des tests de
régression exprimant le contrat corrigé. Toute évolution exige de relire les
probes et leurs résultats ; leur succès ne valide aucune performance LLM.

Résultats, versions et limites : [validation de la recherche](../../../research/2026-09-27-agent-vs-automation/validation.md).
Analyses : [benchmark](../../../research/2026-09-29-benchmark-coverage/analysis.md),
[contexte](../../../research/2026-09-29-context-scalability/analysis.md),
[apport LLM](../../../research/2026-09-27-agent-vs-automation/analysis.md).

## Inventaire statique V2

`coverage_snapshot.py` reproduit les décomptes et empreintes du
[plan V2](../../../research/2026-10-12-recentrage-corpus/README.md), sans réseau,
modèle ou déploiement. Ses assertions contrôlent la partition des 44 fiches,
les noms, relations, dispositions IoT et la conservation des contrats sélectionnés.
Les statuts de qualification restent dans le plan ; les empreintes seules ne
valident pas un résultat expérimental.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3.12 benchmarks/experiments/research-review/coverage_snapshot.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3.12 benchmarks/experiments/research-review/coverage_snapshot.py --check research/2026-10-12-recentrage-corpus/coverage-snapshot.json
```

Le champ `git_commit` donne la base Git au moment de l’inventaire ; les SHA-256
décrivent les octets lus, y compris les modifications en cours. `--check` garde
cette base déclarée et recalcule les empreintes/contenus : il reste reproductible
après le commit de consolidation et ne réécrit aucun fichier.
