# Boucle d’apprentissage à partir des erreurs

Le pipeline principal (`/home/tanguy/LANCE`) extrait les erreurs des runs
`dev-public`. Le workspace Leo ne reçoit que les candidats explicitement
acceptés ; il ne contient aucune logique d’orchestration ou d’évaluation.

## Flux

1. L’évaluateur strict compare les findings à la vérité terrain publique.
2. Le mineur produit des candidats `false_negative`, `false_positive` et
   `severity_mismatch`.
3. Les candidats sont dédupliqués, versionnés et placés en statut `pending`.
4. Une revue humaine les marque `accepted` ou `rejected`.
5. Seuls les candidats `accepted` peuvent être exportés vers Leo.
6. Le convertisseur route les corrections validées vers le dataset SFT de
   l’expert et de la phase concernés.

Les runs `test-public` (S20–S29) et `eval-sealed` sont refusés à partir du split,
de l’identifiant de scénario et du catalogue de confiance. Les runs custom sont
exclus par défaut. Cette barrière empêche qu’un résultat de test held-out soit
réinjecté accidentellement dans le harness.

## Commandes

Importer les runs complets et non scellés d’une instance LANCE distante :

```bash
python -m src.learning.remote_runs \
  --base-url http://nato-master:8501 \
  --destination output/imported/nato-master-YYYY-MM-DD
```

Pour limiter l’import à une famille de modèles :

```bash
python -m src.learning.remote_runs \
  --base-url http://nato-master:8501 \
  --model deepseek-v4-flash \
  --destination output/imported/nato-master-deepseek-YYYY-MM-DD
```

L’import ne copie qu’une liste fermée d’artefacts utiles, refuse les runs
incomplets ou scellés, et inscrit le modèle, la date, le commit source, le score
distant ainsi que le SHA-256 de chaque fichier dans
`remote_snapshot_manifest.json`.

Comparer chaque commit source au pipeline, à l’évaluateur et à la vérité terrain
actuels :

```bash
python -m src.learning.git_compatibility \
  output/imported/nato-master-YYYY-MM-DD
```

Le minage utilise volontairement l’évaluateur `strict-v2` actuel. Le manifeste
conserve les deltas Git pour distinguer une erreur du modèle d’une éventuelle
évolution de la logique d’évaluation.

Créer un corpus de revue :

```bash
python -m src.learning.error_mining mine \
  --runs-root output/agent \
  --output output/learning/feedback-YYYY-MM-DD
```

Limiter l’extraction à certains runs :

```bash
python -m src.learning.error_mining mine \
  --runs-root output/agent \
  --run-id RUN_ID_1 \
  --run-id RUN_ID_2 \
  --output output/learning/feedback-YYYY-MM-DD
```

Valider l’intégrité :

```bash
python -m src.learning.error_mining validate \
  output/learning/feedback-YYYY-MM-DD
```

Accepter ou rejeter un candidat :

```bash
python -m src.learning.error_mining review \
  output/learning/feedback-YYYY-MM-DD \
  lf-IDENTIFIANT \
  --status accepted \
  --reviewer tanguy \
  --notes "Vérifié dans les traces"
```

Exporter uniquement les corrections acceptées vers le dépôt de datasets Leo :

```bash
python -m src.learning.error_mining export \
  output/learning/feedback-YYYY-MM-DD \
  --destination /home/leo/LANCE/data/finetuning/vuln/reviewed_feedback/feedback-YYYY-MM-DD
```

L’export échoue si aucun candidat n’a été accepté ou si la destination existe
déjà. `--overwrite` doit être fourni explicitement pour remplacer une version.

## Conversion SFT multi-expert

Le convertisseur accepte désormais deux familles de feedback :

- `finding_correction`, compatible avec le minage vuln existant ;
- `deliverable_correction`, format générique pour corriger un livrable de
  `secretary`, `recon`, `vuln` ou `exploit`.

Les couples expert/phase autorisés suivent la pipeline réelle :

| Expert | Phases | Livrables usuels |
| --- | --- | --- |
| `secretary` | 1, 6 | `01_graph_analysis.md`, `06_report.md` |
| `recon` | 2 | `02_recon.md` |
| `vuln` | 3 | `03_device_*.json` |
| `exploit` | 4, 5 | `04_exploits/**/*.json`, `05_intrusion.json` |

Un candidat générique accepté suit ce schéma minimal :

```json
{
  "candidate_id": "feedback-recon-001",
  "task": "deliverable_correction",
  "expert": "recon",
  "phase": 2,
  "input": {
    "draft_deliverable": "contenu avant correction",
    "evidence": ["éléments observés dans le run"]
  },
  "target": {
    "expected_deliverable": {
      "filename": "02_recon.md",
      "content": "contenu corrigé et validé"
    }
  },
  "review": {
    "status": "accepted",
    "reviewer": "tanguy",
    "notes": "raison de la correction"
  },
  "occurrences": [{"run_id": "RUN_ID"}]
}
```

`content` peut être une chaîne, un objet JSON ou une liste. Le convertisseur
sérialise les objets/listes et refuse les chemins absolus, les traversées `..`,
les préfixes incompatibles avec la phase et les couples expert/phase invalides.

Convertir un corpus ne contenant qu’un expert :

```bash
python -m src.learning.sft_feedback \
  --candidates accepted_candidates.jsonl \
  --runs-root /home/leo/LANCE/data/finetuning/ressources/training \
  --expert vuln \
  --output /home/leo/LANCE/data/finetuning/vuln/vuln_feedback_accepted.jsonl
```

Router automatiquement un corpus mixte vers un fichier par expert :

```bash
python -m src.learning.sft_feedback \
  --candidates accepted_candidates.jsonl \
  --runs-root /home/leo/LANCE/data/finetuning/ressources/training \
  --output-dir output/learning/sft-by-expert
```

Les sorties sont nommées `<expert>_feedback_accepted.jsonl`. Les corrections de
findings utilisent l’artefact complet du run lorsqu’il est disponible et le
snapshot embarqué dans le candidat comme fallback pour les runs historiques.

## Attribution spécialisée des erreurs

Le minage découvre récursivement les répertoires contenant `scenario_meta.json`, y compris les groupes de runs organisés par modèle. Il utilise le schéma `1.1` et attribue désormais la correction à la
première phase qui dispose d’un signal causal vérifiable :

- `recon_correction` (phase 2) : un faux négatif dont l’IP attendue est absente
  de `02_recon.md`, ou dont le service attendu n’est pas couvert autour de cette
  cible. Le faux négatif correspondant n’est alors pas dupliqué dans `vuln` ;
- `exploit_correction` (phase 4) : un statut hors contrat, ou un verdict positif
  associé à un faux positif et soutenu uniquement par une preuve vide ou
  explicitement négative. Une découverte absente du benchmark mais accompagnée
  d’une preuve directe reste côté `vuln` pour revue humaine ;
- `secretary_correction` (phases 1 et 6) : omission d’un nœud déclaré dans
  l’analyse topologique, ou rapport final désaligné avec l’évaluation revue ;
- `finding_correction` (phase 3) : les erreurs de finding qui ne sont pas
  expliquées par une omission de couverture en phase 2.

Le manifeste expose `counts_by_expert`, `counts_by_task` et
`counts_by_error_type`. Tous les candidats restent `pending` : l’attribution
automatique ne remplace jamais la revue humaine.

Exemple de contrôle de la répartition :

```bash
jq '{counts_by_expert, counts_by_task, counts_by_error_type}' \
  output/learning/feedback-YYYY-MM-DD/manifest.json
```

Après revue et export, un corpus contenant plusieurs experts peut être converti
en une seule commande avec `sft_feedback --output-dir`. Chaque correction sera
écrite dans le JSONL de son expert au lieu d’être ajoutée au dataset `vuln`.
