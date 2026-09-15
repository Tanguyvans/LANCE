# V1 — Exécution et diagnostic

[Vue d’ensemble](README.md) · [Scénarios](scenarios.md) · [Évaluation](evaluation.md)

## Avant de lancer

Les runs avec scénario peuvent déployer des services volontairement vulnérables,
consommer un budget modèle et supprimer les machines du scénario au nettoyage.
Utiliser uniquement le laboratoire autorisé, isolé du réseau de gestion et
des systèmes de production. Ne pas lancer plusieurs scénarios concurrents en
supposant que l’isolation des fichiers suffit à isoler toute l’infrastructure.

Vérifier le fournisseur/modèle configuré, son endpoint, le profil, les budgets,
l’accès à Proxmox et les templates. La configuration machine relève du
[guide Ansible](../../../benchmarks/ansible/README.md) et de ses playbooks ; les
adresses et secrets ne doivent pas être recopiés dans cette documentation.
Utiliser l’environnement Python 3.12 validé pour le dépôt.

Le dashboard lance le pipeline sur la VM maître, pas sur le navigateur client.
Choisir un scénario de développement, le modèle voulu et explicitement `full`
pour une campagne full. Consigner les paramètres et le commit effectivement exécuté.

## Commandes depuis la racine du dépôt

Ces exemples supposent que **`AGENT_PROVIDER` et `AGENT_MODEL` sont déjà configurés**
pour un fournisseur compatible avec le CLI. Sans fournisseur, le CLI refuse
le lancement ; il n’y a pas de remplacement implicite.

```bash
# Un run de développement, en full
python -m src.agent --scenario 1 --split dev-public --execution-profile full

# Un lot de développement, séquentiel
python -m src.agent --batch dev --execution-profile full

# Test seulement après gel de la configuration
python -m src.agent --batch test --execution-profile full
```

Le CLI a sa propre liste de fournisseurs autorisés ; un nom personnalisé du
registre du dashboard n’est pas automatiquement accepté par `--provider`.
Vérifier [le parseur CLI](../../../src/agent/__main__.py) avant de transposer une
configuration du dashboard. Ne pas changer de modèle ou de profil pour contourner
silencieusement une panne fournisseur.

Un groupe explicite incompatible avec le scénario est refusé. `--split auto`
suit le catalogue. `--phases` sert à des exécutions ciblées, pas à prétendre avoir
validé le pipeline complet.

## Cycle de vie

Le pipeline prépare le scénario avec `03_deploy_scenario.yml`, injecte les failles
avec `04_inject_vulns.yml`, puis exécute `06_verify.yml` avant les phases.
Un échec de préparation bloque la suite. Le nettoyage `99_teardown.yml` est tenté
à la finalisation lorsque le pipeline possède le scénario et que le nettoyage
automatique est activé, y compris après un échec.

Les six phases partagent le même moteur. Les sauvegardes sont validées avant
d’être admises comme livrables ; les tentatives rejetées restent dans `.attempts/`.
Un rapport enregistré ou une validation de format réussie ne démontre ni une
intrusion réussie ni une exécution intégralement terminée.

## Statut et score sont indépendants

| Statut | Lecture |
| --- | --- |
| `completed`, affiché `done` | Phases terminées selon le contrat d’exécution ; pas une garantie de couverture parfaite |
| `partial` | Résultat partiel, par exemple phase partielle, workers en erreur, nettoyage échoué ou consommation incomplète |
| `failed` | Cause terminale d’échec, état de phase non admis ou défaut d’intégrité des preuves |
| `blocked` | Prérequis empêchant la poursuite |
| `stopped` | Arrêt demandé/interruption reconnue |
| `budget_exceeded` | Budget épuisé |
| `skipped` | Phases ignorées, pas une campagne complète réussie |

Le statut vient des résultats des phases, de la cause terminale et de la
finalisation ; il n’est pas déduit de la présence d’un rapport. Un échec prioritaire
ne devient pas `partial` simplement parce que certaines phases ont réussi.
Le détail des réserves complète ce statut sans remplacer sa cause.

**Un run `failed` peut donc afficher un bon F1** : les artefacts disponibles
restent évaluables, mais une autre phase ou la finalisation a échoué. Inversement,
`done` ne veut pas dire « toutes les hypothèses confirmées ». Voir
[results.py](../../../src/agent/results.py), [pipeline.py](../../../src/agent/pipeline.py)
et [la projection API des runs](../../../src/api/routes/runs.py).

## Où chercher la cause ?

Dans le dossier du run sous `output/agent/`, selon les fichiers effectivement produits :

| Fichier | Rôle |
| --- | --- |
| `run_meta.json` | Paramètres, contrats, résultats de phases, statut, nettoyage, intégrité et consommation |
| `run_error.json` | Exception terminale, phase active et chaîne causale filtrée |
| `provider_events.jsonl` | Métadonnées des requêtes, réponses, reprises et sauvegardes du fournisseur |
| `tool_calls.jsonl` | Observations d’outils et références utilisées par les contrôles de preuve |
| `03_vuln_analysis_raw.json` / `03_vuln_analysis.json` | Hypothèses avant/après filtrage |
| `04_exploitation.json` | Vérifications et déclarations Phase 4 |
| `05_intrusion.json` | Livrable d’intrusion déclaré par le modèle, pas preuve autonome |
| `06_report.md` | Synthèse destinée au lecteur |
| `cost_summary.json` | Tokens, tours, durées et coûts mesurés/estimés disponibles |
| `ansible_*.log` | Sorties de préparation et de nettoyage |

Commencer par la cause terminale et la phase, puis les événements fournisseur
ou les traces d’outils correspondantes. `provider_events.jsonl` est un diagnostic
de métadonnées, pas un journal de preuves ; il n’est pas exposé comme livrable au
modèle. Une erreur d’écriture peut laisser certains diagnostics absents.

Exemples d’interprétation :

- **Connection refused / Connection error** : vérifier la chaîne causale et la
  disponibilité du service depuis la VM maître ; cela ne prouve pas que le modèle
  est trop petit ou que le scénario est fautif.
- **Analyse partielle** : identifier les appareils en échec et leurs livrables rejetés.
- **Vérification indéterminée** : lire la propriété, la trace attribuée et la raison
  du rejet ; une tentative infructueuse ne réfute pas la faille.
- **Nettoyage échoué** : vérifier les ressources restantes avant un nouveau run.

Le journal d’outils peut contenir des données du laboratoire : ne pas publier
les artefacts bruts sans revue des informations sensibles.

## Consommation et validation

Conserver tokens, temps et coûts même lorsque les scores sont indisponibles.
Le résumé distingue le temps écoulé (`wall_clock_duration_s`) de la somme des
durées des agents (`total_agent_duration_s`) : avec des workers parallèles,
ces valeurs ne sont pas interchangeables.
Un coût estimé n’est pas une facture fournisseur. Une mesure absente reste inconnue,
pas gratuite. Les ratios coût/tours par VP utilisent les **VP finaux** et restent
indéfinis si aucun VP final n’est obtenu.

Avant publication d’une modification : tests positifs et négatifs ciblés, suite
complète, puis essai contrôlé de développement sur le mini-PC. Depuis la racine :

```bash
python -m pytest --rootdir=. -q tests --tb=short
```

Les tests locaux ne prouvent pas la disponibilité de l’endpoint réel ni la bonne
injection du laboratoire. Après un essai S1, contrôler préparation, phases, preuves,
statut et nettoyage avant d’étendre la campagne. Pour les limites de concurrence
et les tests d’isolation : [livrables par run](../../run-artifacts.md).
