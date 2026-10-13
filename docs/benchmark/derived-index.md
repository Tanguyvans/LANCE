# Index dérivé des étiquettes du corpus

## Périmètre

`src/benchmark/derived_index.py` calcule, pour chaque vulnérabilité
attendue des vérités terrain, les axes expérimentaux utilisés pour tirer
les sets pilote et campagne et pour décrire la couverture du corpus.
Il ne modifie ni le catalogue (`benchmarks/catalog.yaml`, schéma strict)
ni les vérités terrain : sa sortie est un index annexe généré,
`benchmarks/labels/derived_index.json`, régénérable à l'identique.

## Fonctionnement

Entrées : `benchmarks/ground_truth/dev/scenario_*.yaml` et
`benchmarks/ground_truth/test/scenario_*.yaml`. Pour chaque entrée de
`vulnerabilities`, le script produit un enregistrement :

| Champ | Source | Règle |
| --- | --- | --- |
| `scenario_id`, `vuln_id`, `device`, `category`, `severity` | Vérité terrain | Copiés tels quels |
| `type` | `category` | `logique` si la catégorie est `broken_access_control` ou `auth_bypass`, sinon `signature` |
| `chainage` | `hop_depth` | Copié (entier, 0 par défaut si absent) |
| `surface`, `bruit`, `protocole` | Manifeste d'altération appliqué (option `--alterations`) | Défauts `base`, `none`, `connu` |

L'index contient en plus un résumé (nombre de scénarios et de failles,
répartitions par type, catégorie et profondeur) et l'empreinte SHA-256
de chaque fichier source, pour détecter toute dérive entre l'index
versionné et les vérités terrain.

Exemple d'enregistrement (scénario 15, faille d'autorisation) :

```json
{
  "scenario_id": "15",
  "vuln_id": "F11-IDOR@s15-fleet-api",
  "category": "broken_access_control",
  "type": "logique",
  "chainage": 1,
  "surface": "base",
  "bruit": "none",
  "protocole": "connu"
}
```

## Commandes

```bash
.venv/bin/python -m src.benchmark.derived_index
.venv/bin/python -m src.benchmark.derived_index --output /tmp/index.json
.venv/bin/python -m src.benchmark.derived_index --alterations alterations.json
```

Le fichier `--alterations` est un JSON `{ "<scenario_id>": {"surface": "...", "bruit": "...", "protocole": "..."} }`
décrivant les axes **réellement appliqués** au déploiement ; sans lui,
les défauts ci-dessus s'appliquent. Ne jamais y déclarer une altération
seulement prévue : l'index décrirait alors une expérience qui n'existe pas.

## Limites

- L'axe `type` est une déduction mécanique de la catégorie déclarée ;
  une catégorie mal classée dans une vérité terrain produit une
  étiquette fausse mais reproductible. La correction se fait dans la
  vérité terrain, jamais dans l'index généré.
- `protocole` vaut `connu` partout aujourd'hui : le corpus n'encode
  aucun protocole inconnu. C'est une limite du corpus, pas du script.
- Les axes `surface`/`bruit` ne valent que pour les instances dont
  l'altération a été réellement déployée et consignée.

Vérification : `tests/test_derived_index.py` couvre la déduction des
axes, le résumé, le remplacement par manifeste d'altération, et le
chargement inchangé du catalogue.
