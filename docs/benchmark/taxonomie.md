# Taxonomie : appareil, architecture, faille

## Périmètre

`src/benchmark/taxonomy.py` classe chaque scénario public et chaque faille
attendue selon trois axes : la classe d'**appareil**, l'**architecture**
réseau et la **famille de faille**. Le vocabulaire et les correspondances
sont définis dans `benchmarks/taxonomy.yaml`. Le module ne modifie ni le
catalogue, ni les scénarios, ni les topologies, ni les vérités terrain, ni
Ansible. Sa sortie, [couverture-axes.md](couverture-axes.md), est générée et
régénérable à l'identique : conformité des architectures et matrices de
couverture. L'index détaillé par scénario et par faille n'est écrit en JSON
que sur demande (`--json`) ; il n'est pas versionné tant qu'aucun outil ne le lit.

L'origine et la suite de ce travail sont décrites dans la
[recherche sur la structuration du benchmark](../../research/2026-10-23-structuration-benchmark/README.md).

## Règles

| Axe | Source dans le dépôt | Règle |
| --- | --- | --- |
| Appareil | `role` des services (topologies) et des failles (vérités terrain) | `roles.<role>.device` dans la taxonomie. Les protocoles viennent de `tool_registry.ROLE_SERVICES` ; la taxonomie ne les donne que pour les rôles absents de ce registre. |
| Architecture visée | `topology` du scénario | `architectures.<topologie>` dans la taxonomie : l'intention du scénario. |
| Architecture mesurée | Champs `ip`, `secondary_ip`, `no_gateway` de la topologie | Calculée, voir ci-dessous. |
| Faille | `category` de chaque faille des vérités terrain | `weaknesses.<catégorie>` dans la taxonomie. |

**Mesure de l'architecture.** Un segment est un sous-réseau /24 du routeur ou
d'un service. Un service doté d'un `secondary_ip` relie deux segments : c'est
un relais. La profondeur de relais est le plus grand nombre de relais entre
le segment du routeur et un service `no_gateway`. Les classes mesurées sont
les suivantes :

| Mesure | Classe |
| --- | --- |
| un seul segment | `flat` |
| plusieurs segments, aucun service isolé derrière un relais | `segmented` |
| profondeur de relais 1 | `gateway` |
| profondeur de relais ≥ 2 | `multi_hop` |

Un scénario est **conforme** si sa classe mesurée réalise sa classe visée.
`star` exige une isolation de type passerelle (feuilles joignables seulement
par le nœud central). `local_cloud` exige au moins deux segments. Ces deux
règles sont provisoires : elles n'ont pas encore de signature structurelle
propre.

## Commandes

```bash
.venv/bin/python -m src.benchmark.taxonomy                     # régénère la page de couverture
.venv/bin/python -m src.benchmark.taxonomy --check             # échoue si la page versionnée est périmée
.venv/bin/python -m src.benchmark.taxonomy --json /tmp/axes.json  # index détaillé, non versionné
```

Après toute modification d'un scénario, d'une topologie, d'une vérité terrain
ou de la taxonomie, régénérer puis committer la page.

## Garde-fous

`tests/test_benchmark_taxonomy.py` vérifie :

- que tout rôle, toute topologie utilisée et toute catégorie présente dans le
  corpus est classé, sans quoi `build_index` lève `TaxonomyError`. Un nouveau
  scénario ne peut donc pas entrer sans être classé ;
- que la taxonomie ne contient aucune entrée qui ne correspond plus au corpus ;
- les règles de mesure sur des topologies synthétiques ;
- que la page versionnée est à jour et que les empreintes de sources de
  l'index correspondent aux fichiers.

## Limites

- La mesure lit la topologie publique, pas l'inventaire Ansible
  (`benchmarks/ansible/group_vars/all/main.yml`), qui décrit les services
  séparément ; ce module ne vérifie pas leur concordance. Côté Ansible, seul
  S13 reçoit des zones de pare-feu VLAN (`04_inject_vulns.yml`). La mesure ne
  prouve ni le filtrage effectif sur nato, ni l'état des machines.
- Les familles de failles reprennent la `category` déclarée. Une catégorie
  mal choisie dans une vérité terrain donne une étiquette fausse mais
  reproductible. En particulier, une partie des failles `misconfiguration`
  (MQTT anonyme, FTP anonyme…) relève en fait de l'authentification. La
  correction se fait dans la vérité terrain, jamais dans l'index.
- Les comptes portent sur les 29 scénarios officiels. S1h et S4h figurent
  dans l'index avec `official: false`, mais sont exclus des matrices.
