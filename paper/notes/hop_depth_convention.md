# Convention `hop_depth` pour la GT — règle d'annotation

> Référence pour annoter `benchmarks/ground_truth/scenario_*.yaml`.
> Objectif : produire une métrique MHR (Multi-Hop Reach) **objective**, défendable face à un reviewer.

---

## 1. Définition formelle

> **`hop_depth(vuln)` = le nombre minimum de devices que l'attaquant doit compromettre (gain shell ou credentials) avant de pouvoir détecter et exploiter `vuln` sur son device cible.**

**Point de départ** (l'attaquant, hop_depth implicite −1) :
- Master VM `192.168.100.200` sur vmbr1, équivalente à un attaquant déjà sur le LAN du benchmark.
- Cela reflète le scénario "attaquant interne ayant gagné un point d'entrée dans le réseau cible" — pas un scan internet brut.

**Compromis :**
- `0` = directement joignable depuis le point de départ (réseau plat ou device exposé)
- `1` = derrière 1 device qu'il faut compromettre d'abord (firewall, jump host, gateway)
- `2` = derrière 2 pivots (zone OT accessible uniquement via IT)
- `3+` = profondeur croissante

---

## 2. Règle de calcul (objective, vérifiable)

`hop_depth` est calculé sur le **graphe de reachability firewall-enforced** :

1. **Nœuds** = devices du scénario.
2. **Arête A → B** existe ssi : *le compromis de A donne un accès réseau (ou cred) au port de service de B*.
3. **`hop_depth(vuln on B)`** = longueur du plus court chemin depuis le point de départ de l'attaquant jusqu'à B (en nombre de nœuds compromis sur le chemin, pas inclus B lui-même).

### Critères pratiques pour décider

Pour chaque vuln, se poser ces questions dans l'ordre :

| Question | Si OUI | Si NON |
|---|---|---|
| L'IP est-elle joignable depuis `192.168.100.200` sur son port de service sans firewall bloquant ? | `hop_depth = 0` | passer à Q2 |
| Le firewall qui bloque tombe quand on compromet un seul device (router OpenWrt, jump host) ? | `hop_depth = 1` | passer à Q3 |
| Faut-il compromettre N devices en chaîne (ex : router + jump_host pour atteindre OT) ? | `hop_depth = N` | reposer la Q1 plus précisément |

**Source d'information :**
- Topologie YAML du scénario (`topology` section)
- Règles iptables/firewall des playbooks Ansible (`benchmarks/ansible/playbooks/03_deploy_scenario.yml` + scénario-spécifique)
- Configuration OpenWrt par scénario (NAT, port forwarding, ACL)

---

## 3. Exemples annotés par scénario

### Scenario 1 — Réseau plat (S1)
```yaml
topology: "Pas d'isolation entre les services"
attaquant → tous devices joignables directement
```
→ **Toutes les vulns à `hop_depth: 0`**.
MHR_1 = MHR_2 = MHR_3 = `None` (métrique non applicable, scénario flat).

### Scenario 2 — Gateway exposée (S2)
```yaml
topology: gateway intermédiaire qui mediate le back-end
- web (DMZ) : exposé directement
- mqtt (DMZ) : exposé directement
- iot-gw : exposé directement
- db (interne) : seulement joignable via gateway
- jump (interne) : seulement joignable via gateway
```
→ web/mqtt/iot-gw vulns à `hop_depth: 0`
→ db/jump vulns à `hop_depth: 1` (gateway compromise requise)

### Scenario 3 — Réplique NATO Lab (S3)
3 zones logiques selon ACL OpenWrt :
- Admin/IT (joignable directement) : depth 0
- Services IoT métier (rpi5, jetson, etc.) : depth 1
- OT/Controllers (lorsqu'isolés derrière jump host) : depth 2

### Scenario 4 — Réseau segmenté ICS/SCADA (S4)
Architecture la plus profonde du benchmark :
- admin/webapp/mqtt (zone IT) : `hop_depth: 0`
- lora-gw : `hop_depth: 1` (passerelle vers OT)
- plc/hmi/historian (zone OT) : `hop_depth: 2`

### Scenario 5 — Smart Building (S5)
Hub-and-spoke :
- mqtt/web (frontend) : `hop_depth: 0`
- access-ctrl/hvac (back-end) : `hop_depth: 1`
- caméras/nvr (selon firewall) : `hop_depth: 0` ou `1` selon config

### Scenario 6 — Domotique centralisée (S6)
- hub central : `hop_depth: 0`
- mqtt/db/cam/web derrière le hub : `hop_depth: 1` ssi le hub mediate

### Scenario 7 — Edge-Cloud pivot (S7)
- edge-gw : `hop_depth: 0`
- edge-mqtt, edge-compute : `hop_depth: 0` (zone edge)
- cloud-api, cloud-db : `hop_depth: 1` (seul edge-gw ponte vers cloud)

---

## 4. Cas limites et règles de tie-break

### Cas A — Plusieurs chemins de compromission de longueurs différentes
→ Prendre le **minimum**. Une vuln joignable par 2 chemins (1 hop ou 3 hops) compte comme `hop_depth: 1`.

### Cas B — Vuln "auth-chain" (mot de passe trouvé sur device A nécessaire pour exploiter device B)
→ Si B est *réseau-joignable* depuis le point de départ mais nécessite un cred trouvé sur A : **`hop_depth: 1`**. La métrique mesure "combien de hops d'attaque sont nécessaires", peu importe que ce soit du firewall ou de l'auth.

### Cas C — Le router OpenWrt lui-même
Toujours `hop_depth: 0` — c'est le point d'entrée du benchmark, attaquant le compromet en premier.

### Cas D — Vuln sur point d'entrée WAN forwardé
Si OpenWrt expose un port (port forwarding WAN admin), le service derrière reste à `hop_depth: 0` — il est *directement joignable* depuis l'attaquant.

### Cas E — Doute → faire le minimum (annotation conservative)
Annoter le `hop_depth` le plus bas plausible. Cela rend l'évaluation **plus stricte** pour notre pipeline (qu'on est censés démontrer fort sur multi-hop) et **plus généreuse** pour les baselines (qui sont censées échouer à profondeur > 0).

---

## 5. Vérification automatique (recommandé avant freeze GT)

Script à écrire en P2.3 du plan : `paper/notes/audit_hop.py`

Pour chaque scenario YAML :
1. Charger la topologie + iptables des playbooks Ansible
2. Construire le graphe de reachability
3. Pour chaque vuln, vérifier que `hop_depth` annoté = shortest path computed
4. Reporter incohérences

→ Donne un audit objectif et reproductible.

---

## 6. Synthèse pour le papier (§4 ou §6)

> *"Each vulnerability in the benchmark is annotated with a `hop_depth` integer derived from the firewall-enforced reachability graph: `hop_depth = 0` means directly reachable from the attacker entry point, `hop_depth = k` means k devices must be compromised on the shortest path before the vulnerability becomes detectable. This annotation is computed once from the Ansible deploy and inject playbooks, providing an objective ground for the Multi-Hop Reach (MHR) metric."*

---

## 7. Distribution attendue (estimation indicative)

Sur les 87 vulns du benchmark complet :

| Profondeur | Estimation # | Scénarios concernés |
|---|---|---|
| 0 | ~50 (60%) | tous |
| 1 | ~25 (30%) | S2, S3, S5, S6, S7 |
| 2 | ~10 (10%) | S3 (OT), S4 (OT) |
| 3+ | 0 | aucun (pas de profondeur 3 dans le design actuel) |

→ Le papier rapportera principalement MHR_1 et MHR_2. MHR_3 pourra être marqué `N/A` dans le tableau §7.1 si aucune vuln à profondeur ≥ 3.

→ Recommandation : si on veut renforcer la démonstration multi-hop, ajouter 1-2 vulns à profondeur 3 dans S4 ou créer S8 dédié — mais hors scope de cette campagne.
